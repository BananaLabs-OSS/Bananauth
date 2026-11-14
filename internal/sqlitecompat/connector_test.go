package sqlitecompat

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

type preparedLog struct {
	queries                           []string
	values                            []driver.Value
	named                             []driver.NamedValue
	prepareCtx, execCtx, queryCtx     context.Context
	prepareErr, execErr, queryErr     error
	closeCount, execCount, queryCount int
	numInput                          int
	afterPrepare                      func()
}
type preparedConnector struct{ conn driver.Conn }

func (c preparedConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (c preparedConnector) Driver() driver.Driver                        { return preparedDriver{} }

type preparedDriver struct{}

func (preparedDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("fake connector only")
}

type preparedTx struct{}

func (preparedTx) Commit() error   { return nil }
func (preparedTx) Rollback() error { return nil }

type preparedLegacyConn struct{ log *preparedLog }

func (c *preparedLegacyConn) Prepare(q string) (driver.Stmt, error) {
	c.log.queries = append(c.log.queries, q)
	if c.log.prepareErr != nil {
		return nil, c.log.prepareErr
	}
	if c.log.afterPrepare != nil {
		c.log.afterPrepare()
	}
	return &preparedLegacyStmt{c.log}, nil
}
func (c *preparedLegacyConn) Close() error              { return nil }
func (c *preparedLegacyConn) Begin() (driver.Tx, error) { return preparedTx{}, nil }
func (c *preparedLegacyConn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.Begin()
}

type preparedContextConn struct{ *preparedLegacyConn }

func (c *preparedContextConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	c.log.prepareCtx = ctx
	c.log.queries = append(c.log.queries, q)
	if c.log.prepareErr != nil {
		return nil, c.log.prepareErr
	}
	return &preparedContextStmt{&preparedLegacyStmt{c.log}}, nil
}

type preparedLegacyStmt struct{ log *preparedLog }

func (s *preparedLegacyStmt) Close() error  { s.log.closeCount++; return nil }
func (s *preparedLegacyStmt) NumInput() int { return s.log.numInput }
func (s *preparedLegacyStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.log.execCount++
	s.log.values = append([]driver.Value(nil), args...)
	return driver.RowsAffected(1), s.log.execErr
}
func (s *preparedLegacyStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.log.queryCount++
	s.log.values = append([]driver.Value(nil), args...)
	if s.log.queryErr != nil {
		return nil, s.log.queryErr
	}
	return &preparedRows{}, nil
}

type preparedContextStmt struct{ *preparedLegacyStmt }

func (s *preparedContextStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	s.log.execCtx = ctx
	s.log.execCount++
	s.log.named = append([]driver.NamedValue(nil), args...)
	return driver.RowsAffected(1), s.log.execErr
}
func (s *preparedContextStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	s.log.queryCtx = ctx
	s.log.queryCount++
	s.log.named = append([]driver.NamedValue(nil), args...)
	if s.log.queryErr != nil {
		return nil, s.log.queryErr
	}
	return &preparedRows{}, nil
}

type preparedRows struct{ sent bool }

func (r *preparedRows) Columns() []string { return []string{"value"} }
func (r *preparedRows) Close() error      { return nil }
func (r *preparedRows) Next(dst []driver.Value) error {
	if r.sent {
		return io.EOF
	}
	r.sent = true
	dst[0] = int64(1)
	return nil
}

func TestPreparedStatementDatabaseSQLAndTransaction(t *testing.T) {
	for _, modern := range []bool{false, true} {
		name := "legacy"
		if modern {
			name = "context"
		}
		t.Run(name, func(t *testing.T) {
			log := &preparedLog{numInput: 2}
			base := &preparedLegacyConn{log}
			var conn driver.Conn = base
			if modern {
				conn = &preparedContextConn{base}
			}
			db := sql.OpenDB(sqliteCompatConnector{base: preparedConnector{conn}})
			defer db.Close()
			db.SetMaxOpenConns(1)
			stmt, err := db.Prepare(`INSERT INTO flags(id,enabled) VALUES (?,?)`)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = stmt.Exec(int64(9), true); err != nil {
				t.Fatal(err)
			}
			if err = stmt.Close(); err != nil {
				t.Fatal(err)
			}
			if got := log.queries[0]; got != `INSERT INTO flags(id,enabled) VALUES ($1,$2)` {
				t.Fatal(got)
			}
			checkPreparedArgs(t, log, modern, []driver.Value{int64(9), int64(1)})
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			txStmt, err := tx.Prepare(`SELECT '?' AS literal FROM flags WHERE id=? AND enabled=? -- ?`)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := txStmt.Query(int64(9), false)
			if err != nil {
				t.Fatal(err)
			}
			rows.Close()
			txStmt.Close()
			checkPreparedArgs(t, log, modern, []driver.Value{int64(9), int64(0)})
			if got := log.queries[1]; got != `SELECT '?' AS literal FROM flags WHERE id=$1 AND enabled=$2 -- ?` {
				t.Fatal(got)
			}
			if _, err = tx.Prepare(`INSERT OR REPLACE INTO flags VALUES (?,?)`); err == nil {
				t.Fatal("unsupported SQLite SQL reached prepared driver")
			}
			if len(log.queries) != 2 {
				t.Fatal("rejected SQL reached driver", log.queries)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func checkPreparedArgs(t *testing.T, log *preparedLog, modern bool, want []driver.Value) {
	t.Helper()
	got := log.values
	if modern {
		got = make([]driver.Value, len(log.named))
		for i, arg := range log.named {
			got[i] = arg.Value
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%#v want=%#v", got, want)
	}
}

func TestPrepareRewriteUsesExistingLexer(t *testing.T) {
	tests := []struct {
		query, want string
		reject      bool
	}{
		{`SELECT ?, '?' AS x, "?", $tag$?$tag$ /* ? /* ? */ ? */ -- ?`, `SELECT $1, '?' AS x, "?", $tag$?$tag$ /* ? /* ? */ ? */ -- ?`, false},
		{`SELECT $2,$1,$2`, `SELECT $2,$1,$2`, false},
		{`PRAGMA busy_timeout=5000`, `SELECT 1 WHERE FALSE`, false},
		{`CREATE TABLE flags(enabled BOOLEAN DEFAULT FALSE,payload BLOB)`, `CREATE TABLE flags(enabled BIGINT DEFAULT 0,payload BYTEA)`, false},
		{`SELECT ?, $1`, "", true}, {`SELECT ?123`, "", true}, {`SELECT $0`, "", true}, {`SELECT $99999999999999999999999999`, "", true},
		{`SELECT 'unterminated`, "", true}, {`PRAGMA journal_mode=WAL`, "", true}, {"SELECT `unsupported`", "", true},
	}
	for _, test := range tests {
		t.Run(test.query, func(t *testing.T) {
			log := &preparedLog{numInput: -1}
			conn := &sqliteCompatConn{Conn: &preparedLegacyConn{log}}
			stmt, err := conn.Prepare(test.query)
			if test.reject {
				if err == nil {
					t.Fatal("expected rejection")
				}
				if len(log.queries) != 0 {
					t.Fatal("rejected SQL reached driver")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer stmt.Close()
			if log.queries[0] != test.want {
				t.Fatalf("got %q want %q", log.queries[0], test.want)
			}
			if stmt.NumInput() != -1 {
				t.Fatal("driver NumInput changed")
			}
		})
	}
}
func TestPreparedStatementLegacyMethodsNormalizeWithoutMutating(t *testing.T) {
	log := &preparedLog{numInput: 2}
	conn := &sqliteCompatConn{Conn: &preparedLegacyConn{log}}
	stmt, err := conn.Prepare("SELECT ?,?")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	values := []driver.Value{true, false}
	if _, err = stmt.Exec(values); err != nil {
		t.Fatal(err)
	}
	checkPreparedArgs(t, log, false, []driver.Value{int64(1), int64(0)})
	rows, err := stmt.Query(values)
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
	checkPreparedArgs(t, log, false, []driver.Value{int64(1), int64(0)})
	if !reflect.DeepEqual(values, []driver.Value{true, false}) {
		t.Fatal("caller values mutated")
	}
}
func TestPreparedStatementContextsErrorsAndFallback(t *testing.T) {
	type contextKey struct{}
	for _, modern := range []bool{false, true} {
		name := "legacy"
		if modern {
			name = "context"
		}
		t.Run(name, func(t *testing.T) {
			log := &preparedLog{numInput: 1}
			base := &preparedLegacyConn{log}
			var raw driver.Conn = base
			if modern {
				raw = &preparedContextConn{base}
			}
			conn := &sqliteCompatConn{Conn: raw}
			ctx := context.WithValue(context.Background(), contextKey{}, "marker")
			stmt, err := conn.PrepareContext(ctx, "SELECT ?")
			if err != nil {
				t.Fatal(err)
			}
			defer stmt.Close()
			if modern && log.prepareCtx != ctx {
				t.Fatal("prepare context lost")
			}
			exec := stmt.(driver.StmtExecContext)
			query := stmt.(driver.StmtQueryContext)
			args := []driver.NamedValue{{Ordinal: 1, Value: true}}
			if _, err = exec.ExecContext(ctx, args); err != nil {
				t.Fatal(err)
			}
			checkPreparedArgs(t, log, modern, []driver.Value{int64(1)})
			rows, err := query.QueryContext(ctx, args)
			if err != nil {
				t.Fatal(err)
			}
			rows.Close()
			checkPreparedArgs(t, log, modern, []driver.Value{int64(1)})
			if modern && (log.execCtx != ctx || log.queryCtx != ctx) {
				t.Fatal("execution context lost")
			}
			if args[0].Value != true {
				t.Fatal("caller named args mutated")
			}
			sentinel := errors.New("underlying sentinel")
			log.execErr = sentinel
			log.queryErr = sentinel
			if _, err = exec.ExecContext(ctx, args); !errors.Is(err, sentinel) {
				t.Fatal("exec error lost", err)
			}
			if _, err = query.QueryContext(ctx, args); !errors.Is(err, sentinel) {
				t.Fatal("query error lost", err)
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			before := len(log.queries)
			if _, err = conn.PrepareContext(canceled, "SELECT ?"); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if len(log.queries) != before {
				t.Fatal("canceled prepare reached driver")
			}
			execBefore, queryBefore := log.execCount, log.queryCount
			if _, err = exec.ExecContext(canceled, args); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if _, err = query.QueryContext(canceled, args); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if log.execCount != execBefore || log.queryCount != queryBefore {
				t.Fatal("canceled statement reached driver")
			}
			if !modern {
				named := []driver.NamedValue{{Name: "enabled", Ordinal: 1, Value: true}}
				if _, err = exec.ExecContext(ctx, named); err == nil || !strings.Contains(err.Error(), "named") {
					t.Fatal("named fallback silently discarded name", err)
				}
				if _, err = query.QueryContext(ctx, named); err == nil {
					t.Fatal("query named fallback accepted")
				}
			}
			log.prepareErr = sentinel
			if _, err = conn.PrepareContext(ctx, "SELECT ?"); !errors.Is(err, sentinel) {
				t.Fatal("prepare error lost", err)
			}
		})
	}
}
func TestLegacyPrepareCancellationClosesNewStatement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	log := &preparedLog{afterPrepare: cancel, numInput: 0}
	conn := &sqliteCompatConn{Conn: &preparedLegacyConn{log}}
	if _, err := conn.PrepareContext(ctx, "SELECT 1"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if log.closeCount != 1 {
		t.Fatal("canceled legacy prepare leaked statement")
	}
}
func TestPreparedNumInputRemainsDriverContract(t *testing.T) {
	log := &preparedLog{numInput: 2}
	db := sql.OpenDB(sqliteCompatConnector{base: preparedConnector{&preparedLegacyConn{log}}})
	defer db.Close()
	stmt, err := db.Prepare("SELECT ?,?")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	if _, err = stmt.Exec(true); err == nil {
		t.Fatal("database/sql lost driver argument count")
	}
	if log.execCount != 0 {
		t.Fatal("wrong argument count reached driver")
	}
}
