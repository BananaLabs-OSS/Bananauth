package sqlitecompat

import (
	"context"
	"database/sql/driver"
	"fmt"
	"strconv"

	"github.com/lib/pq"
)

// NewSQLiteCompatiblePostgresConnector returns a native database/sql connector
// which applies the same bounded SQLite ABI translation as the Pulp host. It
// exists for native integration and migration tooling; production cells still
// receive database authority only through the scoped Pulp host capability.
func NewPostgresConnector(dsn string) (driver.Connector, error) {
	dsn, err := nativeConnectorDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("storage.postgres: parse DSN: %w", err)
	}
	base, err := pq.NewConnector(dsn)
	if err != nil {
		return nil, fmt.Errorf("storage.postgres: parse DSN: %w", err)
	}
	return sqliteCompatConnector{base: base}, nil
}

type sqliteCompatConnector struct{ base driver.Connector }

func (c sqliteCompatConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &sqliteCompatConn{Conn: conn}, nil
}

func (c sqliteCompatConnector) Driver() driver.Driver { return c.base.Driver() }

type sqliteCompatConn struct{ driver.Conn }

// Preparing has no argument values yet. Count only lexer-recognized parameters
// so quoted strings, identifiers and comments retain Rewrite's exact semantics.
func rewritePrepared(query string) (string, error) {
	pieces, err := lexSQL(query)
	if err != nil {
		return "", fmt.Errorf("storage.postgres: invalid SQL: %w", err)
	}
	questions, native := 0, 0
	for _, piece := range pieces {
		switch piece.kind {
		case sqlQuestion:
			questions++
		case sqlNativeParam:
			n, err := strconv.Atoi(piece.text[1:])
			if err != nil {
				return "", fmt.Errorf("storage.postgres: invalid parameter index: %w", err)
			}
			if n > native {
				native = n
			}
		}
	}
	count := questions
	if native > count {
		count = native
	}
	return Rewrite(query, count)
}

func (c *sqliteCompatConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

func (c *sqliteCompatConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rewritten, err := rewritePrepared(query)
	if err != nil {
		return nil, err
	}
	var stmt driver.Stmt
	if preparer, ok := c.Conn.(driver.ConnPrepareContext); ok {
		stmt, err = preparer.PrepareContext(ctx, rewritten)
	} else {
		stmt, err = c.Conn.Prepare(rewritten)
		// Legacy Prepare cannot observe cancellation while it is running. Close the
		// just-created statement, as database/sql's context fallback does.
		if err == nil && ctx.Err() != nil {
			_ = stmt.Close()
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return &sqliteCompatStmt{Stmt: stmt}, nil
}

// Embedding preserves the driver's Close and NumInput contracts. Every execution
// path normalizes SQLite booleans, including database/sql's tx.Prepare fallback.
type sqliteCompatStmt struct{ driver.Stmt }

func (s *sqliteCompatStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.Stmt.Exec(normalizedValues(args))
}
func (s *sqliteCompatStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.Stmt.Query(normalizedValues(args))
}
func (s *sqliteCompatStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if exec, ok := s.Stmt.(driver.StmtExecContext); ok {
		copied := append([]driver.NamedValue(nil), args...)
		normalizeNamedValues(copied)
		return exec.ExecContext(ctx, copied)
	}
	values, err := legacyStatementValues(args)
	if err != nil {
		return nil, err
	}
	return s.Stmt.Exec(values)
}
func (s *sqliteCompatStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if queryer, ok := s.Stmt.(driver.StmtQueryContext); ok {
		copied := append([]driver.NamedValue(nil), args...)
		normalizeNamedValues(copied)
		return queryer.QueryContext(ctx, copied)
	}
	values, err := legacyStatementValues(args)
	if err != nil {
		return nil, err
	}
	return s.Stmt.Query(values)
}
func normalizedValues(args []driver.Value) []driver.Value {
	copied := make([]driver.Value, len(args))
	for i, value := range args {
		copied[i] = NormalizeValue(value)
	}
	return copied
}
func legacyStatementValues(args []driver.NamedValue) ([]driver.Value, error) {
	values := make([]driver.Value, len(args))
	for i, arg := range args {
		if arg.Name != "" {
			return nil, fmt.Errorf("storage.postgres: legacy prepared statement does not support named parameters")
		}
		values[i] = NormalizeValue(arg.Value)
	}
	return values, nil
}

func (c *sqliteCompatConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	exec, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	rewritten, err := Rewrite(query, len(args))
	if err != nil {
		return nil, err
	}
	normalizeNamedValues(args)
	return exec.ExecContext(ctx, rewritten, args)
}

func (c *sqliteCompatConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	rewritten, err := Rewrite(query, len(args))
	if err != nil {
		return nil, err
	}
	normalizeNamedValues(args)
	return queryer.QueryContext(ctx, rewritten, args)
}

func normalizeNamedValues(args []driver.NamedValue) {
	for i := range args {
		args[i].Value = NormalizeValue(args[i].Value)
	}
}

// NormalizeValue preserves SQLite's integer representation of booleans when
// calls cross the PostgreSQL wire protocol.
func NormalizeValue(value any) any {
	if boolean, ok := value.(bool); ok {
		if boolean {
			return int64(1)
		}
		return int64(0)
	}
	return value
}

func (c *sqliteCompatConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	beginner, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, driver.ErrSkip
	}
	return beginner.BeginTx(ctx, opts)
}

func (c *sqliteCompatConn) Ping(ctx context.Context) error {
	pinger, ok := c.Conn.(driver.Pinger)
	if !ok {
		return nil
	}
	return pinger.Ping(ctx)
}

func (c *sqliteCompatConn) ResetSession(ctx context.Context) error {
	resetter, ok := c.Conn.(driver.SessionResetter)
	if !ok {
		return nil
	}
	return resetter.ResetSession(ctx)
}

func (c *sqliteCompatConn) IsValid() bool {
	validator, ok := c.Conn.(driver.Validator)
	return !ok || validator.IsValid()
}
