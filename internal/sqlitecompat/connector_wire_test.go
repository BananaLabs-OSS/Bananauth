package sqlitecompat

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// This ordinary PostgreSQL wire peer requires a parameterized operation to
// include Parse/Bind/Execute before its first Sync. Transaction poolers can
// release a backend at ReadyForQuery between separate protocol exchanges.
func TestPostgresConnectorParameterizedOperationsStayInOneExchange(t *testing.T) {
	for _, kind := range []string{"url", "url-explicit-no", "keyword", "keyword-explicit-no", "explicit-prepare"} {
		t.Run(kind, func(t *testing.T) { ordinaryConnectorExchange(t, kind) })
	}
}
func ordinaryConnectorExchange(t *testing.T, dsnKind string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var clients []net.Conn
	var batches []string
	var bindingChecked bool
	send := func(c net.Conn, kind byte, data []byte) error {
		b := make([]byte, 5+len(data))
		b[0] = kind
		binary.BigEndian.PutUint32(b[1:5], uint32(4+len(data)))
		copy(b[5:], data)
		_, err := c.Write(b)
		return err
	}
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			clients = append(clients, c)
			mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				r := bufio.NewReader(c)
				read := func() ([]byte, error) {
					var b [4]byte
					if _, err := io.ReadFull(r, b[:]); err != nil {
						return nil, err
					}
					n := binary.BigEndian.Uint32(b[:])
					if n < 4 || n > 65536 {
						return nil, fmt.Errorf("ordinary frame size")
					}
					data := make([]byte, n-4)
					_, err := io.ReadFull(r, data)
					return data, err
				}
				startup, err := read()
				if err != nil {
					return
				}
				if len(startup) < 4 {
					return
				}
				startupValues := strings.Split(string(startup[4:]), "\x00")
				app := ""
				for i := 0; i+1 < len(startupValues); i += 2 {
					if startupValues[i] == "application_name" {
						app = startupValues[i+1]
					}
				}
				if app != "ordinary name" {
					t.Error("DSN application_name was not preserved")
					return
				}
				if send(c, 'R', []byte{0, 0, 0, 0}) != nil || send(c, 'Z', []byte{'I'}) != nil {
					return
				}
				for {
					var kinds []byte
					var query string
					var bindData []byte
					for {
						kind, err := r.ReadByte()
						if err != nil {
							return
						}
						data, err := read()
						if err != nil {
							return
						}
						if kind == 'X' {
							return
						}
						kinds = append(kinds, kind)
						if kind == 'B' {
							bindData = append([]byte(nil), data...)
						}
						if kind == 'P' {
							parts := strings.SplitN(string(data), "\x00", 3)
							if len(parts) > 1 {
								query = parts[1]
							}
						}
						if kind == 'S' {
							break
						}
					}
					mu.Lock()
					batches = append(batches, string(kinds))
					mu.Unlock()
					if !strings.ContainsRune(string(kinds), 'B') || !strings.ContainsRune(string(kinds), 'E') {
						_ = send(c, 'E', []byte("SERROR\x00C0A000\x00Mordinary parameterized request needs another backend exchange\x00\x00"))
						_ = send(c, 'Z', []byte{'I'})
						continue
					}
					if strings.HasPrefix(query, "INSERT") {
						params, err := ordinaryBindParams(bindData)
						if err != nil || len(params) != 11 || params[9].format != 1 || string(params[9].value) != "ordinary bytes" || !params[10].null {
							t.Errorf("ordinary byte/NullString binding changed: %v", err)
							return
						}
						mu.Lock()
						bindingChecked = true
						mu.Unlock()
					}
					if send(c, '1', nil) != nil || send(c, '2', nil) != nil {
						return
					}
					if strings.HasPrefix(query, "SELECT") {
						// One integer field using text result format.
						desc := []byte{0, 1, 'v', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4, 255, 255, 255, 255, 0, 0}
						if send(c, 'T', desc) != nil || send(c, 'D', []byte{0, 1, 0, 0, 0, 1, '1'}) != nil || send(c, 'C', []byte("SELECT 1\x00")) != nil {
							return
						}
					} else {
						if send(c, 'n', nil) != nil || send(c, 'C', []byte("INSERT 0 1\x00")) != nil {
							return
						}
					}
					if send(c, 'Z', []byte{'I'}) != nil {
						return
					}
				}
			}(c)
		}
	}()
	dsn := fmt.Sprintf("postgres://fixture@%s/fixture?sslmode=disable&application_name=ordinary+name", listener.Addr())
	if strings.HasPrefix(dsnKind, "keyword") {
		host, port, err := net.SplitHostPort(listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		dsn = "host=" + host + " port=" + port + " user=fixture dbname=fixture sslmode=disable application_name='ordinary name'"
	}
	if strings.HasSuffix(dsnKind, "explicit-no") {
		if strings.HasPrefix(dsnKind, "url") {
			dsn += "&binary_parameters=no"
		} else {
			dsn += " binary_parameters=no"
		}
	}
	connector, err := NewPostgresConnector(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(2)
	defer func() {
		_ = db.Close()
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range clients {
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if dsnKind == "explicit-prepare" {
		// binary_parameters affects one-shot Exec/Query, not persistent server
		// prepared statements. Applications still need transaction/session affinity.
		statement, err := db.PrepareContext(ctx, "SELECT ?")
		if statement != nil {
			_ = statement.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "another backend exchange") {
			t.Fatalf("explicit Prepare unexpectedly treated as one-shot: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(batches) != 1 || batches[0] != "PDS" {
			t.Fatalf("explicit Prepare batch=%v", batches)
		}
		return
	}
	args := []any{1, 2, 3, 4, 5, 6, 7, 8, 9, []byte("ordinary bytes"), sql.NullString{}}
	if _, err := db.ExecContext(ctx, "INSERT INTO ordinary_values VALUES (?,?,?,?,?,?,?,?,?,?,?)", args...); err != nil {
		t.Fatalf("ordinary parameterized Exec: %v", err)
	}
	var value int
	if err := db.QueryRowContext(ctx, "SELECT ?", 1).Scan(&value); err != nil {
		t.Fatalf("ordinary parameterized Query: %v", err)
	}
	if value != 1 {
		t.Fatalf("value=%d", value)
	}
	mu.Lock()
	defer mu.Unlock()
	if !bindingChecked {
		t.Fatal("byte/null bindings not checked")
	}
	if len(batches) != 2 {
		t.Fatalf("batches=%v", batches)
	}
	for _, b := range batches {
		if b != "PBDES" {
			t.Fatalf("parameterized protocol batch=%q", b)
		}
	}
}

type ordinaryBindParam struct {
	format int16
	value  []byte
	null   bool
}

func ordinaryBindParams(data []byte) ([]ordinaryBindParam, error) {
	r := bufio.NewReader(bytes.NewReader(data))
	for i := 0; i < 2; i++ {
		if _, err := r.ReadString(0); err != nil {
			return nil, err
		}
	}
	var count int16
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	if count < 0 || count > 100 {
		return nil, fmt.Errorf("format count")
	}
	formats := make([]int16, int(count))
	for i := range formats {
		if err := binary.Read(r, binary.BigEndian, &formats[i]); err != nil {
			return nil, err
		}
	}
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	if count < 0 || count > 100 {
		return nil, fmt.Errorf("value count")
	}
	params := make([]ordinaryBindParam, int(count))
	for i := range params {
		if len(formats) == 1 {
			params[i].format = formats[0]
		} else if len(formats) == len(params) {
			params[i].format = formats[i]
		} else if len(formats) != 0 {
			return nil, fmt.Errorf("format/value mismatch")
		}
		var size int32
		if err := binary.Read(r, binary.BigEndian, &size); err != nil {
			return nil, err
		}
		if size == -1 {
			params[i].null = true
			continue
		}
		if size < 0 || size > 65536 {
			return nil, fmt.Errorf("value length")
		}
		params[i].value = make([]byte, size)
		if _, err := io.ReadFull(r, params[i].value); err != nil {
			return nil, err
		}
	}
	return params, nil
}
