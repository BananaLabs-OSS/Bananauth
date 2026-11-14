// Neutral historical erasure evidence. A successful receipt does not assert
// current account absence and never grants a new mutation by itself.
package identity

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"github.com/vmihailenco/msgpack/v5"
	"io"
	"strings"
)

const FnAccountErasureGetV1 = "auth.identity.v1.account-erasure.get"
const accountErasureFactVersionV1 = "auth.identity-erasure-fact.v1"

type accountErasureReferenceV1 struct {
	Operation string `msgpack:"operation"`
	RequestID string `msgpack:"request_id"`
}
type accountErasureFactV1 struct {
	Version       string `msgpack:"version"`
	Operation     string `msgpack:"operation"`
	RequestID     string `msgpack:"request_id"`
	AccountID     string `msgpack:"account_id"`
	OwnerRevision int64  `msgpack:"owner_revision"`
}
type accountErasureLookupV1 struct {
	Found bool                  `msgpack:"found"`
	Fact  *accountErasureFactV1 `msgpack:"fact,omitempty"`
}
type erasureReceiptV1 struct {
	Operation, RequestID string
	Revision             int64
	Response             []byte
}
type erasureReceiptKeyV1 struct{ Operation, RequestID string }
type erasureReceiptReaderV1 interface {
	readErasureReceiptV1(context.Context, string, string) (*erasureReceiptV1, error)
}

func (s *sqliteEventStore) readErasureReceiptV1(ctx context.Context, operation, requestID string) (*erasureReceiptV1, error) {
	var r erasureReceiptV1
	e := s.db.QueryRowContext(ctx, `SELECT revision,operation,request_id,response FROM auth_identity_commands WHERE operation=? AND request_id=?`, operation, requestID).Scan(&r.Revision, &r.Operation, &r.RequestID, &r.Response)
	if e == sql.ErrNoRows {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	return &r, nil
}
func (s *memoryEventStore) readErasureReceiptV1(_ context.Context, operation, requestID string) (*erasureReceiptV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, ok := s.erasureReceiptIndex[erasureReceiptKeyV1{operation, requestID}]
	if !ok {
		return nil, nil
	}
	if index < 0 || index >= len(s.records) {
		return nil, fmt.Errorf("invalid receipt index")
	}
	r := s.records[index].Receipt
	return &erasureReceiptV1{Operation: r.Operation, RequestID: r.RequestID, Revision: int64(index + 1), Response: append([]byte(nil), r.Response...)}, nil
}
func decodeErasureReferenceV1(raw []byte) (accountErasureReferenceV1, error) {
	var q accountErasureReferenceV1
	if len(raw) == 0 || len(raw) > 2048 {
		return q, fmt.Errorf("bounded erasure reference required")
	}
	d := msgpack.NewDecoder(bytes.NewReader(raw))
	n, e := d.DecodeMapLen()
	if e != nil || n != 2 {
		return q, fmt.Errorf("exact erasure reference required")
	}
	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		k, e := d.DecodeString()
		if e != nil || seen[k] || (k != "operation" && k != "request_id") {
			return q, fmt.Errorf("closed erasure reference required")
		}
		seen[k] = true
		v, e := d.DecodeString()
		if e != nil {
			return q, fmt.Errorf("opaque reference strings required")
		}
		if k == "operation" {
			q.Operation = v
		} else {
			q.RequestID = v
		}
	}
	if _, e := d.PeekCode(); e != io.EOF {
		return q, fmt.Errorf("trailing erasure reference data")
	}
	if (q.Operation != FnAccountErase && q.Operation != FnAccountDelete) || q.RequestID == "" || len(q.RequestID) > 512 || strings.TrimSpace(q.RequestID) != q.RequestID || strings.ContainsAny(q.RequestID, "\r\n\x00") {
		return q, fmt.Errorf("closed erasure operation and request identity required")
	}
	return q, nil
}
func (o *owner) accountErasureGetV1(raw []byte) ([]byte, error) {
	q, e := decodeErasureReferenceV1(raw)
	if e != nil {
		return nil, e
	}
	reader, ok := o.store.(erasureReceiptReaderV1)
	if !ok {
		return encode(failure[accountErasureLookupV1]("unavailable", "indexed erasure receipt reader unavailable"))
	}
	r, e := reader.readErasureReceiptV1(context.Background(), q.Operation, q.RequestID)
	if e != nil {
		return encode(failure[accountErasureLookupV1]("unavailable", "erasure receipt unavailable"))
	}
	value := accountErasureLookupV1{}
	if r != nil {
		var result Result[AccountProjection]
		if r.Revision <= 0 || r.Operation != q.Operation || r.RequestID != q.RequestID || len(r.Response) == 0 || len(r.Response) > 8192 || msgpack.Unmarshal(r.Response, &result) != nil || result.Version != ContractVersion {
			return encode(failure[accountErasureLookupV1]("unavailable", "stored erasure receipt invalid"))
		}
		if result.OK && result.Error == nil {
			id := result.Value.AccountID
			if id == "" || len(id) > 512 || strings.TrimSpace(id) != id || strings.ContainsAny(id, "\r\n\x00") {
				return encode(failure[accountErasureLookupV1]("unavailable", "stored erasure identity invalid"))
			}
			value = accountErasureLookupV1{Found: true, Fact: &accountErasureFactV1{accountErasureFactVersionV1, q.Operation, q.RequestID, id, r.Revision}}
		}
	}
	// Preserve an explicit found=false value rather than omitting a zero result.
	return encode(struct {
		Version string                 `msgpack:"version"`
		OK      bool                   `msgpack:"ok"`
		Value   accountErasureLookupV1 `msgpack:"value"`
	}{ContractVersion, true, value})
}
