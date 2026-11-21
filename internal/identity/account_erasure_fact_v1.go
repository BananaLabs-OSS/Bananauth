// Neutral historical erasure evidence. A successful receipt does not assert
// current account absence and never grants a new mutation by itself.
package identity

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/vmihailenco/msgpack/v5"

	"strings"
)

const FnAccountErasureGetV1 = "auth.identity.v1.account-erasure.get"
const accountErasureFactVersionV1 = "auth.identity-erasure-fact.v1"

type ErasureReference struct {
	Operation string `msgpack:"operation" json:"operation"`
	RequestID string `msgpack:"request_id" json:"request_id"`
}
type accountErasureFactV1 struct {
	Version       string `msgpack:"version" json:"version"`
	Operation     string `msgpack:"operation" json:"operation"`
	RequestID     string `msgpack:"request_id" json:"request_id"`
	AccountID     string `msgpack:"account_id" json:"account_id"`
	OwnerRevision int64  `msgpack:"owner_revision" json:"owner_revision"`
}
type ErasureLookup struct {
	Found bool                  `msgpack:"found" json:"found"`
	Fact  *accountErasureFactV1 `msgpack:"fact,omitempty" json:"fact,omitempty"`
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
func validateErasureReference(q ErasureReference) error {
	if (q.Operation != FnAccountErase && q.Operation != FnAccountDelete) || q.RequestID == "" || len(q.RequestID) > 512 || strings.TrimSpace(q.RequestID) != q.RequestID || strings.ContainsAny(q.RequestID, "\r\n\x00") {
		return fmt.Errorf("closed erasure operation and request identity required")
	}
	return nil
}
func (o *Service) AccountErasureGetV1(q ErasureReference) (Result[ErasureLookup], error) {
	if e := validateErasureReference(q); e != nil {
		return Result[ErasureLookup]{}, e
	}
	reader, ok := o.store.(erasureReceiptReaderV1)
	if !ok {
		return failure[ErasureLookup]("unavailable", "indexed erasure receipt reader unavailable"), nil
	}
	r, e := reader.readErasureReceiptV1(context.Background(), q.Operation, q.RequestID)
	if e != nil {
		return failure[ErasureLookup]("unavailable", "erasure receipt unavailable"), nil
	}
	value := ErasureLookup{}
	if r != nil {
		var result Result[AccountProjection]
		if r.Revision <= 0 || r.Operation != q.Operation || r.RequestID != q.RequestID || len(r.Response) == 0 || len(r.Response) > 8192 || msgpack.Unmarshal(r.Response, &result) != nil || result.Version != ContractVersion {
			return failure[ErasureLookup]("unavailable", "stored erasure receipt invalid"), nil
		}
		if result.OK && result.Error == nil {
			id := result.Value.AccountID
			if id == "" || len(id) > 512 || strings.TrimSpace(id) != id || strings.ContainsAny(id, "\r\n\x00") {
				return failure[ErasureLookup]("unavailable", "stored erasure identity invalid"), nil
			}
			value = ErasureLookup{Found: true, Fact: &accountErasureFactV1{accountErasureFactVersionV1, q.Operation, q.RequestID, id, r.Revision}}
		}
	}
	// Preserve an explicit found=false value rather than omitting a zero result.
	return success(value), nil
}
