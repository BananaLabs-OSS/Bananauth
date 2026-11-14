package identity

import (
	"context"
	"github.com/vmihailenco/msgpack/v5"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func erasureReferenceWireV1(t *testing.T, q accountErasureReferenceV1) []byte {
	t.Helper()
	b, e := msgpack.Marshal(q)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func erasureFactCallV1(t *testing.T, o *owner, q accountErasureReferenceV1) Result[accountErasureLookupV1] {
	t.Helper()
	raw, e := o.accountErasureGetV1(erasureReferenceWireV1(t, q))
	if e != nil {
		t.Fatal(e)
	}
	var out Result[accountErasureLookupV1]
	if msgpack.Unmarshal(raw, &out) != nil {
		t.Fatal("invalid lookup wire")
	}
	return out
}
func erasureOAuthV1(t *testing.T, o *owner, key, email string, now int64) {
	t.Helper()
	r := callResult[OAuthUpsertResult](t, o.oauthUpsert, OAuthUpsertRequest{RequestID: "oauth:" + key, AccountID: "stable-account", LinkID: "link:" + key, Provider: "fixture", ProviderID: key, ProviderEmail: email, Now: now})
	if !r.OK {
		t.Fatal("actual owner account operation failed")
	}
}
func TestAccountErasureReceiptPointOriginalUUIDAndHistoricalReopenV1(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, operation := range []string{FnAccountErase, FnAccountDelete} {
			t.Run(backend+"/"+operation, func(t *testing.T) {
				var store eventStore = &memoryEventStore{}
				var sqlStore *sqliteEventStore
				if backend == "sqlite" {
					var e error
					sqlStore, e = openSQLite(filepath.Join(t.TempDir(), "identity.db"))
					if e != nil {
						t.Fatal(e)
					}
					defer sqlStore.db.Close()
					store = sqlStore
				}
				o := newTestOwner(t, store)
				erasureOAuthV1(t, o, "first", "old@example.test", 100)
				erasureOAuthV1(t, o, "changed", "new@example.test", 200)
				q := accountErasureReferenceV1{operation, "erase-original"}
				if r := erasureFactCallV1(t, o, q); !r.OK || r.Value.Found || r.Value.Fact != nil {
					t.Fatal("pending/no receipt fabricated erasure")
				}
				var erased Result[AccountProjection]
				if operation == FnAccountErase {
					erased = callResult[AccountProjection](t, o.accountErase, AccountEraseRequest{RequestID: q.RequestID, AccountID: "stable-account", ReasonID: "fixture-erasure", Now: 300})
				} else {
					erased = callResult[AccountProjection](t, o.accountDelete, AccountDeleteRequest{RequestID: q.RequestID, AccountID: "stable-account", Email: "new@example.test", Now: 300})
				}
				if !erased.OK {
					t.Fatal("actual owner erase failed")
				}
				first := erasureFactCallV1(t, o, q)
				if !first.OK || !first.Value.Found || first.Value.Fact == nil {
					t.Fatal("actual successful receipt missing")
				}
				f := first.Value.Fact
				if f.AccountID != "stable-account" || f.Operation != operation || f.RequestID != q.RequestID || f.Version != accountErasureFactVersionV1 || f.OwnerRevision <= 0 {
					t.Fatal("authoritative receipt coordinates missing")
				}
				raw, _ := msgpack.Marshal(first)
				var outer map[string]any
				msgpack.Unmarshal(raw, &outer)
				b, _ := msgpack.Marshal(f)
				for _, forbidden := range []string{"old@example.test", "new@example.test", "password", "credential", "username"} {
					if strings.Contains(string(b), forbidden) {
						t.Fatal("point exported account body or credential")
					}
				}
				erasureOAuthV1(t, o, "recreated", "fresh@example.test", 900)
				again := erasureFactCallV1(t, o, q)
				if !reflect.DeepEqual(first, again) {
					t.Fatal("historical receipt changed after UUID recreation")
				}
				live := callResult[AccountProjection](t, o.accountGet, AccountGetRequest{AccountID: "stable-account"})
				if !live.OK {
					t.Fatal("historical fact must not be mistaken for current absence")
				}
				if backend == "sqlite" {
					reopened := newTestOwner(t, store)
					retained := erasureFactCallV1(t, reopened, q)
					if !reflect.DeepEqual(first, retained) {
						t.Fatal("SQL reopen changed original receipt")
					}
					// Corruption sentinel AFTER construction: querying receipt may not load the
					// latest owner snapshot or decode unrelated history.
					if _, e := sqlStore.db.Exec(`INSERT INTO auth_identity_commands(revision,operation,request_id,request_digest,response,snapshot) SELECT MAX(revision)+1,?,?,?,?,? FROM auth_identity_commands`, "unrelated", "poison", "synthetic", []byte{0xc1}, []byte{0xc1}); e != nil {
						t.Fatal(e)
					}
					r := erasureFactCallV1(t, reopened, q)
					if !reflect.DeepEqual(first, r) {
						t.Fatal("point consulted unrelated snapshot/history")
					}
				}
			})
		}
	}
}
func TestAccountErasureReceiptPointDeniesAbsentFailedForeignAndStrictWireV1(t *testing.T) {
	o := newTestOwner(t, &memoryEventStore{})
	erasureOAuthV1(t, o, "first", "member@example.test", 100)
	failed := callResult[AccountProjection](t, o.accountDelete, AccountDeleteRequest{RequestID: "denied", AccountID: "stable-account", Email: "foreign@example.test", Now: 200})
	if failed.OK {
		t.Fatal("failure fixture unexpectedly erased")
	}
	for _, q := range []accountErasureReferenceV1{{FnAccountDelete, "denied"}, {FnAccountErase, "denied"}, {FnAccountErase, "unknown"}} {
		r := erasureFactCallV1(t, o, q)
		if !r.OK || r.Value.Found {
			t.Fatal("missing/failed/foreign reference became erasure")
		}
	}
	good := erasureReferenceWireV1(t, accountErasureReferenceV1{FnAccountErase, "unknown"})
	extra, _ := msgpack.Marshal(map[string]string{"operation": FnAccountErase, "request_id": "unknown", "account_id": "victim"})
	duplicate, _ := msgpack.Marshal(map[string]string{"operation": FnAccountErase, "request_id": "unknown"})
	_ = duplicate
	dup := []byte{0x82, 0xa9, 'o', 'p', 'e', 'r', 'a', 't', 'i', 'o', 'n', 0xa1, 'x', 0xa9, 'o', 'p', 'e', 'r', 'a', 't', 'i', 'o', 'n', 0xa1, 'y'}
	foreign := erasureReferenceWireV1(t, accountErasureReferenceV1{FnAccountGet, "unknown"})
	for _, bad := range [][]byte{nil, {0xc1}, extra, dup, foreign, append(append([]byte{}, good...), 0x80), erasureReferenceWireV1(t, accountErasureReferenceV1{FnAccountErase, " x"})} {
		if _, e := o.accountErasureGetV1(bad); e == nil {
			t.Fatal("expanded/malformed reference accepted")
		}
	}
	raw, e := o.accountErasureGetV1(good)
	if e != nil {
		t.Fatal(e)
	}
	var value map[string]msgpack.RawMessage
	msgpack.Unmarshal(raw, &value)
	if len(value["value"]) == 0 {
		t.Fatal("empty result omitted explicit found=false")
	}
}

type erasureBadReaderV1 struct {
	eventStore
	r *erasureReceiptV1
}

func (s erasureBadReaderV1) readErasureReceiptV1(context.Context, string, string) (*erasureReceiptV1, error) {
	return s.r, nil
}
func TestAccountErasureReceiptPointCorruptIndexedRowFailsClosedV1(t *testing.T) {
	base := &memoryEventStore{}
	o := newTestOwner(t, base)
	q := accountErasureReferenceV1{FnAccountErase, "ref"}
	valid, _ := encode(success(AccountProjection{AccountID: "stable-account", Email: "private@example.test"}))
	for _, mode := range []string{"foreign-operation", "foreign-request", "corrupt-response", "wrong-version", "blank-account", "zero-revision"} {
		t.Run(mode, func(t *testing.T) {
			r := &erasureReceiptV1{Operation: q.Operation, RequestID: q.RequestID, Revision: 1, Response: valid}
			switch mode {
			case "foreign-operation":
				r.Operation = FnAccountDelete
			case "foreign-request":
				r.RequestID = "foreign"
			case "corrupt-response":
				r.Response = []byte{0xc1}
			case "wrong-version":
				r.Response, _ = msgpack.Marshal(map[string]any{"version": "wrong", "ok": true, "value": map[string]string{"account_id": "stable-account"}})
			case "blank-account":
				r.Response, _ = encode(success(AccountProjection{}))
			case "zero-revision":
				r.Revision = 0
			}
			o.store = erasureBadReaderV1{base, r}
			got := erasureFactCallV1(t, o, q)
			if got.OK || got.Value.Found || got.Value.Fact != nil {
				t.Fatal("corrupt row became authority")
			}
		})
	}
}
