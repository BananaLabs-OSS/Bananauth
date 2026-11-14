package identity

import "testing"

func TestAccountLookupNormalizesEmailAndRejectsAmbiguity(t *testing.T) {
	cell := newTestOwner(t, &memoryEventStore{})
	for index, id := range []string{"account-one", "account-two"} {
		imported := callResult[LegacyImportResult](t, cell.legacyImport, LegacyImportRequest{
			RequestID: "lookup-seed-" + id, Accounts: []AccountProjection{{AccountID: id, Email: "Member@example.test", CreatedAt: 1}},
		})
		if !imported.OK {
			t.Fatal(imported.Error)
		}
		found := callResult[AccountProjection](t, cell.accountGet, AccountGetRequest{Email: " MEMBER@example.test "})
		if index == 0 && (!found.OK || found.Value.AccountID != id) {
			t.Fatalf("lookup %#v", found)
		}
		if index == 1 && (found.OK || found.Error.Code != "conflict") {
			t.Fatalf("ambiguous lookup %#v", found)
		}
	}
	missing := callResult[AccountProjection](t, cell.accountGet, AccountGetRequest{Email: "unknown@example.test"})
	if missing.OK || missing.Error.Code != "not_found" {
		t.Fatalf("missing %#v", missing)
	}
	direct := callResult[AccountProjection](t, cell.accountGet, AccountGetRequest{AccountID: "account-one"})
	if !direct.OK || direct.Value.AccountID != "account-one" {
		t.Fatalf("ID lookup %#v", direct)
	}
}
