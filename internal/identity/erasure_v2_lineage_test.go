package identity

import (
	"path/filepath"
	"testing"
)

func TestAcceptedV2IssuanceFactRemovedByReceiptBackedErase(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var store eventStore = &memoryEventStore{}
			if kind == "sqlite" {
				s, e := openSQLite(filepath.Join(t.TempDir(), "identity.db"))
				if e != nil {
					t.Fatal(e)
				}
				defer s.db.Close()
				store = s
			}
			o := newTestOwner(t, store)
			r := callResult[AccountProjection](t, o.nativeRegister, NativeRegisterRequest{RequestID: "lineage-register", AccountID: "lineage-member", CredentialID: "lineage-credential", Email: "member@example.test", Username: "Member", Password: "synthetic-password-123", Now: 1000})
			if !r.OK {
				t.Fatal("register failed")
			}
			if r := issueV2(t, o, "login", "lineage-login", "member@example.test", 1001); !r.OK || !r.Value.EffectQueued {
				t.Fatal("accepted V2 login issue lost")
			}
			before := callResult[EmailVerificationFactV2](t, o.emailVerificationFactGetV2, EmailVerificationFactRequestV2{EffectID: "lineage-login-effect", Email: "member@example.test", Now: 1002})
			if !before.OK || !before.Value.Active || before.Value.AccountID != "lineage-member" {
				t.Fatal("original V2 issuance fact missing")
			}
			removed := callResult[AccountProjection](t, o.accountErase, AccountEraseRequest{RequestID: "lineage-erase", AccountID: "lineage-member", ReasonID: "lineage-retention-eligible", Now: 1003})
			if !removed.OK {
				t.Fatal("actual owner erase failed")
			}
			again := newTestOwner(t, store)
			after := callResult[EmailVerificationFactV2](t, again.emailVerificationFactGetV2, EmailVerificationFactRequestV2{EffectID: "lineage-login-effect", Email: "member@example.test", Now: 1004})
			if after.OK {
				t.Fatal("erased account retained V2 issuance authority")
			}
			point := erasureFactCallV1(t, again, accountErasureReferenceV1{FnAccountErase, "lineage-erase"})
			if !point.OK || !point.Value.Found || point.Value.Fact == nil || point.Value.Fact.AccountID != "lineage-member" || point.Value.Fact.OwnerRevision <= 0 {
				t.Fatal("historical erasure receipt authority lost")
			}
		})
	}
}
