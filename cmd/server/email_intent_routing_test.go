package main

import (
	"context"
	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/notification"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmailIntentHTTPUsesStrictTypedServices(t *testing.T) {
	for _, intent := range []string{"", "login", "signup", "broadcast", "email_change", "Signup"} {
		t.Run("intent="+intent, func(t *testing.T) {
			keys, _ := otpsecure.Parse(strings.Repeat("k", 32), "")
			service, closer, err := identity.Open(context.Background(), filepath.Join(t.TempDir(), "identity.db"), keys)
			if err != nil {
				t.Fatal(err)
			}
			defer closer.Close()
			valid := intent == "" || intent == "login" || intent == "signup"
			if intent != "signup" && valid {
				result, err := service.NativeRegister(identity.NativeRegisterRequest{RequestID: "register", AccountID: "account", CredentialID: "credential", Email: "member@example.test", Username: "member", Password: "fixture-password", Now: 100})
				if err != nil || !result.OK {
					t.Fatal(result, err)
				}
			}
			handler := AuthHandler{identity: service}
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/auth/email-verification", strings.NewReader(`{"email":"member@example.test","intent":"`+intent+`"}`))
			handler.IssueEmailVerificationV2(w, r)
			want := 400
			if valid {
				want = 202
			}
			if w.Code != want {
				t.Fatalf("status %d want %d: %s", w.Code, want, w.Body)
			}
			claim, err := service.EffectsClaim(notification.ClaimRequest{ConsumerID: "fixture-worker", Limit: 2, LeaseDurationMillis: 1000})
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			if valid {
				count = 1
			}
			if len(claim.Leases) != count {
				t.Fatalf("queued %d notifications want %d", len(claim.Leases), count)
			}
		})
	}
}
