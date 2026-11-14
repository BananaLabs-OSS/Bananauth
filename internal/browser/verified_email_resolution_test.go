package browser

import (
	"bytes"
	"errors"
	"github.com/vmihailenco/msgpack/v5"
	"testing"
	"time"
)

func TestResolveEmailAssuranceComesFromSessionNotProfile(t *testing.T) {
	r := validResolver()
	baseGet := r.get
	legacy, _ := resolveRequest(t, r, validRequest())
	if !legacy.OK || legacy.EmailVerified || legacy.VerifiedEmail != "" {
		t.Fatal("legacy profile became verified")
	}
	r.get = func(req sessionGetRequest) (sessionGetResult, error) {
		v, e := baseGet(req)
		v.Value.CreatedAt = fixedNow.Add(-time.Hour).UnixMilli()
		v.Value.VerifiedEmail = "verified@example.test"
		v.Value.EmailVerifiedAtUnixMilli = v.Value.CreatedAt - 1000
		v.Value.EmailVerificationExpiresAtUnixMilli = v.Value.CreatedAt + 60000
		v.Value.VerificationRequestID = "verified-operation"
		return v, e
	}
	got, _ := resolveRequest(t, r, validRequest())
	if !got.OK || !got.EmailVerified || got.VerifiedEmail != "verified@example.test" || got.Email != "member@example.test" {
		t.Fatalf("owner proof/profile conflated: %#v", got)
	}
	// The original OTP expired; the already-created active session retains its
	// assurance without extending the original proof or session lifetime.
}
func TestResolveRejectsPartialOrImpossibleSessionEmailAssurance(t *testing.T) {
	for _, mutate := range []func(*sessionFact){func(s *sessionFact) { s.VerifiedEmail = "verified@example.test" }, func(s *sessionFact) {
		s.VerifiedEmail = "Mixed@Example.test"
		s.CreatedAt = 100
		s.EmailVerifiedAtUnixMilli = 50
		s.EmailVerificationExpiresAtUnixMilli = 200
		s.VerificationRequestID = "proof"
	}, func(s *sessionFact) {
		s.VerifiedEmail = "verified@example.test"
		s.CreatedAt = 300
		s.EmailVerifiedAtUnixMilli = 50
		s.EmailVerificationExpiresAtUnixMilli = 200
		s.VerificationRequestID = "proof"
	}} {
		r := validResolver()
		get := r.get
		r.get = func(req sessionGetRequest) (sessionGetResult, error) { v, e := get(req); mutate(&v.Value); return v, e }
		if got, _ := resolveRequest(t, r, validRequest()); got.OK {
			t.Fatal("invalid session assurance authorized")
		}
	}
}

func TestResolveNegativeWireRetainsExactThreeFieldContract(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		prepare    func(*resolver)
		malformed  bool
	}{
		{"malformed", "invalid_request", nil, true},
		{"expired JWT", "unauthorized", func(r *resolver) {
			r.verify = func(string) (jwtClaims, error) { return jwtClaims{}, errors.New("expired token") }
		}, false},
		{"owner unavailable", "unavailable", func(r *resolver) {
			r.get = func(sessionGetRequest) (sessionGetResult, error) {
				return sessionGetResult{}, errors.New("owner unavailable")
			}
		}, false},
		{"expired session", "unauthorized", func(r *resolver) {
			get := r.get
			r.get = func(req sessionGetRequest) (sessionGetResult, error) {
				v, e := get(req)
				v.Value.Active = false
				return v, e
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := validResolver()
			if tc.prepare != nil {
				tc.prepare(&r)
			}
			input, err := msgpack.Marshal(validRequest())
			if err != nil {
				t.Fatal(err)
			}
			if tc.malformed {
				input = []byte{0x80}
			}
			wire, err := r.resolve(input)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if msgpack.Unmarshal(wire, &fields) != nil || len(fields) != 3 || fields["version"] != ContractVersion || fields["ok"] != false || fields["error"] != tc.code {
				t.Fatalf("negative wire changed: %#v", fields)
			}
			if _, exists := fields["email_verified"]; exists {
				t.Fatal("failure must not carry session assurance")
			}
		})
	}
}

func TestResolvePositiveWirePreservesExplicitAssuranceSchemas(t *testing.T) {
	for _, assured := range []bool{false, true} {
		r := validResolver()
		if assured {
			get := r.get
			r.get = func(req sessionGetRequest) (sessionGetResult, error) {
				v, e := get(req)
				v.Value.CreatedAt = fixedNow.Add(-time.Hour).UnixMilli()
				v.Value.VerifiedEmail = "verified@example.test"
				v.Value.EmailVerifiedAtUnixMilli = v.Value.CreatedAt - 1000
				v.Value.EmailVerificationExpiresAtUnixMilli = v.Value.CreatedAt + 60000
				v.Value.VerificationRequestID = "verified-operation"
				return v, e
			}
		}
		input, err := msgpack.Marshal(validRequest())
		if err != nil {
			t.Fatal(err)
		}
		result := r.resolveValue(input)
		if !result.OK {
			t.Fatal("positive fixture denied")
		}
		expected, err := msgpack.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := r.resolve(input)
		if err != nil || !bytes.Equal(wire, expected) {
			t.Fatal("positive receipt bytes changed")
		}
		var fields map[string]any
		if msgpack.Unmarshal(wire, &fields) != nil {
			t.Fatal("positive receipt decode")
		}
		want := 8
		if assured {
			want = 9
		}
		if len(fields) != want || fields["email_verified"] != assured {
			t.Fatalf("positive schema changed: %#v", fields)
		}
	}
}
