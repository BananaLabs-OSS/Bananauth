package browser

import (
	"errors"

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

func TestResolveDeniedTypedResultHasNoPrincipalOrAssurance(t *testing.T) {
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
			request := validRequest()
			if tc.malformed {
				request = ResolveRequest{}
			}
			result := r.resolveRequest(request)
			if result.OK || result.Error != tc.code || result.AccountID != "" || result.SessionID != "" || result.Email != "" || result.VerifiedEmail != "" || result.EmailVerified {
				t.Fatalf("denied result leaked principal or assurance: %+v", result)
			}

		})
	}
}

func TestResolvePositiveTypedResultPreservesAssurance(t *testing.T) {
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
		result := r.resolveRequest(validRequest())
		if !result.OK || result.EmailVerified != assured {
			t.Fatalf("positive assurance changed: %+v", result)
		}
		if assured && result.VerifiedEmail != "verified@example.test" {
			t.Fatal("verified email missing")
		}
		if !assured && result.VerifiedEmail != "" {
			t.Fatal("ordinary session manufactured assurance")
		}

	}
}
