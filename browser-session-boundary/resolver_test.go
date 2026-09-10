package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

var fixedNow = time.UnixMilli(1_800_000_000_000).UTC()

func validResolver() resolver {
	return resolver{
		verify: func(token string) (jwtClaims, error) {
			if token != "signed.jwt.value" {
				return jwtClaims{}, errors.New("invalid token containing secret material")
			}
			return jwtClaims{AccountID: "account_01", SessionID: "session_01"}, nil
		},
		get: func(req sessionGetRequest) (sessionGetResult, error) {
			return sessionGetResult{Version: sessionContractVersion, OK: true, Value: sessionFact{
				AccountID: "account_01", SessionID: req.SessionID,
				ExpiresAt: fixedNow.Add(time.Hour).UnixMilli(), Active: true,
			}}, nil
		},
		now: func() time.Time { return fixedNow },
	}
}

func validRequest() ResolveRequest {
	return ResolveRequest{Version: ContractVersion, Audience: AccountAudience, Credential: "Bearer signed.jwt.value"}
}

func resolveRequest(t *testing.T, r resolver, request any) (ResolveResult, []byte) {
	t.Helper()
	wire, err := msgpack.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := r.resolve(wire)
	if err != nil {
		t.Fatal(err)
	}
	var result ResolveResult
	if err := msgpack.Unmarshal(response, &result); err != nil {
		t.Fatal(err)
	}
	return result, response
}

func TestResolveVerifiesJWTAndDurableSessionAndClampsBinding(t *testing.T) {
	var observed sessionGetRequest
	r := validResolver()
	r.get = func(req sessionGetRequest) (sessionGetResult, error) {
		observed = req
		return sessionGetResult{Version: sessionContractVersion, OK: true, Value: sessionFact{
			AccountID: "account_01", SessionID: "session_01",
			ExpiresAt: fixedNow.Add(90 * time.Second).UnixMilli(), Active: true,
		}}, nil
	}
	result, response := resolveRequest(t, r, validRequest())
	if !result.OK || result.Version != ContractVersion || result.Audience != AccountAudience || result.AccountID != "account_01" || result.SessionID != "session_01" {
		t.Fatalf("result = %#v", result)
	}
	if result.ExpiresAtUnixMilli != fixedNow.Add(90*time.Second).UnixMilli() {
		t.Fatalf("expiry = %d", result.ExpiresAtUnixMilli)
	}
	if observed != (sessionGetRequest{SessionID: "session_01", Now: fixedNow.UnixMilli()}) {
		t.Fatalf("owner request = %#v", observed)
	}
	for _, secret := range []string{"Bearer", "signed.jwt.value", "credential"} {
		if strings.Contains(string(response), secret) {
			t.Fatalf("response leaked %q: %x", secret, response)
		}
	}
}

func TestResolveCapsLongSessionAtFiveMinutes(t *testing.T) {
	result, _ := resolveRequest(t, validResolver(), validRequest())
	if !result.OK || result.ExpiresAtUnixMilli != fixedNow.Add(5*time.Minute).UnixMilli() {
		t.Fatalf("result = %#v", result)
	}
}

func TestResolveRejectsUntrustedRequestShapeBeforeVerification(t *testing.T) {
	tests := []struct {
		name    string
		request any
	}{
		{"missing version", map[string]any{"audience": AccountAudience, "credential": "Bearer signed.jwt.value"}},
		{"wrong version", ResolveRequest{Version: "v2", Audience: AccountAudience, Credential: "Bearer signed.jwt.value"}},
		{"wrong audience", ResolveRequest{Version: ContractVersion, Audience: "public", Credential: "Bearer signed.jwt.value"}},
		{"caller account", map[string]any{"version": ContractVersion, "audience": AccountAudience, "credential": "Bearer signed.jwt.value", "account_id": "attacker"}},
		{"caller clock", map[string]any{"version": ContractVersion, "audience": AccountAudience, "credential": "Bearer signed.jwt.value", "now": int64(1)}},
		{"caller ttl", map[string]any{"version": ContractVersion, "audience": AccountAudience, "credential": "Bearer signed.jwt.value", "ttl": int64(999999)}},
		{"lowercase bearer", ResolveRequest{Version: ContractVersion, Audience: AccountAudience, Credential: "bearer signed.jwt.value"}},
		{"whitespace token", ResolveRequest{Version: ContractVersion, Audience: AccountAudience, Credential: "Bearer signed.jwt.value extra"}},
		{"oversized", ResolveRequest{Version: ContractVersion, Audience: AccountAudience, Credential: "Bearer " + strings.Repeat("x", maxCredentialBytes)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifyCalls := 0
			r := validResolver()
			r.verify = func(string) (jwtClaims, error) { verifyCalls++; return jwtClaims{}, nil }
			result, _ := resolveRequest(t, r, test.request)
			if result.OK || result.AccountID != "" || result.SessionID != "" || result.ExpiresAtUnixMilli != 0 || verifyCalls != 0 {
				t.Fatalf("result=%#v verifyCalls=%d", result, verifyCalls)
			}
		})
	}
}

func TestResolveRejectsJWTAndOwnerFactFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*resolver)
	}{
		{"jwt rejected", func(r *resolver) {
			r.verify = func(string) (jwtClaims, error) { return jwtClaims{}, errors.New("token secret") }
		}},
		{"invalid claim account", func(r *resolver) {
			r.verify = func(string) (jwtClaims, error) {
				return jwtClaims{AccountID: "email@example.com", SessionID: "session_01"}, nil
			}
		}},
		{"owner unavailable", func(r *resolver) {
			r.get = func(sessionGetRequest) (sessionGetResult, error) {
				return sessionGetResult{}, errors.New("database detail")
			}
		}},
		{"wrong owner version", func(r *resolver) { r.get = factResult(func(f *sessionFact) {}, "auth-session.v2", true) }},
		{"owner denied", func(r *resolver) { r.get = factResult(func(f *sessionFact) {}, sessionContractVersion, false) }},
		{"inactive", func(r *resolver) {
			r.get = factResult(func(f *sessionFact) { f.Active = false }, sessionContractVersion, true)
		}},
		{"revoked", func(r *resolver) {
			r.get = factResult(func(f *sessionFact) { f.RevokedAt = fixedNow.Add(-time.Second).UnixMilli() }, sessionContractVersion, true)
		}},
		{"expired", func(r *resolver) {
			r.get = factResult(func(f *sessionFact) { f.ExpiresAt = fixedNow.UnixMilli() }, sessionContractVersion, true)
		}},
		{"session mismatch", func(r *resolver) {
			r.get = factResult(func(f *sessionFact) { f.SessionID = "session_other" }, sessionContractVersion, true)
		}},
		{"account mismatch", func(r *resolver) {
			r.get = factResult(func(f *sessionFact) { f.AccountID = "account_other" }, sessionContractVersion, true)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := validResolver()
			test.mutate(&r)
			result, response := resolveRequest(t, r, validRequest())
			if result.OK || result.AccountID != "" || result.SessionID != "" || result.ExpiresAtUnixMilli != 0 {
				t.Fatalf("result = %#v", result)
			}
			for _, private := range []string{"signed.jwt.value", "token secret", "database detail"} {
				if strings.Contains(string(response), private) {
					t.Fatalf("failure leaked private value %q", private)
				}
			}
		})
	}
}

func factResult(mutate func(*sessionFact), version string, ok bool) func(sessionGetRequest) (sessionGetResult, error) {
	return func(req sessionGetRequest) (sessionGetResult, error) {
		fact := sessionFact{AccountID: "account_01", SessionID: req.SessionID, ExpiresAt: fixedNow.Add(time.Hour).UnixMilli(), Active: true}
		mutate(&fact)
		return sessionGetResult{Version: version, OK: ok, Value: fact}, nil
	}
}

func TestResolverIsRaceSafeAndHoldsNoCredentialState(t *testing.T) {
	r := validResolver()
	request, err := msgpack.Marshal(validRequest())
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 64; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 32; j++ {
				response, callErr := r.resolve(request)
				if callErr != nil {
					t.Errorf("resolve: %v", callErr)
					return
				}
				if strings.Contains(string(response), "signed.jwt.value") {
					t.Error("credential retained in response")
					return
				}
			}
		}()
	}
	group.Wait()
}
