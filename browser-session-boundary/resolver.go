package main

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vmihailenco/msgpack/v5"
)

const sessionContractVersion = "auth-session.v1"

type resolver struct {
	verify func(string) (jwtClaims, error)
	get    func(sessionGetRequest) (sessionGetResult, error)
	now    func() time.Time
}

func (r resolver) resolve(raw []byte) ([]byte, error) {
	result := r.resolveValue(raw)
	return msgpack.Marshal(result)
}

func (r resolver) resolveValue(raw []byte) ResolveResult {
	if r.verify == nil || r.get == nil || r.now == nil {
		return denied("unavailable")
	}
	request, ok := decodeExactRequest(raw)
	if !ok {
		return denied("invalid_request")
	}
	token, ok := bearerToken(request.Credential)
	if !ok {
		return denied("unauthorized")
	}
	claims, err := r.verify(token)
	if err != nil || !opaqueID(claims.AccountID) || !opaqueID(claims.SessionID) {
		return denied("unauthorized")
	}

	now := r.now().UTC()
	nowMillis := now.UnixMilli()
	if nowMillis <= 0 {
		return denied("unavailable")
	}
	factResult, err := r.get(sessionGetRequest{SessionID: claims.SessionID, Now: nowMillis})
	if err != nil {
		return denied("unavailable")
	}
	fact := factResult.Value
	if factResult.Version != sessionContractVersion || !factResult.OK || !fact.Active || fact.RevokedAt != 0 || fact.ExpiresAt <= nowMillis || fact.SessionID != claims.SessionID || fact.AccountID != claims.AccountID || !opaqueID(fact.AccountID) || !opaqueID(fact.SessionID) {
		return denied("unauthorized")
	}
	expires := now.Add(5 * time.Minute).UnixMilli()
	if fact.ExpiresAt < expires {
		expires = fact.ExpiresAt
	}
	return ResolveResult{
		Version: ContractVersion, OK: true, Audience: AccountAudience,
		AccountID: fact.AccountID, SessionID: fact.SessionID,
		ExpiresAtUnixMilli: expires,
	}
}

func decodeExactRequest(raw []byte) (ResolveRequest, bool) {
	if len(raw) == 0 || len(raw) > maxCredentialBytes+256 {
		return ResolveRequest{}, false
	}
	var fields map[string]any
	if err := msgpack.Unmarshal(raw, &fields); err != nil || len(fields) != 3 {
		return ResolveRequest{}, false
	}
	for _, key := range []string{"version", "audience", "credential"} {
		if _, exists := fields[key]; !exists {
			return ResolveRequest{}, false
		}
	}
	for key := range fields {
		if key != "version" && key != "audience" && key != "credential" {
			return ResolveRequest{}, false
		}
	}
	request := ResolveRequest{}
	var valid bool
	request.Version, valid = fields["version"].(string)
	if !valid || request.Version != ContractVersion {
		return ResolveRequest{}, false
	}
	request.Audience, valid = fields["audience"].(string)
	if !valid || request.Audience != AccountAudience {
		return ResolveRequest{}, false
	}
	request.Credential, valid = fields["credential"].(string)
	if !valid || len(request.Credential) == 0 || len(request.Credential) > maxCredentialBytes || !utf8.ValidString(request.Credential) {
		return ResolveRequest{}, false
	}
	return request, true
}

func bearerToken(credential string) (string, bool) {
	if !strings.HasPrefix(credential, "Bearer ") || len(credential) <= len("Bearer ") {
		return "", false
	}
	token := credential[len("Bearer "):]
	if strings.TrimSpace(token) != token || strings.ContainsAny(token, " \t\r\n\x00") {
		return "", false
	}
	return token, true
}

func opaqueID(value string) bool {
	if value == "" || len(value) > maxOpaqueIDBytes || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func denied(code string) ResolveResult {
	if code == "" {
		code = "unauthorized"
	}
	return ResolveResult{Version: ContractVersion, Error: code}
}
