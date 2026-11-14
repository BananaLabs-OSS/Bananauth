package browser

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vmihailenco/msgpack/v5"
)

const sessionContractVersion = "auth-session.v1"

type resolver struct {
	verify  func(string) (jwtClaims, error)
	get     func(sessionGetRequest) (sessionGetResult, error)
	account func(accountGetRequest) (accountGetResult, error)
	now     func() time.Time
}

func (r resolver) resolve(raw []byte) ([]byte, error) {
	result := r.resolveValue(raw)
	if !result.OK {
		// Negative receipts retain the exact original three-field contract.
		// Assurance fields describe successful live sessions only.
		return msgpack.Marshal(struct {
			Version string `msgpack:"version"`
			OK      bool   `msgpack:"ok"`
			Error   string `msgpack:"error"`
		}{Version: result.Version, OK: false, Error: result.Error})
	}
	return msgpack.Marshal(result)
}

func (r resolver) resolveValue(raw []byte) ResolveResult {
	if r.verify == nil || r.get == nil || r.account == nil || r.now == nil {
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
	accountResult, err := r.account(accountGetRequest{AccountID: fact.AccountID})
	if err != nil {
		return denied("unavailable")
	}
	email := strings.ToLower(strings.TrimSpace(accountResult.Value.Email))
	if accountResult.Version != "auth-identity.v1" || !accountResult.OK || accountResult.Value.AccountID != fact.AccountID || len(email) < 3 || len(email) > 254 || !strings.Contains(email, "@") || !utf8.ValidString(email) {
		return denied("unauthorized")
	}
	expires := now.Add(5 * time.Minute).UnixMilli()
	if fact.ExpiresAt < expires {
		expires = fact.ExpiresAt
	}
	verifiedEmail, emailVerified, proofValid := verifiedSessionEmail(fact)
	if !proofValid {
		return denied("unauthorized")
	}
	return ResolveResult{
		Version: ContractVersion, OK: true, Audience: AccountAudience,
		AccountID: fact.AccountID, SessionID: fact.SessionID,
		ExpiresAtUnixMilli: expires, Email: email, VerifiedEmail: verifiedEmail, EmailVerified: emailVerified,
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

// Legacy and generic sessions carry no email assurance. A complete proof is
// valid for the existing session lifetime, not a renewed OTP deadline.
func verifiedSessionEmail(fact sessionFact) (string, bool, bool) {
	if fact.VerifiedEmail == "" && fact.EmailVerifiedAtUnixMilli == 0 && fact.EmailVerificationExpiresAtUnixMilli == 0 && fact.VerificationRequestID == "" {
		return "", false, true
	}
	email := fact.VerifiedEmail
	if email != strings.ToLower(strings.TrimSpace(email)) || len(email) < 3 || len(email) > 254 || !strings.Contains(email, "@") || !utf8.ValidString(email) ||
		fact.EmailVerifiedAtUnixMilli <= 0 || fact.EmailVerificationExpiresAtUnixMilli <= fact.EmailVerifiedAtUnixMilli ||
		fact.CreatedAt < fact.EmailVerifiedAtUnixMilli || fact.CreatedAt >= fact.EmailVerificationExpiresAtUnixMilli || !verificationOperationID(fact.VerificationRequestID) {
		return "", false, false
	}
	return email, true, true
}

func verificationOperationID(value string) bool {
	if value == "" || len(value) > maxOpaqueIDBytes || !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '-' && c != '_' && c != ':' {
			return false
		}
	}
	return true
}
