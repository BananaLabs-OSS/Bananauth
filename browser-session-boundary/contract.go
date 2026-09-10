package main

const (
	ProviderResolve = "auth.browser-session.v1.resolve"
	ContractVersion = "auth.browser-session.v1"
	AccountAudience = "account"

	maxCredentialBytes = 4096
	maxOpaqueIDBytes   = 128
)

type ResolveRequest struct {
	Version    string `msgpack:"version"`
	Audience   string `msgpack:"audience"`
	Credential string `msgpack:"credential"`
}

type ResolveResult struct {
	Version            string `msgpack:"version"`
	OK                 bool   `msgpack:"ok"`
	Audience           string `msgpack:"audience,omitempty"`
	AccountID          string `msgpack:"account_id,omitempty"`
	SessionID          string `msgpack:"session_id,omitempty"`
	ExpiresAtUnixMilli int64  `msgpack:"expires_at_unix_milli,omitempty"`
	Error              string `msgpack:"error,omitempty"`
}

type jwtClaims struct {
	AccountID string
	SessionID string
}

type sessionGetRequest struct {
	SessionID string `msgpack:"session_id"`
	Now       int64  `msgpack:"now"`
}

type sessionFact struct {
	SessionID string `msgpack:"session_id"`
	AccountID string `msgpack:"account_id"`
	ExpiresAt int64  `msgpack:"expires_at"`
	RevokedAt int64  `msgpack:"revoked_at,omitempty"`
	Active    bool   `msgpack:"active"`
}

type sessionError struct {
	Code string `msgpack:"code"`
}

type sessionGetResult struct {
	Version string        `msgpack:"version"`
	OK      bool          `msgpack:"ok"`
	Value   sessionFact   `msgpack:"value"`
	Error   *sessionError `msgpack:"error,omitempty"`
}
