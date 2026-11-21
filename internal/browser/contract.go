package browser

import (
	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/session"
)

const (
	ContractVersion = "auth.browser-session.v1"
	AccountAudience = "account"

	maxCredentialBytes = 4096
	maxOpaqueIDBytes   = 128
)

type CompleteEmailVerificationRequest struct {
	Version   string `msgpack:"version" json:"version"`
	RequestID string `msgpack:"request_id" json:"request_id"`
	Email     string `msgpack:"email" json:"email"`
	Code      string `msgpack:"code" json:"code"`
}

type CompleteEmailVerificationResult struct {
	Version            string `msgpack:"version" json:"version"`
	OK                 bool   `msgpack:"ok" json:"ok"`
	AccessToken        string `msgpack:"access_token,omitempty" json:"access_token,omitempty"`
	AccountID          string `msgpack:"account_id,omitempty" json:"account_id,omitempty"`
	SessionID          string `msgpack:"session_id,omitempty" json:"session_id,omitempty"`
	ExpiresIn          int64  `msgpack:"expires_in,omitempty" json:"expires_in,omitempty"`
	ExpiresAtUnixMilli int64  `msgpack:"expires_at_unix_milli,omitempty" json:"expires_at_unix_milli,omitempty"`
	Error              string `msgpack:"error,omitempty" json:"error,omitempty"`
}

type ResolveRequest struct {
	Version    string `msgpack:"version" json:"version"`
	Audience   string `msgpack:"audience" json:"audience"`
	Credential string `msgpack:"credential" json:"credential"`
}

type ResolveResult struct {
	VerifiedEmail      string `msgpack:"verified_email,omitempty" json:"verified_email,omitempty"`
	EmailVerified      bool   `msgpack:"email_verified" json:"email_verified"`
	Version            string `msgpack:"version" json:"version"`
	OK                 bool   `msgpack:"ok" json:"ok"`
	Audience           string `msgpack:"audience,omitempty" json:"audience,omitempty"`
	AccountID          string `msgpack:"account_id,omitempty" json:"account_id,omitempty"`
	SessionID          string `msgpack:"session_id,omitempty" json:"session_id,omitempty"`
	ExpiresAtUnixMilli int64  `msgpack:"expires_at_unix_milli,omitempty" json:"expires_at_unix_milli,omitempty"`
	Email              string `msgpack:"email,omitempty" json:"email,omitempty"`
	Error              string `msgpack:"error,omitempty" json:"error,omitempty"`
}

type jwtClaims struct {
	AccountID string
	SessionID string
}

type sessionGetRequest = session.GetRequest
type sessionFact = session.Session
type sessionError = session.Error
type accountGetRequest = identity.AccountGetRequest
type accountGetResult = identity.Result[identity.AccountProjection]
type sessionGetResult = session.Result[session.Session]

type CompleteEmailVerificationRequestV2 struct {
	Version   string `msgpack:"version" json:"version"`
	RequestID string `msgpack:"request_id" json:"request_id"`
	Email     string `msgpack:"email" json:"email"`
	Code      string `msgpack:"code" json:"code"`
	Intent    string `msgpack:"intent" json:"intent"`
}
