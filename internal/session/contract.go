package session

const (
	ContractVersion = "auth-session.v1"
)

type Error struct {
	Code    string `msgpack:"code" json:"code"`
	Message string `msgpack:"message" json:"message"`
}

type Result[T any] struct {
	Version string `msgpack:"version" json:"version"`
	OK      bool   `msgpack:"ok" json:"ok"`
	Value   T      `msgpack:"value,omitempty" json:"value,omitempty"`
	Error   *Error `msgpack:"error,omitempty" json:"error,omitempty"`
}

type Session struct {
	VerifiedEmail                       string `msgpack:"verified_email,omitempty" json:"verified_email,omitempty"`
	EmailVerifiedAtUnixMilli            int64  `msgpack:"email_verified_at_unix_milli,omitempty" json:"email_verified_at_unix_milli,omitempty"`
	EmailVerificationExpiresAtUnixMilli int64  `msgpack:"email_verification_expires_at_unix_milli,omitempty" json:"email_verification_expires_at_unix_milli,omitempty"`
	VerificationRequestID               string `msgpack:"verification_request_id,omitempty" json:"verification_request_id,omitempty"`

	SessionID string `msgpack:"session_id" json:"session_id"`
	AccountID string `msgpack:"account_id" json:"account_id"`
	CreatedAt int64  `msgpack:"created_at" json:"created_at"`
	ExpiresAt int64  `msgpack:"expires_at" json:"expires_at"`
	RevokedAt int64  `msgpack:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	Active    bool   `msgpack:"active" json:"active"`
}

type CreateRequest struct {
	RequestID string `msgpack:"request_id" json:"request_id"`
	SessionID string `msgpack:"session_id" json:"session_id"`
	AccountID string `msgpack:"account_id" json:"account_id"`
	CreatedAt int64  `msgpack:"created_at" json:"created_at"`
	ExpiresAt int64  `msgpack:"expires_at" json:"expires_at"`
}

// CreateOwnedRequest lets the auth-session owner provide the authoritative
// clock while preserving idempotency from a stable logical request.
type CreateOwnedRequest struct {
	RequestID      string `msgpack:"request_id" json:"request_id"`
	SessionID      string `msgpack:"session_id" json:"session_id"`
	AccountID      string `msgpack:"account_id" json:"account_id"`
	LifetimeMillis int64  `msgpack:"lifetime_millis" json:"lifetime_millis"`
}

type CreateEmailVerifiedOwnedRequest struct {
	RequestID      string `msgpack:"request_id" json:"request_id"`
	SessionID      string `msgpack:"session_id" json:"session_id"`
	AccountID      string `msgpack:"account_id" json:"account_id"`
	LifetimeMillis int64  `msgpack:"lifetime_millis" json:"lifetime_millis"`

	VerifiedEmail                       string `msgpack:"verified_email,omitempty" json:"verified_email,omitempty"`
	EmailVerifiedAtUnixMilli            int64  `msgpack:"email_verified_at_unix_milli,omitempty" json:"email_verified_at_unix_milli,omitempty"`
	EmailVerificationExpiresAtUnixMilli int64  `msgpack:"email_verification_expires_at_unix_milli,omitempty" json:"email_verification_expires_at_unix_milli,omitempty"`
	VerificationRequestID               string `msgpack:"verification_request_id,omitempty" json:"verification_request_id,omitempty"`
}

type GetRequest struct {
	SessionID string `msgpack:"session_id" json:"session_id"`
	Now       int64  `msgpack:"now" json:"now"`
}

type RevokeRequest struct {
	RequestID string `msgpack:"request_id" json:"request_id"`
	SessionID string `msgpack:"session_id" json:"session_id"`
	RevokedAt int64  `msgpack:"revoked_at" json:"revoked_at"`
}

type RevokeOwnedRequest struct {
	RequestID string `msgpack:"request_id" json:"request_id"`
	SessionID string `msgpack:"session_id" json:"session_id"`
}

func success[T any](value T) Result[T] {
	return Result[T]{Version: ContractVersion, OK: true, Value: value}
}

func failure[T any](code, message string) Result[T] {
	return Result[T]{Version: ContractVersion, Error: &Error{Code: code, Message: message}}
}
