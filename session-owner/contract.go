package main

const (
	ContractVersion = "auth-session.v1"

	FnCreate = "auth.session.v1.create"
	FnGet    = "auth.session.v1.get"
	FnRevoke = "auth.session.v1.revoke"
)

type Error struct {
	Code    string `msgpack:"code"`
	Message string `msgpack:"message"`
}

type Result[T any] struct {
	Version string `msgpack:"version"`
	OK      bool   `msgpack:"ok"`
	Value   T      `msgpack:"value,omitempty"`
	Error   *Error `msgpack:"error,omitempty"`
}

type Session struct {
	SessionID string `msgpack:"session_id"`
	AccountID string `msgpack:"account_id"`
	CreatedAt int64  `msgpack:"created_at"`
	ExpiresAt int64  `msgpack:"expires_at"`
	RevokedAt int64  `msgpack:"revoked_at,omitempty"`
	Active    bool   `msgpack:"active"`
}

type CreateRequest struct {
	RequestID string `msgpack:"request_id"`
	SessionID string `msgpack:"session_id"`
	AccountID string `msgpack:"account_id"`
	CreatedAt int64  `msgpack:"created_at"`
	ExpiresAt int64  `msgpack:"expires_at"`
}

type GetRequest struct {
	SessionID string `msgpack:"session_id"`
	Now       int64  `msgpack:"now"`
}

type RevokeRequest struct {
	RequestID string `msgpack:"request_id"`
	SessionID string `msgpack:"session_id"`
	RevokedAt int64  `msgpack:"revoked_at"`
}

func success[T any](value T) Result[T] {
	return Result[T]{Version: ContractVersion, OK: true, Value: value}
}

func failure[T any](code, message string) Result[T] {
	return Result[T]{Version: ContractVersion, Error: &Error{Code: code, Message: message}}
}
