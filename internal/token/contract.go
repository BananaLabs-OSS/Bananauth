package token

type SignRequest struct {
	AccountID string `msgpack:"account_id"`
	SessionID string `msgpack:"session_id"`
	ExpiresAt int64  `msgpack:"expires_at"`
}
