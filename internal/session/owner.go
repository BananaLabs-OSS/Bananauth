package session

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

type Service struct {
	store sessionStore
	now   func() time.Time
}

func newOwner(store sessionStore) *Service { return &Service{store: store, now: time.Now} }

func (o *Service) RevokeOwned(req RevokeOwnedRequest) (Result[Session], error) {
	if blank(req.RequestID) || blank(req.SessionID) {
		return failure[Session]("invalid_request", "request_id and session_id are required"), nil
	}
	now := o.now().UTC().UnixMilli()
	if now <= 0 {
		return failure[Session]("clock_unavailable", "owner clock is unavailable"), nil
	}
	value, ok, err := o.store.RevokeOwned(req, now)
	if err != nil {
		var conflict requestConflictError
		if errors.As(err, &conflict) {
			return failure[Session]("idempotency_conflict", conflict.Error()), nil
		}
		var competing sessionMutationConflictError
		if errors.As(err, &competing) {
			return failure[Session]("mutation_conflict", competing.Error()), nil
		}
		return Result[Session]{}, fmt.Errorf("revoke owner-clock auth session: %w", err)
	}
	if !ok {
		return failure[Session]("not_found", "session not found"), nil
	}
	value.Active = false
	return success(value), nil
}

func (o *Service) CreateOwned(req CreateOwnedRequest) (Result[Session], error) {
	if blank(req.RequestID) || blank(req.SessionID) || blank(req.AccountID) || req.LifetimeMillis <= 0 || req.LifetimeMillis > int64((30*24*time.Hour)/time.Millisecond) {
		return failure[Session]("invalid_request", "request_id, session_id, account_id, and a bounded lifetime are required"), nil
	}
	now := o.now().UTC().UnixMilli()
	if now <= 0 {
		return failure[Session]("clock_unavailable", "owner clock is unavailable"), nil
	}
	value, err := o.store.CreateOwned(req, now)
	if err != nil {
		var conflict requestConflictError
		if errors.As(err, &conflict) {
			return failure[Session]("idempotency_conflict", conflict.Error()), nil
		}
		return Result[Session]{}, fmt.Errorf("create owner-clock auth session: %w", err)
	}
	value.Active = value.RevokedAt == 0 && value.ExpiresAt > now
	return success(value), nil
}

func (o *Service) Create(req CreateRequest) (Result[Session], error) {
	if blank(req.RequestID) || blank(req.SessionID) || blank(req.AccountID) || req.CreatedAt <= 0 || req.ExpiresAt <= req.CreatedAt {
		return failure[Session]("invalid_request", "request_id, session_id, account_id, and a valid lifetime are required"), nil
	}
	value, err := o.store.Create(req)
	if err != nil {
		var conflict requestConflictError
		if errors.As(err, &conflict) {
			return failure[Session]("idempotency_conflict", conflict.Error()), nil
		}
		return Result[Session]{}, fmt.Errorf("create auth session: %w", err)
	}
	value.Active = value.RevokedAt == 0 && value.ExpiresAt > req.CreatedAt
	return success(value), nil
}

func (o *Service) Get(req GetRequest) (Result[Session], error) {
	if blank(req.SessionID) || req.Now <= 0 {
		return failure[Session]("invalid_request", "session_id and now are required"), nil
	}
	value, ok, err := o.store.Get(req.SessionID)
	if err != nil {
		return Result[Session]{}, fmt.Errorf("get auth session: %w", err)
	}
	if !ok {
		return failure[Session]("not_found", "session not found"), nil
	}
	value.Active = value.RevokedAt == 0 && value.ExpiresAt > req.Now
	return success(value), nil
}

func (o *Service) Revoke(req RevokeRequest) (Result[Session], error) {
	if blank(req.RequestID) || blank(req.SessionID) || req.RevokedAt <= 0 {
		return failure[Session]("invalid_request", "request_id, session_id, and revoked_at are required"), nil
	}
	value, ok, err := o.store.Revoke(req)
	if err != nil {
		var conflict requestConflictError
		if errors.As(err, &conflict) {
			return failure[Session]("idempotency_conflict", conflict.Error()), nil
		}
		var competing sessionMutationConflictError
		if errors.As(err, &competing) {
			return failure[Session]("mutation_conflict", competing.Error()), nil
		}
		return Result[Session]{}, fmt.Errorf("revoke auth session: %w", err)
	}
	if !ok {
		return failure[Session]("not_found", "session not found"), nil
	}
	value.Active = false
	return success(value), nil
}

func (o *Service) CreateEmailVerifiedOwned(req CreateEmailVerifiedOwnedRequest) (Result[Session], error) {
	if blank(req.RequestID) || blank(req.SessionID) || blank(req.AccountID) || req.LifetimeMillis <= 0 || req.LifetimeMillis > int64((30*24*time.Hour)/time.Millisecond) {
		return failure[Session]("invalid_request", "bounded session identity is required"), nil
	}
	if !validVerification(req) {
		return failure[Session]("invalid_verification", "email verification proof is invalid"), nil
	}
	now := o.now().UTC().UnixMilli()
	if now <= 0 || now > int64(^uint64(0)>>1)-req.LifetimeMillis {
		return failure[Session]("clock_unavailable", "owner clock is unavailable"), nil
	}
	value, err := o.store.CreateEmailVerifiedOwned(req, now)
	if err != nil {
		var conflict requestConflictError
		if errors.As(err, &conflict) {
			return failure[Session]("idempotency_conflict", conflict.Error()), nil
		}
		var proof verificationTimeError
		if errors.As(err, &proof) {
			return failure[Session](proof.code, "email verification proof is not current"), nil
		}
		return Result[Session]{}, fmt.Errorf("create email-verified auth session: %w", err)
	}
	value.Active = value.RevokedAt == 0 && value.ExpiresAt > now
	return success(value), nil
}
func validVerification(req CreateEmailVerifiedOwnedRequest) bool {
	email := req.VerifiedEmail
	return len(email) >= 3 && len(email) <= 254 && utf8.ValidString(email) && email == strings.ToLower(strings.TrimSpace(email)) && strings.Count(email, "@") == 1 && !strings.ContainsAny(email, "\x00\r\n\t ") && req.EmailVerifiedAtUnixMilli > 0 && req.EmailVerificationExpiresAtUnixMilli > req.EmailVerifiedAtUnixMilli && !blank(req.VerificationRequestID) && len(req.VerificationRequestID) <= 256 && !strings.ContainsAny(req.VerificationRequestID, "\x00\r\n")
}
