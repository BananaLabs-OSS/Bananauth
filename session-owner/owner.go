package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

type owner struct {
	store sessionStore
	now   func() time.Time
}

func newOwner(store sessionStore) *owner { return &owner{store: store, now: time.Now} }

func (o *owner) providers() map[string]func([]byte) ([]byte, error) {
	return map[string]func([]byte) ([]byte, error){
		FnCreate:      o.create,
		FnCreateOwned: o.createOwned,
		FnGet:         o.get,
		FnRevoke:      o.revoke,
		FnRevokeOwned: o.revokeOwned,
	}
}

func (o *owner) revokeOwned(raw []byte) ([]byte, error) {
	var req RevokeOwnedRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if blank(req.RequestID) || blank(req.SessionID) {
		return encode(failure[Session]("invalid_request", "request_id and session_id are required"))
	}
	now := o.now().UTC().UnixMilli()
	if now <= 0 {
		return encode(failure[Session]("clock_unavailable", "owner clock is unavailable"))
	}
	value, ok, err := o.store.RevokeOwned(req, now)
	if err != nil {
		var conflict requestConflictError
		if errors.As(err, &conflict) {
			return encode(failure[Session]("idempotency_conflict", conflict.Error()))
		}
		var competing sessionMutationConflictError
		if errors.As(err, &competing) {
			return encode(failure[Session]("mutation_conflict", competing.Error()))
		}
		return nil, fmt.Errorf("revoke owner-clock auth session: %w", err)
	}
	if !ok {
		return encode(failure[Session]("not_found", "session not found"))
	}
	value.Active = false
	return encode(success(value))
}

func (o *owner) createOwned(raw []byte) ([]byte, error) {
	var req CreateOwnedRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if blank(req.RequestID) || blank(req.SessionID) || blank(req.AccountID) || req.LifetimeMillis <= 0 || req.LifetimeMillis > int64((30*24*time.Hour)/time.Millisecond) {
		return encode(failure[Session]("invalid_request", "request_id, session_id, account_id, and a bounded lifetime are required"))
	}
	now := o.now().UTC().UnixMilli()
	if now <= 0 {
		return encode(failure[Session]("clock_unavailable", "owner clock is unavailable"))
	}
	value, err := o.store.CreateOwned(req, now)
	if err != nil {
		var conflict requestConflictError
		if errors.As(err, &conflict) {
			return encode(failure[Session]("idempotency_conflict", conflict.Error()))
		}
		return nil, fmt.Errorf("create owner-clock auth session: %w", err)
	}
	value.Active = value.RevokedAt == 0 && value.ExpiresAt > now
	return encode(success(value))
}

func (o *owner) create(raw []byte) ([]byte, error) {
	var req CreateRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if blank(req.RequestID) || blank(req.SessionID) || blank(req.AccountID) || req.CreatedAt <= 0 || req.ExpiresAt <= req.CreatedAt {
		return encode(failure[Session]("invalid_request", "request_id, session_id, account_id, and a valid lifetime are required"))
	}
	value, err := o.store.Create(req)
	if err != nil {
		var conflict requestConflictError
		if errors.As(err, &conflict) {
			return encode(failure[Session]("idempotency_conflict", conflict.Error()))
		}
		return nil, fmt.Errorf("create auth session: %w", err)
	}
	value.Active = value.RevokedAt == 0 && value.ExpiresAt > req.CreatedAt
	return encode(success(value))
}

func (o *owner) get(raw []byte) ([]byte, error) {
	var req GetRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if blank(req.SessionID) || req.Now <= 0 {
		return encode(failure[Session]("invalid_request", "session_id and now are required"))
	}
	value, ok, err := o.store.Get(req.SessionID)
	if err != nil {
		return nil, fmt.Errorf("get auth session: %w", err)
	}
	if !ok {
		return encode(failure[Session]("not_found", "session not found"))
	}
	value.Active = value.RevokedAt == 0 && value.ExpiresAt > req.Now
	return encode(success(value))
}

func (o *owner) revoke(raw []byte) ([]byte, error) {
	var req RevokeRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if blank(req.RequestID) || blank(req.SessionID) || req.RevokedAt <= 0 {
		return encode(failure[Session]("invalid_request", "request_id, session_id, and revoked_at are required"))
	}
	value, ok, err := o.store.Revoke(req)
	if err != nil {
		var conflict requestConflictError
		if errors.As(err, &conflict) {
			return encode(failure[Session]("idempotency_conflict", conflict.Error()))
		}
		var competing sessionMutationConflictError
		if errors.As(err, &competing) {
			return encode(failure[Session]("mutation_conflict", competing.Error()))
		}
		return nil, fmt.Errorf("revoke auth session: %w", err)
	}
	if !ok {
		return encode(failure[Session]("not_found", "session not found"))
	}
	value.Active = false
	return encode(success(value))
}

func decode(raw []byte, value any) error {
	if len(raw) == 0 {
		return fmt.Errorf("empty auth session request")
	}
	if err := msgpack.Unmarshal(raw, value); err != nil {
		return fmt.Errorf("decode auth session request: %w", err)
	}
	return nil
}

func encode(value any) ([]byte, error) {
	raw, err := msgpack.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode auth session response: %w", err)
	}
	return raw, nil
}
