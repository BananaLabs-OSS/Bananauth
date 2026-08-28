package main

import (
	"errors"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

type owner struct{ store sessionStore }

func newOwner(store sessionStore) *owner { return &owner{store: store} }

func (o *owner) providers() map[string]func([]byte) ([]byte, error) {
	return map[string]func([]byte) ([]byte, error){
		FnCreate: o.create,
		FnGet:    o.get,
		FnRevoke: o.revoke,
	}
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
