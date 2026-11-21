package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/vmihailenco/msgpack/v5"
	"strings"
)

func zeroValue[T any]() (zero T) { return }

// runCommand commits the native result and state together. MessagePack appears
// only at the durable receipt boundary, including exact replay of old results.
func runCommand[T any](o *Service, operation, requestID string, request any, mutate func(*snapshot) (T, error)) (Result[T], error) {
	if strings.TrimSpace(requestID) == "" {
		return failure[T]("invalid_request", "request_id is required"), nil
	}
	result, err := commitCommand(o, operation, requestID, request, func(s *snapshot) (Result[T], error) {
		value, err := mutate(s)
		if err != nil {
			return Result[T]{}, err
		}
		return success(value), nil
	})
	if typed, ok := err.(domainError); ok {
		return failure[T](typed.code, typed.message), nil
	}
	return result, err
}

func runRawCommand[T any](o *Service, operation, requestID string, request any, mutate func(*snapshot) (T, error)) (T, error) {
	return commitCommand(o, operation, requestID, request, mutate)
}

func commitCommand[T any](o *Service, operation, requestID string, request any, mutate func(*snapshot) (T, error)) (T, error) {
	var zero T
	if strings.TrimSpace(requestID) == "" {
		return zero, fmt.Errorf("request_id is required")
	}
	wire, err := msgpack.Marshal(request)
	if err != nil {
		return zero, err
	}
	sum := sha256.Sum256(wire)
	digest := hex.EncodeToString(sum[:])
	o.mu.Lock()
	defer o.mu.Unlock()
	for attempt := 0; attempt < 128; attempt++ {
		revision, current, prior, err := o.store.LoadCommand(context.Background(), operation, requestID)
		if err != nil {
			return zero, fmt.Errorf("refresh %s: %w", operation, err)
		}
		normalizeSnapshot(&current)
		o.state = current
		if prior != nil {
			if prior.Digest != digest {
				return zero, domain("idempotency_conflict", "request_id was reused with a different payload")
			}
			var result T
			if err := msgpack.Unmarshal(prior.Response, &result); err != nil {
				return zero, fmt.Errorf("read command receipt: %w", err)
			}
			o.receipts[operation+":"+requestID] = *prior
			return result, nil
		}
		next := current.clone()
		value, err := mutate(&next)
		if err != nil {
			return zero, err
		}
		response, err := msgpack.Marshal(value)
		if err != nil {
			return zero, err
		}
		receipt := commandReceipt{Operation: operation, RequestID: requestID, Digest: digest, Response: response}
		committed, err := o.store.AppendCAS(context.Background(), revision, durableRecord{Receipt: receipt, Snapshot: next})
		if err != nil {
			return zero, fmt.Errorf("persist %s: %w", operation, err)
		}
		if !committed {
			continue
		}
		o.state, o.receipts[operation+":"+requestID] = next, receipt
		return value, nil
	}
	return zero, fmt.Errorf("persist %s: owner revision remained contended", operation)
}

func runQuery[T any](o *Service, run func(snapshot) (T, error)) (Result[T], error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, current, _, err := o.store.LoadCommand(context.Background(), "", "")
	if err != nil {
		return Result[T]{}, fmt.Errorf("refresh identity query: %w", err)
	}
	normalizeSnapshot(&current)
	o.state = current
	value, err := run(current)
	if err != nil {
		if typed, ok := err.(domainError); ok {
			return failure[T](typed.code, typed.message), nil
		}
		return Result[T]{}, err
	}
	return success(value), nil
}
