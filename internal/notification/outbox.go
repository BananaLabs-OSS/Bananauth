// Package notification defines Bananauth's durable encrypted-email queue.
// It does not dispatch arbitrary effects or expose a guest protocol.
package notification

import (
	"bytes"
	"errors"
	"strings"
	"unicode"
)

type Status string

const (
	Pending   Status = "pending"
	Completed Status = "completed"
	Failed    Status = "failed"
)

type Failure struct {
	Code    string `msgpack:"code"`
	Message string `msgpack:"message"`
}
type Message struct {
	ID             string `msgpack:"id"`
	IdempotencyKey string `msgpack:"idempotency_key"`
	Ciphertext     []byte `msgpack:"ciphertext"`
}

func identifier(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}
func (m Message) Validate() error {
	if !identifier(m.ID) || !identifier(m.IdempotencyKey) || len(m.Ciphertext) == 0 || len(m.Ciphertext) > 1<<20 {
		return errors.New("invalid encrypted notification")
	}
	return nil
}
func NewMessage(id, key string, ciphertext []byte) (Message, error) {
	m := Message{ID: id, IdempotencyKey: key, Ciphertext: append([]byte(nil), ciphertext...)}
	return m, m.Validate()
}

type ClaimRequest struct {
	ConsumerID          string `msgpack:"consumer_id"`
	Limit               uint32 `msgpack:"limit"`
	LeaseDurationMillis int64  `msgpack:"lease_duration_millis"`
}

func (r ClaimRequest) Validate() error {
	if !identifier(r.ConsumerID) || r.Limit < 1 || r.Limit > 1000 || r.LeaseDurationMillis <= 0 || r.LeaseDurationMillis > 3600000 {
		return errors.New("invalid notification claim")
	}
	return nil
}
func NewClaimRequest(consumer string, limit uint32, duration int64) (ClaimRequest, error) {
	r := ClaimRequest{consumer, limit, duration}
	return r, r.Validate()
}

type Lease struct {
	ConsumerID           string  `msgpack:"consumer_id"`
	LeaseID              string  `msgpack:"lease_id"`
	Attempt              uint32  `msgpack:"attempt"`
	LeasedUntilUnixMilli int64   `msgpack:"leased_until_unix_milli"`
	Message              Message `msgpack:"message"`
}

func (l Lease) Validate() error {
	if !identifier(l.ConsumerID) || !identifier(l.LeaseID) || l.Attempt == 0 || l.LeasedUntilUnixMilli <= 0 {
		return errors.New("invalid notification lease")
	}
	return l.Message.Validate()
}

type ClaimResult struct {
	ConsumerID string  `msgpack:"consumer_id"`
	Leases     []Lease `msgpack:"leases"`
}

func (r ClaimResult) Validate() error {
	if !identifier(r.ConsumerID) || len(r.Leases) > 1000 {
		return errors.New("invalid notification claim result")
	}
	tokens, ids := map[string]bool{}, map[string]bool{}
	for _, lease := range r.Leases {
		if err := lease.Validate(); err != nil {
			return err
		}
		if lease.ConsumerID != r.ConsumerID || tokens[lease.LeaseID] || ids[lease.Message.ID] {
			return errors.New("notification claim identity mismatch")
		}
		tokens[lease.LeaseID] = true
		ids[lease.Message.ID] = true
	}
	return nil
}

type Receipt struct {
	MessageID         string   `msgpack:"message_id"`
	IdempotencyKey    string   `msgpack:"idempotency_key"`
	Status            Status   `msgpack:"status"`
	ProviderMessageID string   `msgpack:"provider_message_id,omitempty"`
	Failure           *Failure `msgpack:"failure,omitempty"`
}

func (r Receipt) Validate() error {
	if !identifier(r.MessageID) || !identifier(r.IdempotencyKey) {
		return errors.New("invalid notification receipt")
	}
	if r.Status == Completed {
		if r.Failure != nil {
			return errors.New("completed notification contains failure")
		}
	} else if r.Status == Failed {
		if r.Failure == nil || !identifier(r.Failure.Code) || len(r.Failure.Message) > 1024 {
			return errors.New("invalid notification failure")
		}
	} else {
		return errors.New("notification receipt must be terminal")
	}
	return nil
}
func (r Receipt) ValidateFor(message Message) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.MessageID != message.ID || r.IdempotencyKey != message.IdempotencyKey {
		return errors.New("notification receipt identity mismatch")
	}
	return nil
}
func NewCompletedReceipt(message Message, providerMessageID string) (Receipt, error) {
	r := Receipt{MessageID: message.ID, IdempotencyKey: message.IdempotencyKey, Status: Completed, ProviderMessageID: providerMessageID}
	return r, r.ValidateFor(message)
}
func NewFailedReceipt(message Message, failure Failure) (Receipt, error) {
	r := Receipt{MessageID: message.ID, IdempotencyKey: message.IdempotencyKey, Status: Failed, Failure: &failure}
	return r, r.ValidateFor(message)
}

type AcknowledgeRequest struct {
	ConsumerID string  `msgpack:"consumer_id"`
	LeaseID    string  `msgpack:"lease_id"`
	Receipt    Receipt `msgpack:"receipt"`
}

func (r AcknowledgeRequest) Validate() error {
	if !identifier(r.ConsumerID) || !identifier(r.LeaseID) {
		return errors.New("invalid notification acknowledgement")
	}
	return r.Receipt.Validate()
}
func (r AcknowledgeRequest) ValidateFor(lease Lease) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.ConsumerID != lease.ConsumerID || r.LeaseID != lease.LeaseID {
		return errors.New("notification lease lost")
	}
	return r.Receipt.ValidateFor(lease.Message)
}

type RetryRequest struct {
	ConsumerID       string  `msgpack:"consumer_id"`
	LeaseID          string  `msgpack:"lease_id"`
	Failure          Failure `msgpack:"failure"`
	RetryAtUnixMilli int64   `msgpack:"retry_at_unix_milli"`
}

func (r RetryRequest) Validate() error {
	if !identifier(r.ConsumerID) || !identifier(r.LeaseID) || !identifier(r.Failure.Code) || len(r.Failure.Message) > 1024 || r.RetryAtUnixMilli <= 0 {
		return errors.New("invalid notification retry")
	}
	return nil
}
func (r RetryRequest) ValidateFor(lease Lease) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.ConsumerID != lease.ConsumerID || r.LeaseID != lease.LeaseID {
		return errors.New("notification lease lost")
	}
	return nil
}

type SettlementResult struct {
	ConsumerID string `msgpack:"consumer_id"`
	LeaseID    string `msgpack:"lease_id"`
	Settled    bool   `msgpack:"settled"`
}

func (r SettlementResult) ValidateFor(lease Lease) error {
	if r.ConsumerID != lease.ConsumerID || r.LeaseID != lease.LeaseID {
		return errors.New("notification settlement identity mismatch")
	}
	return nil
}

type ObserveConsumerRequest struct {
	ConsumerID string `msgpack:"consumer_id"`
}

func (r ObserveConsumerRequest) Validate() error {
	if !identifier(r.ConsumerID) {
		return errors.New("invalid notification consumer")
	}
	return nil
}

type ConsumerObservation struct {
	AtMillis int64 `msgpack:"at_ms"`
	Leased   int64 `msgpack:"leased"`
	Overdue  int64 `msgpack:"overdue"`
}

func SameMessage(a, b Message) bool {
	return a.ID == b.ID && a.IdempotencyKey == b.IdempotencyKey && bytes.Equal(a.Ciphertext, b.Ciphertext)
}

func (m Message) Clone() Message { m.Ciphertext = append([]byte(nil), m.Ciphertext...); return m }
func (l Lease) Clone() Lease     { l.Message = l.Message.Clone(); return l }
