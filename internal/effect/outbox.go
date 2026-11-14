package effect

import (
	"errors"
	"fmt"
)

const (
	// OutboxVersionV1 identifies the provider-neutral leasing wire used by
	// state owners and host dispatchers. It versions lease semantics separately
	// from the effect intent envelope.
	OutboxVersionV1 = "pulp.effect.outbox.v1"

	FnOutboxClaim       = "effect.outbox.claim.v1"
	FnOutboxAcknowledge = "effect.outbox.acknowledge.v1"
	FnOutboxRetry       = "effect.outbox.retry.v1"
)

const (
	maxClaimLimit          = 1000
	maxLeaseDurationMillis = 60 * 60 * 1000
)

// ClaimRequest asks one state-owning outbox to atomically lease pending work
// to a particular dispatcher instance.
type ClaimRequest struct {
	Version             string `msgpack:"version"`
	Owner               string `msgpack:"owner"`
	ConsumerID          string `msgpack:"consumer_id"`
	Limit               uint32 `msgpack:"limit"`
	LeaseDurationMillis int64  `msgpack:"lease_duration_millis"`
}

// Lease is one claimed canonical Intent. LeaseID is an opaque fencing token:
// acknowledgement and retry must present the exact token returned by claim.
type Lease struct {
	Version              string `msgpack:"version"`
	Owner                string `msgpack:"owner"`
	ConsumerID           string `msgpack:"consumer_id"`
	LeaseID              string `msgpack:"lease_id"`
	Attempt              uint32 `msgpack:"attempt"`
	LeasedUntilUnixMilli int64  `msgpack:"leased_until_unix_milli"`
	Intent               Intent `msgpack:"intent"`
}

// ClaimResult is the bounded batch returned by FnOutboxClaim.
type ClaimResult struct {
	Version    string  `msgpack:"version"`
	Owner      string  `msgpack:"owner"`
	ConsumerID string  `msgpack:"consumer_id"`
	Leases     []Lease `msgpack:"leases"`
}

// AcknowledgeRequest durably records a host Receipt for a leased Intent.
type AcknowledgeRequest struct {
	Version    string  `msgpack:"version"`
	Owner      string  `msgpack:"owner"`
	ConsumerID string  `msgpack:"consumer_id"`
	LeaseID    string  `msgpack:"lease_id"`
	Receipt    Receipt `msgpack:"receipt"`
}

// RetryRequest releases failed leased work for a future attempt. Failure is a
// stable non-secret summary; RetryAtUnixMilli is an absolute owner-clock time.
type RetryRequest struct {
	Version          string  `msgpack:"version"`
	Owner            string  `msgpack:"owner"`
	ConsumerID       string  `msgpack:"consumer_id"`
	LeaseID          string  `msgpack:"lease_id"`
	Failure          Failure `msgpack:"failure"`
	RetryAtUnixMilli int64   `msgpack:"retry_at_unix_milli"`
}

// SettlementResult is returned by both FnOutboxAcknowledge and
// FnOutboxRetry. Settled=false is an expected fencing outcome: the lease was
// lost or expired and the dispatcher must discard its stale result.
type SettlementResult struct {
	Version    string `msgpack:"version"`
	Owner      string `msgpack:"owner"`
	ConsumerID string `msgpack:"consumer_id"`
	LeaseID    string `msgpack:"lease_id"`
	Settled    bool   `msgpack:"settled"`
}

func NewClaimRequest(owner, consumerID string, limit uint32, leaseDurationMillis int64) (ClaimRequest, error) {
	request := ClaimRequest{
		Version: OutboxVersionV1, Owner: owner, ConsumerID: consumerID,
		Limit: limit, LeaseDurationMillis: leaseDurationMillis,
	}
	return request, request.Validate()
}

func (r ClaimRequest) Validate() error {
	if err := validateOutboxHeader(r.Version, r.Owner, r.ConsumerID); err != nil {
		return err
	}
	if r.Limit == 0 || r.Limit > maxClaimLimit {
		return fmt.Errorf("effect outbox claim limit must be between 1 and %d", maxClaimLimit)
	}
	if r.LeaseDurationMillis <= 0 || r.LeaseDurationMillis > maxLeaseDurationMillis {
		return fmt.Errorf("effect outbox lease_duration_millis must be between 1 and %d", maxLeaseDurationMillis)
	}
	return nil
}

func (l Lease) Validate() error {
	if err := validateOutboxHeader(l.Version, l.Owner, l.ConsumerID); err != nil {
		return err
	}
	if err := validateField("effect outbox lease_id", l.LeaseID); err != nil {
		return err
	}
	if l.Attempt == 0 {
		return errors.New("effect outbox lease attempt must be positive")
	}
	if l.LeasedUntilUnixMilli <= 0 {
		return errors.New("effect outbox leased_until_unix_milli must be positive")
	}
	return l.Intent.Validate()
}

func (r ClaimResult) Validate() error {
	if err := validateOutboxHeader(r.Version, r.Owner, r.ConsumerID); err != nil {
		return err
	}
	if len(r.Leases) > maxClaimLimit {
		return fmt.Errorf("effect outbox claim result exceeds %d leases", maxClaimLimit)
	}
	seenLeaseIDs := make(map[string]struct{}, len(r.Leases))
	seenIntentIDs := make(map[string]struct{}, len(r.Leases))
	for index, lease := range r.Leases {
		if err := lease.Validate(); err != nil {
			return fmt.Errorf("effect outbox lease %d: %w", index, err)
		}
		if lease.Owner != r.Owner || lease.ConsumerID != r.ConsumerID {
			return fmt.Errorf("effect outbox lease %d does not match claim result", index)
		}
		if _, ok := seenLeaseIDs[lease.LeaseID]; ok {
			return fmt.Errorf("effect outbox lease_id %q is duplicated", lease.LeaseID)
		}
		seenLeaseIDs[lease.LeaseID] = struct{}{}
		if _, ok := seenIntentIDs[lease.Intent.ID]; ok {
			return fmt.Errorf("effect outbox intent id %q is duplicated", lease.Intent.ID)
		}
		seenIntentIDs[lease.Intent.ID] = struct{}{}
	}
	return nil
}

func (r AcknowledgeRequest) Validate() error {
	if err := validateOutboxHeader(r.Version, r.Owner, r.ConsumerID); err != nil {
		return err
	}
	if err := validateField("effect outbox lease_id", r.LeaseID); err != nil {
		return err
	}
	if r.Receipt.Status == Pending {
		return errors.New("effect outbox acknowledgement receipt must be terminal")
	}
	return r.Receipt.Validate()
}

// ValidateFor proves the acknowledgement is fenced by this exact lease and
// acknowledges its exact intent.
func (r AcknowledgeRequest) ValidateFor(lease Lease) error {
	if err := lease.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Owner != lease.Owner || r.ConsumerID != lease.ConsumerID || r.LeaseID != lease.LeaseID {
		return errors.New("effect outbox acknowledgement does not match lease")
	}
	return r.Receipt.ValidateFor(lease.Intent)
}

func (r RetryRequest) Validate() error {
	if err := validateOutboxHeader(r.Version, r.Owner, r.ConsumerID); err != nil {
		return err
	}
	if err := validateField("effect outbox lease_id", r.LeaseID); err != nil {
		return err
	}
	if err := r.Failure.Validate(); err != nil {
		return fmt.Errorf("effect outbox retry failure: %w", err)
	}
	if r.RetryAtUnixMilli <= 0 {
		return errors.New("effect outbox retry_at_unix_milli must be positive")
	}
	return nil
}

func (r RetryRequest) ValidateFor(lease Lease) error {
	if err := lease.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Owner != lease.Owner || r.ConsumerID != lease.ConsumerID || r.LeaseID != lease.LeaseID {
		return errors.New("effect outbox retry does not match lease")
	}
	return nil
}

func (r SettlementResult) Validate() error {
	if err := validateOutboxHeader(r.Version, r.Owner, r.ConsumerID); err != nil {
		return err
	}
	return validateField("effect outbox lease_id", r.LeaseID)
}

func (r SettlementResult) ValidateFor(lease Lease) error {
	if err := lease.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Owner != lease.Owner || r.ConsumerID != lease.ConsumerID || r.LeaseID != lease.LeaseID {
		return errors.New("effect outbox settlement does not match lease")
	}
	return nil
}

func validateOutboxHeader(version, owner, consumerID string) error {
	if version != OutboxVersionV1 {
		return fmt.Errorf("unsupported effect outbox version %q", version)
	}
	if err := validateField("effect outbox owner", owner); err != nil {
		return err
	}
	return validateField("effect outbox consumer_id", consumerID)
}
