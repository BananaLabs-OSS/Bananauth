package identity

import (
	"fmt"
	"github.com/vmihailenco/msgpack/v5"
	"sort"
	"strings"
	"unicode"
)

// Hold commands deliberately accept no expiry or clock. A finite lease keeps
// its existing separate contract. Unknown fields fail instead of silently
// turning a caller's expiring request into indefinite protection.
func decodeRetentionHoldRequest(raw []byte) (RetentionHoldRequest, error) {
	var fields map[string]msgpack.RawMessage
	var req RetentionHoldRequest
	if err := msgpack.Unmarshal(raw, &fields); err != nil {
		return req, err
	}
	allowed := map[string]bool{"request_id": true, "account_id": true, "hold_id": true, "reason_id": true, "acquisition_id": true}
	if len(fields) != len(allowed) {
		return req, fmt.Errorf("hold requires exactly request_id, account_id, hold_id, reason_id, acquisition_id")
	}
	for key := range fields {
		if !allowed[key] {
			return req, fmt.Errorf("unknown hold field")
		}
	}
	if err := msgpack.Unmarshal(raw, &req); err != nil {
		return req, err
	}
	for _, id := range []string{req.RequestID, req.AccountID, req.HoldID, req.ReasonID, req.AcquisitionID} {
		if id == "" || len(id) > 256 || strings.TrimSpace(id) != id || strings.IndexFunc(id, unicode.IsControl) >= 0 {
			return req, fmt.Errorf("hold identifiers must be bounded nonempty opaque strings")
		}
	}
	return req, nil
}
func retentionHoldKey(req RetentionHoldRequest) string {
	return req.AccountID + "\x00" + req.HoldID + "\x00" + req.AcquisitionID
}
func activeRetentionHolds(s *snapshot, account string) []RetentionHold {
	holds := make([]RetentionHold, 0)
	for _, hold := range s.RetentionHolds {
		if hold.Active && hold.AccountID == account {
			holds = append(holds, hold)
		}
	}
	sort.Slice(holds, func(i, j int) bool {
		if holds[i].HoldID != holds[j].HoldID {
			return holds[i].HoldID < holds[j].HoldID
		}
		return holds[i].AcquisitionID < holds[j].AcquisitionID
	})
	return holds
}
func retentionEligibilityFor(s *snapshot, account string, now int64) RetentionEligibility {
	leases := activeRetentionLeases(s, account, now)
	holds := activeRetentionHolds(s, account)
	return RetentionEligibility{Deletable: len(leases) == 0 && len(holds) == 0, LiveLeases: leases, LiveHolds: holds}
}
func (o *owner) retentionHoldAcquire(raw []byte) ([]byte, error) {
	req, err := decodeRetentionHoldRequest(raw)
	if err != nil {
		return encode(failure[any]("invalid_request", err.Error()))
	}
	return o.command(FnRetentionHoldAcquire, req.RequestID, req, func(s *snapshot) (any, error) {
		if _, ok := s.Accounts[req.AccountID]; !ok {
			return nil, domain("not_found", "No account found")
		}
		key := retentionHoldKey(req)
		if old, ok := s.RetentionHolds[key]; ok {
			if old.ReasonID != req.ReasonID {
				return nil, domain("conflict", "hold reason cannot change")
			}
			if !old.Active {
				return nil, domain("conflict", "released acquisition cannot be acquired again")
			}
			return old, nil
		}
		for _, old := range s.RetentionHolds {
			if old.Active && old.AccountID == req.AccountID && old.HoldID == req.HoldID {
				return nil, domain("conflict", "hold already has an active acquisition")
			}
		}
		hold := RetentionHold{AccountID: req.AccountID, HoldID: req.HoldID, ReasonID: req.ReasonID, AcquisitionID: req.AcquisitionID, Active: true}
		s.RetentionHolds[key] = hold
		return hold, nil
	})
}
func (o *owner) retentionHoldRelease(raw []byte) ([]byte, error) {
	req, err := decodeRetentionHoldRequest(raw)
	if err != nil {
		return encode(failure[any]("invalid_request", err.Error()))
	}
	return o.command(FnRetentionHoldRelease, req.RequestID, req, func(s *snapshot) (any, error) {
		key := retentionHoldKey(req)
		hold, ok := s.RetentionHolds[key]
		if !ok {
			return nil, domain("not_found", "hold acquisition not found")
		}
		if hold.ReasonID != req.ReasonID {
			return nil, domain("conflict", "hold reason does not match")
		}
		hold.Active = false
		s.RetentionHolds[key] = hold
		return hold, nil
	})
}
