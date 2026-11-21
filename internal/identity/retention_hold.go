package identity

import (
	"fmt"

	"sort"
	"strings"
	"unicode"
)

// Hold commands deliberately accept no expiry or clock. A finite lease keeps
// its existing separate contract. Unknown fields fail instead of silently
// turning a caller's expiring request into indefinite protection.
func validateRetentionHoldRequest(req RetentionHoldRequest) error {
	for _, id := range []string{req.RequestID, req.AccountID, req.HoldID, req.ReasonID, req.AcquisitionID} {
		if id == "" || len(id) > 256 || strings.TrimSpace(id) != id || strings.IndexFunc(id, unicode.IsControl) >= 0 {
			return fmt.Errorf("hold identifiers must be bounded nonempty opaque strings")
		}
	}
	return nil
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
func (o *Service) RetentionHoldAcquire(req RetentionHoldRequest) (Result[RetentionHold], error) {
	if err := validateRetentionHoldRequest(req); err != nil {
		return failure[RetentionHold]("invalid_request", err.Error()), nil
	}
	return runCommand[RetentionHold](o, FnRetentionHoldAcquire, req.RequestID, req, func(s *snapshot) (RetentionHold, error) {
		if _, ok := s.Accounts[req.AccountID]; !ok {
			return zeroValue[RetentionHold](), domain("not_found", "No account found")
		}
		key := retentionHoldKey(req)
		if old, ok := s.RetentionHolds[key]; ok {
			if old.ReasonID != req.ReasonID {
				return zeroValue[RetentionHold](), domain("conflict", "hold reason cannot change")
			}
			if !old.Active {
				return zeroValue[RetentionHold](), domain("conflict", "released acquisition cannot be acquired again")
			}
			return old, nil
		}
		for _, old := range s.RetentionHolds {
			if old.Active && old.AccountID == req.AccountID && old.HoldID == req.HoldID {
				return zeroValue[RetentionHold](), domain("conflict", "hold already has an active acquisition")
			}
		}
		hold := RetentionHold{AccountID: req.AccountID, HoldID: req.HoldID, ReasonID: req.ReasonID, AcquisitionID: req.AcquisitionID, Active: true}
		s.RetentionHolds[key] = hold
		return hold, nil
	})
}
func (o *Service) RetentionHoldRelease(req RetentionHoldRequest) (Result[RetentionHold], error) {
	if err := validateRetentionHoldRequest(req); err != nil {
		return failure[RetentionHold]("invalid_request", err.Error()), nil
	}
	return runCommand[RetentionHold](o, FnRetentionHoldRelease, req.RequestID, req, func(s *snapshot) (RetentionHold, error) {
		key := retentionHoldKey(req)
		hold, ok := s.RetentionHolds[key]
		if !ok {
			return zeroValue[RetentionHold](), domain("not_found", "hold acquisition not found")
		}
		if hold.ReasonID != req.ReasonID {
			return zeroValue[RetentionHold](), domain("conflict", "hold reason does not match")
		}
		hold.Active = false
		s.RetentionHolds[key] = hold
		return hold, nil
	})
}
