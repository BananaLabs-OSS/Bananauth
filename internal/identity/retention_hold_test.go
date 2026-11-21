package identity

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func holdRequest(id, acquisition string) RetentionHoldRequest {
	return RetentionHoldRequest{RequestID: id, AccountID: "account", HoldID: "opaque-hold", ReasonID: "opaque-reason", AcquisitionID: acquisition}
}
func registerHoldAccount(t *testing.T, o *owner) {
	t.Helper()
	if !callResult[AccountProjection](t, o.nativeRegister, registerRequest("register", "account", "member@example.test")).OK {
		t.Fatal("account registration failed")
	}
}
func checkHoldEligibility(t *testing.T, o *owner, now int64, count int) {
	t.Helper()
	r := callResult[RetentionEligibility](t, o.retentionEligibility, RetentionEligibilityRequest{AccountID: "account", Now: now})
	if !r.OK || len(r.Value.LiveHolds) != count || r.Value.Deletable != (count == 0 && len(r.Value.LiveLeases) == 0) {
		t.Fatalf("eligibility=%#v", r)
	}
}

func TestRetentionHoldsProtectBothDeletionPathsWithoutClock(t *testing.T) {
	for _, op := range []string{"delete", "erase"} {
		t.Run(op, func(t *testing.T) {
			o := newTestOwner(t, &memoryEventStore{})
			registerHoldAccount(t, o)
			if !callResult[RetentionHold](t, o.retentionHoldAcquire, holdRequest("hold", "a")).OK {
				t.Fatal("acquire failed")
			}
			lease := RetentionLease{AccountID: "account", LeaseID: "finite", ReasonID: "finite-reason", ExpiresAt: 200}
			if !callResult[RetentionLease](t, o.retentionLeaseCreate, RetentionLeaseCreateRequest{RequestID: "lease", Lease: lease, Now: 100}).OK {
				t.Fatal("lease failed")
			}
			checkHoldEligibility(t, o, 9_000_000_000_000, 1)
			var denied Result[AccountProjection]
			if op == "delete" {
				denied = callResult[AccountProjection](t, o.accountDelete, AccountDeleteRequest{RequestID: "blocked", AccountID: "account", Password: "password-1", Now: 9_000_000_000_000})
			} else {
				denied = callResult[AccountProjection](t, o.accountErase, AccountEraseRequest{RequestID: "blocked", AccountID: "account", ReasonID: "erase", Now: 9_000_000_000_000})
			}
			if denied.OK || denied.Error == nil || denied.Error.Code != "retention_active" {
				t.Fatalf("deletion bypassed hold=%#v", denied)
			}
			released := callResult[RetentionEligibility](t, o.retentionLeaseRelease, RetentionLeaseReleaseRequest{RequestID: "lease-release", AccountID: "account", LeaseID: "finite", ReasonID: "finite-reason", Now: 201})
			if !released.OK || released.Value.Deletable || len(released.Value.LiveHolds) != 1 {
				t.Fatalf("lease release ignored hold=%#v", released)
			}
			if !callResult[RetentionHold](t, o.retentionHoldRelease, holdRequest("release", "a")).OK {
				t.Fatal("release failed")
			}
			checkHoldEligibility(t, o, 202, 0)
			var deleted Result[AccountProjection]
			if op == "delete" {
				deleted = callResult[AccountProjection](t, o.accountDelete, AccountDeleteRequest{RequestID: "allowed", AccountID: "account", Password: "password-1", Now: 202})
			} else {
				deleted = callResult[AccountProjection](t, o.accountErase, AccountEraseRequest{RequestID: "allowed", AccountID: "account", ReasonID: "erase", Now: 202})
			}
			if !deleted.OK {
				t.Fatalf("deletion after release=%#v", deleted)
			}
		})
	}
}

func TestRetentionHoldDurableAcquisitionFenceAndReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	o := newTestOwner(t, openReplicaStore(t, path))
	registerHoldAccount(t, o)
	acquire := holdRequest("acquire-a", "a")
	raw, _ := msgpack.Marshal(acquire)
	first, err := o.retentionHoldAcquire(raw)
	if err != nil {
		t.Fatal(err)
	}
	o = newTestOwner(t, openReplicaStore(t, path))
	again, err := o.retentionHoldAcquire(raw)
	if err != nil || !bytes.Equal(first, again) {
		t.Fatal("reply-loss replay changed response")
	}
	if !callResult[RetentionHold](t, o.retentionHoldRelease, holdRequest("release-a", "a")).OK {
		t.Fatal("release failed")
	}
	if !callResult[RetentionHold](t, o.retentionHoldAcquire, holdRequest("acquire-b", "b")).OK {
		t.Fatal("new acquisition failed")
	}
	// An old successful acquire receipt is historical, never a new mutation.
	if replay, err := o.retentionHoldAcquire(raw); err != nil || !bytes.Equal(first, replay) {
		t.Fatal("historical response changed")
	}
	stale := callResult[RetentionHold](t, o.retentionHoldAcquire, holdRequest("late-acquire-a", "a"))
	if stale.OK || stale.Error == nil || stale.Error.Code != "conflict" {
		t.Fatalf("released acquisition resurrected=%#v", stale)
	}
	for _, r := range []RetentionHoldRequest{holdRequest("release-a", "a"), holdRequest("late-release-a", "a")} {
		if !callResult[RetentionHold](t, o.retentionHoldRelease, r).OK {
			t.Fatal("exact old release should replay harmlessly")
		}
		checkHoldEligibility(t, o, 9_000_000_000_000, 1)
	}
	changed := acquire
	changed.AcquisitionID = "changed"
	if r := callResult[RetentionHold](t, o.retentionHoldAcquire, changed); r.OK || r.Error == nil || r.Error.Code != "idempotency_conflict" {
		t.Fatalf("changed replay=%#v", r)
	}
	wrong := holdRequest("wrong-reason", "b")
	wrong.ReasonID = "other"
	if r := callResult[RetentionHold](t, o.retentionHoldRelease, wrong); r.OK || r.Error.Code != "conflict" {
		t.Fatalf("wrong reason=%#v", r)
	}
	foreign := holdRequest("foreign-release", "b")
	foreign.AccountID = "other-account"
	if r := callResult[RetentionHold](t, o.retentionHoldRelease, foreign); r.OK || r.Error.Code != "not_found" {
		t.Fatalf("foreign release=%#v", r)
	}
	if r := callResult[RetentionHold](t, o.retentionHoldAcquire, holdRequest("acquire-c", "c")); r.OK || r.Error.Code != "conflict" {
		t.Fatalf("active hold replaced=%#v", r)
	}
	o = newTestOwner(t, openReplicaStore(t, path))
	checkHoldEligibility(t, o, 9_000_000_000_000, 1)
	if !callResult[RetentionHold](t, o.retentionHoldRelease, holdRequest("release-b", "b")).OK {
		t.Fatal("release b failed")
	}
	checkHoldEligibility(t, o, 202, 0)
}

func TestRetentionHoldsReplicaCASRaces(t *testing.T) {
	for _, kind := range []string{"competing-acquire", "acquire-vs-erase"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity.db")
			first := newTestOwner(t, openReplicaStore(t, path))
			second := newTestOwner(t, openReplicaStore(t, path))
			registerHoldAccount(t, first)
			a, _ := msgpack.Marshal(holdRequest("acquire-a", "a"))
			var b []byte
			f := second.retentionHoldAcquire
			if kind == "competing-acquire" {
				b, _ = msgpack.Marshal(holdRequest("acquire-b", "b"))
			} else {
				b, _ = msgpack.Marshal(AccountEraseRequest{RequestID: "erase", AccountID: "account", ReasonID: "erase", Now: 200})
				f = second.accountErase
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			out := make([][]byte, 2)
			errs := make([]error, 2)
			for i, fn := range []func([]byte) ([]byte, error){first.retentionHoldAcquire, f} {
				wg.Add(1)
				go func(i int, fn func([]byte) ([]byte, error)) {
					defer wg.Done()
					<-start
					request := a
					if i == 1 {
						request = b
					}
					out[i], errs[i] = fn(request)
				}(i, fn)
			}
			close(start)
			wg.Wait()
			ok := 0
			for i := range out {
				if errs[i] != nil {
					t.Fatal(errs[i])
				}
				var r Result[any]
				if err := msgpack.Unmarshal(out[i], &r); err != nil {
					t.Fatal(err)
				}
				if r.OK {
					ok++
				}
			}
			if ok != 1 {
				t.Fatalf("mutually exclusive commands committed together: %s", out)
			}
			reopened := newTestOwner(t, openReplicaStore(t, path))
			account := callResult[AccountProjection](t, reopened.accountGet, AccountGetRequest{AccountID: "account"})
			if kind == "competing-acquire" || account.OK {
				checkHoldEligibility(t, reopened, 9_000_000_000_000, 1)
			} else {
				checkHoldEligibility(t, reopened, 200, 0)
			}
		})
	}
}

type faultHoldStore struct {
	eventStore
	failBefore, loseAfter bool
}

func (s *faultHoldStore) AppendCAS(ctx context.Context, revision int64, r durableRecord) (bool, error) {
	if s.failBefore {
		s.failBefore = false
		return false, fmt.Errorf("synthetic persistence failure")
	}
	ok, err := s.eventStore.AppendCAS(ctx, revision, r)
	if err == nil && ok && s.loseAfter {
		s.loseAfter = false
		return false, fmt.Errorf("synthetic reply loss after durable commit")
	}
	return ok, err
}
func TestRetentionHoldsFailedPersistAndCommittedReplyLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	base := openReplicaStore(t, path)
	o := newTestOwner(t, base)
	registerHoldAccount(t, o)
	fault := &faultHoldStore{eventStore: base, failBefore: true}
	o.store = fault
	raw, _ := msgpack.Marshal(holdRequest("acquire", "a"))
	if _, err := o.retentionHoldAcquire(raw); err == nil {
		t.Fatal("failed persistence reported success")
	}
	checkHoldEligibility(t, newTestOwner(t, openReplicaStore(t, path)), 200, 0)
	fault.loseAfter = true
	if _, err := o.retentionHoldAcquire(raw); err == nil {
		t.Fatal("reply loss not injected")
	}
	reopened := newTestOwner(t, openReplicaStore(t, path))
	checkHoldEligibility(t, reopened, 9_000_000_000_000, 1)
	if r := callResult[RetentionHold](t, reopened.retentionHoldAcquire, holdRequest("acquire", "a")); !r.OK || !r.Value.Active {
		t.Fatalf("durable retry=%#v", r)
	}
}

func TestRetentionHoldsRejectExpiryAndMalformedAuthority(t *testing.T) {
	o := newTestOwner(t, &memoryEventStore{})
	registerHoldAccount(t, o)
	good := map[string]any{"request_id": "hold", "account_id": "account", "hold_id": "opaque", "reason_id": "opaque", "acquisition_id": "a"}
	for _, field := range []string{"now", "expires_at", "ttl", "version"} {
		r := map[string]any{}
		for k, v := range good {
			r[k] = v
		}
		r[field] = 100
		v := callResult[RetentionHold](t, o.retentionHoldAcquire, r)
		if v.OK || v.Error == nil || v.Error.Code != "invalid_request" {
			t.Fatalf("unsupported field %s accepted=%#v", field, v)
		}
	}
	for _, bad := range []string{"", " padded", "nul\x00id", strings.Repeat("x", 257)} {
		r := holdRequest("invalid", "a")
		r.HoldID = bad
		v := callResult[RetentionHold](t, o.retentionHoldAcquire, r)
		if v.OK || v.Error == nil || v.Error.Code != "invalid_request" {
			t.Fatalf("bad id accepted=%#v", v)
		}
	}
	foreign := holdRequest("missing-account", "a")
	foreign.AccountID = "missing"
	if r := callResult[RetentionHold](t, o.retentionHoldAcquire, foreign); r.OK || r.Error.Code != "not_found" {
		t.Fatalf("missing account=%#v", r)
	}
	checkHoldEligibility(t, o, 200, 0)
	// A hold does not weaken the original future-expiry lease contract.
	r := callResult[RetentionLease](t, o.retentionLeaseCreate, RetentionLeaseCreateRequest{RequestID: "invalid-lease", Now: 100, Lease: RetentionLease{AccountID: "account", LeaseID: "finite", ReasonID: "opaque", ExpiresAt: 0}})
	if r.OK || r.Error.Code != "invalid_request" {
		t.Fatalf("finite lease accepted no expiry=%#v", r)
	}
}

func TestRetentionHoldsOldDataNormalizationAndTypedService(t *testing.T) {
	legacy := newSnapshot()
	legacy.RetentionHolds = nil
	normalizeSnapshot(&legacy)
	if legacy.RetentionHolds == nil {
		t.Fatal("old snapshot not normalized")
	}
	o := newTestOwner(t, &memoryEventStore{})
	request := RetentionHoldRequest{RequestID: "typed", AccountID: "missing", HoldID: "hold", ReasonID: "reason", AcquisitionID: "acquisition"}
	for _, execute := range []func(RetentionHoldRequest) (Result[RetentionHold], error){o.RetentionHoldAcquire, o.RetentionHoldRelease} {
		result, err := execute(request)
		if err != nil || result.OK || result.Error == nil || result.Error.Code != "not_found" {
			t.Fatalf("typed service rejected valid command incorrectly: %+v %v", result, err)
		}
	}

}

func TestRetentionHoldsErasureRemovesOnlyAccountTombstones(t *testing.T) {
	for _, op := range []string{"delete", "erase"} {
		t.Run(op, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity.db")
			o := newTestOwner(t, openReplicaStore(t, path))
			registerHoldAccount(t, o)
			if !callResult[AccountProjection](t, o.nativeRegister, registerRequest("register-other", "other", "other@example.test")).OK {
				t.Fatal("foreign registration failed")
			}
			for _, account := range []string{"account", "other"} {
				for _, acquisition := range []string{"a", "b"} {
					r := holdRequest(account+acquisition+"acquire", acquisition)
					r.AccountID = account
					if !callResult[RetentionHold](t, o.retentionHoldAcquire, r).OK {
						t.Fatal("acquire failed")
					}
					r.RequestID = account + acquisition + "release"
					if !callResult[RetentionHold](t, o.retentionHoldRelease, r).OK {
						t.Fatal("release failed")
					}
				}
			}
			foreign := map[string]RetentionHold{}
			for key, hold := range o.state.RetentionHolds {
				if hold.AccountID == "other" {
					foreign[key] = hold
				}
			}
			if len(foreign) != 2 || len(o.state.RetentionHolds) != 4 {
				t.Fatal("missing tombstones before erasure")
			}
			var result Result[AccountProjection]
			if op == "delete" {
				result = callResult[AccountProjection](t, o.accountDelete, AccountDeleteRequest{RequestID: "delete", AccountID: "account", Password: "password-1", Now: 202})
			} else {
				result = callResult[AccountProjection](t, o.accountErase, AccountEraseRequest{RequestID: "erase", AccountID: "account", ReasonID: "erase", Now: 202})
			}
			if !result.OK {
				t.Fatalf("erasure failed: %#v", result)
			}
			o = newTestOwner(t, openReplicaStore(t, path))
			if _, exists := o.state.Accounts["account"]; exists {
				t.Fatal("erased account survived reopen")
			}
			if len(o.state.RetentionHolds) != len(foreign) {
				t.Fatalf("unexpected holds after reopen: %#v", o.state.RetentionHolds)
			}
			for key, hold := range o.state.RetentionHolds {
				if hold.AccountID != "other" || foreign[key] != hold {
					t.Fatal("foreign hold changed or erased account hold survived")
				}
			}
		})
	}
}
