package identity

import (
	"github.com/bananalabs-oss/bananauth/internal/notification"
	"testing"
)

func TestObserveDurableAuthLeasesAcrossRestart(t *testing.T) {
	snap := newSnapshot()
	snap.Effects["one"] = ownerEffect{Status: string(notification.Pending), Lease: &notification.Lease{ConsumerID: "worker", LeasedUntilUnixMilli: 1}}
	store := &memoryEventStore{records: []durableRecord{{Snapshot: snap}}}
	for i := 0; i < 2; i++ {
		o := newTestOwner(t, store)
		req := notification.ObserveConsumerRequest{ConsumerID: "worker"}
		v := callResult[notification.ConsumerObservation](t, o.observeConsumer, req)
		if !v.OK || v.Value.Leased != 1 || v.Value.Overdue != 1 {
			t.Fatalf("%+v", v)
		}
		req.ConsumerID = "other"
		v = callResult[notification.ConsumerObservation](t, o.observeConsumer, req)
		if !v.OK || v.Value.Leased != 0 {
			t.Fatal("consumer isolation failed")
		}
	}
	if len(store.records) != 1 {
		t.Fatal("observation wrote a command")
	}
}
