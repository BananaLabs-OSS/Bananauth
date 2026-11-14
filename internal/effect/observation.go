package effect

import (
	"errors"
	"strings"
)

const FnObserveConsumer = "pulp.effects.observe-consumer.v1"

type ObserveConsumerRequest struct {
	Version    string `msgpack:"version"`
	Owner      string `msgpack:"owner"`
	ConsumerID string `msgpack:"consumer_id"`
}

func (r ObserveConsumerRequest) Validate() error {
	if r.Version != OutboxVersionV1 || strings.TrimSpace(r.Owner) == "" || strings.TrimSpace(r.ConsumerID) == "" || len(r.ConsumerID) > 256 {
		return errors.New("invalid effect observation")
	}
	return nil
}

// ConsumerObservation includes expired leases until settled/reclaimed. It never
// contains intent bodies, consumer identifiers or delivery credentials.
type ConsumerObservation struct {
	Version  string `msgpack:"version"`
	Owner    string `msgpack:"owner"`
	AtMillis int64  `msgpack:"at_ms"`
	Leased   int64  `msgpack:"leased"`
	Overdue  int64  `msgpack:"overdue"`
}
