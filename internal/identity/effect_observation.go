package identity

import (
	"fmt"
	"github.com/bananalabs-oss/bananauth/internal/effect"
	"time"
)

func (o *owner) observeConsumer(input []byte) ([]byte, error) {
	var req effect.ObserveConsumerRequest
	if err := decode(input, &req); err != nil {
		return nil, err
	}
	if err := req.Validate(); err != nil || req.Owner != effectOwner {
		return nil, fmt.Errorf("invalid auth identity observation")
	}
	return o.query(func(s snapshot) (any, error) {
		v := effect.ConsumerObservation{Version: effect.OutboxVersionV1, Owner: effectOwner, AtMillis: time.Now().UnixMilli()}
		for _, record := range s.Effects {
			if record.Status == string(effect.Pending) && record.Lease != nil && record.Lease.ConsumerID == req.ConsumerID {
				v.Leased++
				if record.Lease.LeasedUntilUnixMilli <= v.AtMillis {
					v.Overdue++
				}
			}
		}
		return v, nil
	})
}
