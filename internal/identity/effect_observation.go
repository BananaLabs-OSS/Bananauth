package identity

import (
	"fmt"
	"github.com/bananalabs-oss/bananauth/internal/notification"
	"time"
)

func (o *Service) ObserveConsumer(req notification.ObserveConsumerRequest) (Result[notification.ConsumerObservation], error) {
	if err := req.Validate(); err != nil {
		return Result[notification.ConsumerObservation]{}, fmt.Errorf("invalid auth identity observation")
	}
	return runQuery[notification.ConsumerObservation](o, func(s snapshot) (notification.ConsumerObservation, error) {
		v := notification.ConsumerObservation{AtMillis: time.Now().UnixMilli()}
		for _, record := range s.Effects {
			if record.Status == string(notification.Pending) && record.Lease != nil && record.Lease.ConsumerID == req.ConsumerID {
				v.Leased++
				if record.Lease.LeasedUntilUnixMilli <= v.AtMillis {
					v.Overdue++
				}
			}
		}
		return v, nil
	})
}
