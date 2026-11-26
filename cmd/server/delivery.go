package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/notification"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"
)

var errInvalidNotification = errors.New("notification payload is invalid or expired")

type deliveryWorker struct {
	commands                         notificationOutbox
	keys                             otpsecure.Keyring
	client                           *http.Client
	testRecipients                   map[string]bool
	endpoint, apiKey, from, consumer string
}

func newDeliveryWorker(commands notificationOutbox, keys otpsecure.Keyring, apiKey, from string) *deliveryWorker {
	return &deliveryWorker{
		commands: commands, keys: keys, endpoint: "https://api.resend.com/emails", apiKey: apiKey, from: from,
		consumer: "bananauth-email:" + uuid.NewString(),
		client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
}

func mailbox(value string) (string, bool) {
	address, err := mail.ParseAddress(value)
	if err != nil || address.Name != "" || address.Address != value || strings.ContainsAny(value, "\r\n") {
		return "", false
	}
	return strings.ToLower(value), true
}

func parseTestRecipients(list, required string) (map[string]bool, error) {
	if required != "" && required != "true" && required != "false" {
		return nil, errors.New("invalid verification recipient requirement")
	}
	if list == "" {
		if required == "true" {
			return nil, errors.New("required verification recipient restriction is empty")
		}
		return nil, nil
	}
	allowed := make(map[string]bool)
	for _, entry := range strings.Split(list, ",") {
		address, ok := mailbox(strings.TrimSpace(entry))
		if !ok || allowed[address] {
			return nil, errors.New("invalid or duplicate verification recipient")
		}
		allowed[address] = true
	}
	return allowed, nil
}

func (d *deliveryWorker) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := d.drain(ctx); err != nil && ctx.Err() == nil {
				log.Printf("email outbox: %v", err)
			}
			timer.Reset(time.Second)
		}
	}
}

func (d *deliveryWorker) drain(ctx context.Context) error {
	if d.commands == nil {
		return errors.New("notification outbox unavailable")
	}
	claim, err := notification.NewClaimRequest(d.consumer, 1, (30 * time.Second).Milliseconds())
	if err != nil {
		return err
	}
	result, err := d.commands.EffectsClaim(claim)
	if err != nil {
		return err
	}
	if result.Validate() != nil || result.ConsumerID != claim.ConsumerID || len(result.Leases) > 1 {
		return errors.New("invalid email outbox claim")
	}
	if len(result.Leases) == 0 {
		return nil
	}
	lease := result.Leases[0]
	deadline := time.UnixMilli(lease.LeasedUntilUnixMilli).Add(-500 * time.Millisecond)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	messageID, err := d.deliver(ctx, lease)
	var settled notification.SettlementResult
	var settleErr error
	if err != nil && !errors.Is(err, errInvalidNotification) {
		retry := notification.RetryRequest{
			ConsumerID: lease.ConsumerID, LeaseID: lease.LeaseID,
			Failure:          notification.Failure{Code: "notification_delivery_failed", Message: "notification delivery failed"},
			RetryAtUnixMilli: time.Now().Add(30 * time.Second).UnixMilli(),
		}
		settled, settleErr = d.commands.EffectsRetry(retry)
		if settleErr != nil {
			return settleErr
		}
	} else {
		var receipt notification.Receipt
		if errors.Is(err, errInvalidNotification) {
			receipt, err = notification.NewFailedReceipt(lease.Message, notification.Failure{
				Code: "invalid_notification_payload", Message: errInvalidNotification.Error(),
			})
		} else {
			receipt, err = notification.NewCompletedReceipt(lease.Message, messageID)
		}
		if err != nil {
			return err
		}
		ack := notification.AcknowledgeRequest{
			ConsumerID: lease.ConsumerID, LeaseID: lease.LeaseID, Receipt: receipt,
		}
		settled, settleErr = d.commands.EffectsAck(ack)
		if settleErr != nil {
			return settleErr
		}
	}
	if err := settled.ValidateFor(lease); err != nil {
		return err
	}
	if !settled.Settled {
		return errors.New("email outbox lease was lost")
	}
	return nil
}

func (d *deliveryWorker) deliver(ctx context.Context, lease notification.Lease) (string, error) {
	intent := lease.Message
	encrypted := intent.Ciphertext
	raw, envelope, err := d.keys.Open(intent.ID, encrypted)
	if err != nil || envelope.ExpiresAt <= time.Now().UnixMilli() {
		return "", errInvalidNotification
	}
	var message struct {
		To      string `msgpack:"to"`
		Subject string `msgpack:"subject"`
		Text    string `msgpack:"text"`
	}
	if msgpack.Unmarshal(raw, &message) != nil || message.To == "" || message.Subject == "" || message.Text == "" ||
		!strings.EqualFold(strings.TrimSpace(envelope.Recipient), strings.TrimSpace(message.To)) {
		return "", errInvalidNotification
	}
	recipient, valid := mailbox(message.To)
	if !valid {
		return "", errInvalidNotification
	}
	if d.testRecipients != nil && !d.testRecipients[recipient] {
		return "", errors.New("notification held by verification recipient restriction")
	}
	payload := map[string]any{"from": d.from, "to": []string{message.To}, "subject": message.Subject, "text": message.Text}
	if markup := sessionsVerificationHTML(message.Subject, message.Text); markup != "" {
		payload["html"] = markup
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+d.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", intent.IdempotencyKey)
	if d.commands == nil {
		return "", errors.New("notification delivery authorization unavailable")
	}
	allowed, err := d.commands.EffectsCheckDelivery(lease)
	if err != nil || !allowed.OK {
		return "", errors.New("notification delivery authorization unavailable")
	}
	if !allowed.Value {
		return "", errInvalidNotification
	}
	response, err := d.client.Do(req)
	if err != nil {
		return "", errors.New("notification provider unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", errors.New("notification provider rejected request")
	}
	var result struct {
		ID string `json:"id"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&result) != nil || result.ID == "" {
		return "", errors.New("invalid notification provider response")
	}
	return result.ID, nil
}

// notificationOutbox is the delivery worker's bounded durable authority.
type notificationOutbox interface {
	EffectsClaim(notification.ClaimRequest) (notification.ClaimResult, error)
	EffectsAck(notification.AcknowledgeRequest) (notification.SettlementResult, error)
	EffectsRetry(notification.RetryRequest) (notification.SettlementResult, error)
	EffectsCheckDelivery(notification.Lease) (identity.Result[bool], error)
}
