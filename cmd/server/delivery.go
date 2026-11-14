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

	"github.com/bananalabs-oss/bananauth/internal/effect"
	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"
)

var errInvalidNotification = errors.New("notification payload is invalid or expired")

type deliveryWorker struct {
	commands                         map[string]func([]byte) ([]byte, error)
	keys                             otpsecure.Keyring
	client                           *http.Client
	testRecipients                   map[string]bool
	endpoint, apiKey, from, consumer string
}

func newDeliveryWorker(commands map[string]func([]byte) ([]byte, error), keys otpsecure.Keyring, apiKey, from string) *deliveryWorker {
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

func (d *deliveryWorker) command(name string, request, response any) error {
	wire, err := msgpack.Marshal(request)
	if err != nil {
		return err
	}
	execute := d.commands[name]
	if execute == nil {
		return errors.New("outbox command is unavailable")
	}
	raw, err := execute(wire)
	if err != nil {
		return err
	}
	return msgpack.Unmarshal(raw, response)
}

func (d *deliveryWorker) drain(ctx context.Context) error {
	claim, err := effect.NewClaimRequest("auth-identity", d.consumer, 1, (30 * time.Second).Milliseconds())
	if err != nil {
		return err
	}
	var result effect.ClaimResult
	if err := d.command(identity.FnEffectsClaim, claim, &result); err != nil {
		return err
	}
	if result.Validate() != nil || result.Owner != claim.Owner || result.ConsumerID != claim.ConsumerID || len(result.Leases) > 1 {
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
	var settled effect.SettlementResult
	if err != nil && !errors.Is(err, errInvalidNotification) {
		retry := effect.RetryRequest{
			Version: effect.OutboxVersionV1, Owner: lease.Owner, ConsumerID: lease.ConsumerID, LeaseID: lease.LeaseID,
			Failure:          effect.Failure{Code: "notification_delivery_failed", Message: "notification delivery failed"},
			RetryAtUnixMilli: time.Now().Add(30 * time.Second).UnixMilli(),
		}
		if err := d.command(identity.FnEffectsRetry, retry, &settled); err != nil {
			return err
		}
	} else {
		var receipt effect.Receipt
		if errors.Is(err, errInvalidNotification) {
			receipt, err = effect.NewFailedReceipt(lease.Intent, effect.Failure{
				Code: "invalid_notification_payload", Message: errInvalidNotification.Error(),
			})
		} else {
			receipt, err = effect.NewCompletedReceipt(lease.Intent, struct {
				Provider  string `msgpack:"provider"`
				MessageID string `msgpack:"message_id"`
			}{Provider: "resend", MessageID: messageID})
		}
		if err != nil {
			return err
		}
		ack := effect.AcknowledgeRequest{
			Version: effect.OutboxVersionV1, Owner: lease.Owner, ConsumerID: lease.ConsumerID, LeaseID: lease.LeaseID, Receipt: receipt,
		}
		if err := d.command(identity.FnEffectsAck, ack, &settled); err != nil {
			return err
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

func (d *deliveryWorker) deliver(ctx context.Context, lease effect.Lease) (string, error) {
	intent := lease.Intent
	if intent.Kind != effect.KindNotificationEmailSend {
		return "", errInvalidNotification
	}
	var encrypted []byte
	if err := msgpack.Unmarshal(intent.Payload, &encrypted); err != nil {
		return "", errInvalidNotification
	}
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
	body, err := json.Marshal(map[string]any{"from": d.from, "to": []string{message.To}, "subject": message.Subject, "text": message.Text})
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
	var allowed identity.Result[bool]
	if err := d.command(identity.FnEffectsCheckDelivery, lease, &allowed); err != nil || !allowed.OK {
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
