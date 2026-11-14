// Package effect retains the persisted notification outbox contract.
package effect

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/bananalabs-oss/bananauth/internal/msgpackframe"
	"github.com/vmihailenco/msgpack/v5"
)

// VersionV1 identifies the first host-effect envelope. Incompatible wire or
// semantic changes require a distinct version.
const VersionV1 = "pulp.effect.v1"

// Kind names the provider-neutral effect to be performed. Kinds are
// namespaced and versioned so a host cannot silently reinterpret persisted
// work after an application upgrade.
const (
	KindStripePaymentIntentCreate     = "pulp.effect.stripe.payment-intent.create.v1"
	KindStripePaymentIntentGet        = "pulp.effect.stripe.payment-intent.get.v1"
	KindStripePaymentIntentCapture    = "pulp.effect.stripe.payment-intent.capture.v1"
	KindStripePaymentIntentCancel     = "pulp.effect.stripe.payment-intent.cancel.v1"
	KindStripeCheckoutSessionCreate   = "pulp.effect.stripe.checkout-session.create.v1"
	KindStripeSetupIntentCreate       = "pulp.effect.stripe.setup-intent.create.v1"
	KindStripeSetupIntentGet          = "pulp.effect.stripe.setup-intent.get.v1"
	KindStripeRefundCreate            = "pulp.effect.stripe.refund.create.v1"
	KindStripeCustomerCreate          = "pulp.effect.stripe.customer.create.v1"
	KindStripeFreeInvoiceFinalize     = "pulp.effect.stripe.free-invoice.finalize.v1"
	KindStripeInvoiceItemCreate       = "pulp.effect.stripe.invoice-item.create.v1"
	KindStripeInvoiceCreate           = "pulp.effect.stripe.invoice.create.v1"
	KindStripeInvoiceFinalize         = "pulp.effect.stripe.invoice.finalize.v1"
	KindStripeInvoiceMarkPaid         = "pulp.effect.stripe.invoice.mark-paid.v1"
	KindStripeCouponUpsert            = "pulp.effect.stripe.coupon.upsert.v1"
	KindStripeCouponDelete            = "pulp.effect.stripe.coupon.delete.v1"
	KindStripePromotionCodeUpsert     = "pulp.effect.stripe.promotion-code.upsert.v1"
	KindStripePromotionCodeDeactivate = "pulp.effect.stripe.promotion-code.deactivate.v1"

	KindFleetServerProvision   = "pulp.effect.fleet.server.provision.v1"
	KindFleetServerReconfigure = "pulp.effect.fleet.server.reconfigure.v1"
	KindFleetServerSuspend     = "pulp.effect.fleet.server.suspend.v1"
	KindFleetServerResume      = "pulp.effect.fleet.server.resume.v1"
	KindFleetServerDeprovision = "pulp.effect.fleet.server.deprovision.v1"
	KindFleetExtensionApply    = "pulp.effect.fleet.extension.apply.v1"
	// KindFleetRuntimeObservationExecute permits one typed, bounded live
	// observation. It never carries an endpoint, command, path, or arbitrary
	// query surface.
	KindFleetRuntimeObservationExecute = "pulp.effect.fleet.runtime-observation.execute.v1"

	KindNotificationEmailSend = "pulp.effect.notification.email.send.v1"
	// KindServiceObservationExecute performs one authenticated, bounded read
	// selected by an opaque host-configured service definition ID. It exposes
	// no URL, credential, header or generic request surface.
	KindServiceObservationExecute = "pulp.effect.service.observation.execute.v1"
	// KindCapacityObservationExecute reads bounded provider-neutral node
	// capacity facts from one opaque host-configured destination.
	KindCapacityObservationExecute = "pulp.effect.capacity-observation.execute.v1"
	// KindStatusSignalPublish publishes one bounded health signal through a
	// host-owned status endpoint. The guest never controls a URL, header, or
	// transport credential.
	KindStatusSignalPublish = "pulp.effect.status.signal.publish.v1"
	// KindHTTPProbeExecute is the legacy Control-owned unauthenticated status
	// probe. Its URL is used only to derive a host-configured destination
	// allowlist key; the guest cannot instruct the host to fetch that URL.
	KindHTTPProbeExecute = "host.http.probe.v1"

	// KindStorageExactObjectHead reads the generation inventory for one exact,
	// application-owned object key. It is intentionally not a prefix/listing
	// operation: the state owner supplies the full key to inspect.
	KindStorageExactObjectHead = "pulp.effect.storage.exact-object.head.v1"
)

const maxFieldLength = 256

var ErrUnsupportedKind = errors.New("pulp effect: unsupported kind")

// Status is the durable processing status of one effect intent.
type Status string

const (
	Pending   Status = "pending"
	Completed Status = "completed"
	Failed    Status = "failed"
)

// Failure is a stable, intentionally non-secret failure surface returned to a
// state owner. Provider diagnostics must remain in host logs, never this wire.
type Failure struct {
	Code    string `msgpack:"code"`
	Message string `msgpack:"message"`
}

// Intent is a durable request to perform one privileged operation. ID and
// IdempotencyKey are owner-generated and must stay stable through retries.
// Payload is an embedded, raw MessagePack value owned by Kind.
type Intent struct {
	Version        string             `msgpack:"version"`
	ID             string             `msgpack:"id"`
	Kind           string             `msgpack:"kind"`
	IdempotencyKey string             `msgpack:"idempotency_key"`
	Payload        msgpack.RawMessage `msgpack:"payload"`
}

// Receipt is the host's result for an Intent. A state owner is responsible for
// durably storing it before advancing the owning workflow. Result is an
// embedded, raw MessagePack value owned by Kind.
type Receipt struct {
	Version        string             `msgpack:"version"`
	IntentID       string             `msgpack:"intent_id"`
	Kind           string             `msgpack:"kind"`
	IdempotencyKey string             `msgpack:"idempotency_key"`
	Status         Status             `msgpack:"status"`
	Result         msgpack.RawMessage `msgpack:"result,omitempty"`
	Failure        *Failure           `msgpack:"failure,omitempty"`
}

// NewIntent encodes a typed, kind-owned payload into a validated canonical
// host-effect intent.
func NewIntent[T any](id, kind, idempotencyKey string, payload T) (Intent, error) {
	encoded, err := msgpack.Marshal(payload)
	if err != nil {
		return Intent{}, fmt.Errorf("encode effect payload: %w", err)
	}
	canonicalKind, err := NormalizeKind(kind)
	if err != nil {
		return Intent{}, err
	}
	intent := Intent{
		Version: VersionV1, ID: id, Kind: canonicalKind,
		IdempotencyKey: idempotencyKey, Payload: encoded,
	}
	if err := intent.Validate(); err != nil {
		return Intent{}, err
	}
	return intent, nil
}

// DecodePayload decodes an intent's raw kind-owned MessagePack payload.
func DecodePayload[T any](intent Intent) (T, error) {
	var value T
	if err := intent.Validate(); err != nil {
		return value, err
	}
	if err := msgpack.Unmarshal(intent.Payload, &value); err != nil {
		return value, fmt.Errorf("decode effect payload: %w", err)
	}
	return value, nil
}

// NewPendingReceipt records work that was durably accepted but not completed.
func NewPendingReceipt(intent Intent) (Receipt, error) {
	receipt := receiptFor(intent, Pending)
	if err := receipt.ValidateFor(intent); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// NewCompletedReceipt records a typed host result for an intent.
func NewCompletedReceipt[T any](intent Intent, result T) (Receipt, error) {
	encoded, err := msgpack.Marshal(result)
	if err != nil {
		return Receipt{}, fmt.Errorf("encode effect result: %w", err)
	}
	receipt := receiptFor(intent, Completed)
	receipt.Result = encoded
	if err := receipt.ValidateFor(intent); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// NewFailedReceipt records a terminal, non-secret failure for an intent.
func NewFailedReceipt(intent Intent, failure Failure) (Receipt, error) {
	receipt := receiptFor(intent, Failed)
	receipt.Failure = &failure
	if err := receipt.ValidateFor(intent); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// DecodeResult decodes a completed receipt's raw kind-owned MessagePack
// result.
func DecodeResult[T any](receipt Receipt) (T, error) {
	var value T
	if receipt.Status != Completed {
		return value, fmt.Errorf("effect receipt is %q, not completed", receipt.Status)
	}
	if len(receipt.Result) == 0 {
		return value, errors.New("completed effect receipt has no result")
	}
	if err := msgpack.Unmarshal(receipt.Result, &value); err != nil {
		return value, fmt.Errorf("decode effect result: %w", err)
	}
	return value, nil
}

// MarshalIntent and UnmarshalIntent provide the canonical MessagePack wire
// boundary. UnmarshalIntent accepts supported legacy kind aliases and returns
// the canonical v1 name so persistence converges after a replay.
func MarshalIntent(intent Intent) ([]byte, error) {
	if err := intent.Validate(); err != nil {
		return nil, err
	}
	return msgpack.Marshal(intent)
}

func UnmarshalIntent(wire []byte) (Intent, error) {
	var intent Intent
	if err := msgpack.Unmarshal(wire, &intent); err != nil {
		return Intent{}, fmt.Errorf("decode effect intent: %w", err)
	}
	if err := intent.Normalize(); err != nil {
		return Intent{}, err
	}
	return intent, nil
}

// MarshalReceipt and UnmarshalReceipt provide the canonical receipt boundary.
func MarshalReceipt(receipt Receipt) ([]byte, error) {
	if err := receipt.Validate(); err != nil {
		return nil, err
	}
	return msgpack.Marshal(receipt)
}

func UnmarshalReceipt(wire []byte) (Receipt, error) {
	var receipt Receipt
	if err := msgpack.Unmarshal(wire, &receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode effect receipt: %w", err)
	}
	if err := receipt.Normalize(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// Normalize rewrites a supported legacy kind alias to its canonical v1 name.
func (i *Intent) Normalize() error {
	kind, err := NormalizeKind(i.Kind)
	if err != nil {
		return err
	}
	i.Kind = kind
	return i.Validate()
}

// Normalize rewrites a supported legacy kind alias to its canonical v1 name.
func (r *Receipt) Normalize() error {
	kind, err := NormalizeKind(r.Kind)
	if err != nil {
		return err
	}
	r.Kind = kind
	return r.Validate()
}

// Validate checks the canonical intent envelope. Call Normalize after decoding
// legacy persisted work; newly emitted intents must already be canonical.
func (i Intent) Validate() error {
	if i.Version != VersionV1 {
		return fmt.Errorf("unsupported effect version %q", i.Version)
	}
	if err := validateField("effect id", i.ID); err != nil {
		return err
	}
	if err := validateField("effect idempotency_key", i.IdempotencyKey); err != nil {
		return err
	}
	if !isCanonicalKind(i.Kind) {
		return fmt.Errorf("effect kind %q is not canonical", i.Kind)
	}
	if err := validateRaw("effect payload", i.Payload); err != nil {
		return err
	}
	return nil
}

// Validate checks receipt consistency without an Intent. ValidateFor also
// verifies that this receipt is bound to a particular intent.
func (r Receipt) Validate() error {
	if r.Version != VersionV1 {
		return fmt.Errorf("unsupported effect version %q", r.Version)
	}
	if err := validateField("effect receipt intent_id", r.IntentID); err != nil {
		return err
	}
	if err := validateField("effect receipt idempotency_key", r.IdempotencyKey); err != nil {
		return err
	}
	if !isCanonicalKind(r.Kind) {
		return fmt.Errorf("effect receipt kind %q is not canonical", r.Kind)
	}
	switch r.Status {
	case Pending:
		if len(r.Result) != 0 || r.Failure != nil {
			return errors.New("pending effect receipt must not contain a result or failure")
		}
	case Completed:
		if r.Failure != nil {
			return errors.New("completed effect receipt must not contain a failure")
		}
		if err := validateRaw("completed effect receipt result", r.Result); err != nil {
			return err
		}
	case Failed:
		if len(r.Result) != 0 {
			return errors.New("failed effect receipt must not contain a result")
		}
		if err := r.Failure.Validate(); err != nil {
			return fmt.Errorf("failed effect receipt: %w", err)
		}
	default:
		return fmt.Errorf("invalid effect receipt status %q", r.Status)
	}
	return nil
}

// ValidateFor proves that a receipt acknowledges this exact durable intent.
func (r Receipt) ValidateFor(intent Intent) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.IntentID != intent.ID || r.Kind != intent.Kind || r.IdempotencyKey != intent.IdempotencyKey {
		return errors.New("effect receipt does not match intent")
	}
	return nil
}

func (f *Failure) Validate() error {
	if f == nil {
		return errors.New("failure is required")
	}
	if err := validateField("effect failure code", f.Code); err != nil {
		return err
	}
	if strings.TrimSpace(f.Message) == "" {
		return errors.New("effect failure message is required")
	}
	return nil
}

// NormalizeKind maps the currently emitted unversioned and stripe-prefixed
// variants to their canonical v1 names. It never guesses unknown kinds.
func NormalizeKind(kind string) (string, error) {
	canonical, ok := kindAliases[kind]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnsupportedKind, kind)
	}
	return canonical, nil
}

func receiptFor(intent Intent, status Status) Receipt {
	return Receipt{
		Version: VersionV1, IntentID: intent.ID, Kind: intent.Kind,
		IdempotencyKey: intent.IdempotencyKey, Status: status,
	}
}

func validateField(label, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", label)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not have surrounding whitespace", label)
	}
	if len(value) > maxFieldLength {
		return fmt.Errorf("%s exceeds %d bytes", label, maxFieldLength)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	return nil
}

func validateRaw(label string, value msgpack.RawMessage) error {
	if len(value) == 0 {
		return fmt.Errorf("%s is required", label)
	}
	if err := msgpackframe.ValidateMessagePackFrame(value); err != nil {
		return fmt.Errorf("decode %s: %w", label, err)
	}
	return nil
}

func isCanonicalKind(kind string) bool {
	canonical, ok := kindAliases[kind]
	return ok && canonical == kind
}

var kindAliases = map[string]string{
	KindStripePaymentIntentCreate:      KindStripePaymentIntentCreate,
	"payment_intent.create":            KindStripePaymentIntentCreate,
	"stripe.payment_intent.create":     KindStripePaymentIntentCreate,
	"stripe.payment_intent.create.v1":  KindStripePaymentIntentCreate,
	"stripe.payment-intent.create":     KindStripePaymentIntentCreate,
	KindStripePaymentIntentGet:         KindStripePaymentIntentGet,
	"payment_intent.get":               KindStripePaymentIntentGet,
	"stripe.payment_intent.get":        KindStripePaymentIntentGet,
	"stripe.payment_intent.get.v1":     KindStripePaymentIntentGet,
	"stripe.payment-intent.get":        KindStripePaymentIntentGet,
	KindStripePaymentIntentCapture:     KindStripePaymentIntentCapture,
	"payment_intent.capture":           KindStripePaymentIntentCapture,
	"stripe.payment_intent.capture":    KindStripePaymentIntentCapture,
	"stripe.payment_intent.capture.v1": KindStripePaymentIntentCapture,
	"stripe.payment-intent.capture":    KindStripePaymentIntentCapture,
	KindStripePaymentIntentCancel:      KindStripePaymentIntentCancel,
	"payment_intent.cancel":            KindStripePaymentIntentCancel,
	"stripe.payment_intent.cancel":     KindStripePaymentIntentCancel,
	"stripe.payment_intent.cancel.v1":  KindStripePaymentIntentCancel,
	"stripe.payment-intent.cancel":     KindStripePaymentIntentCancel,

	KindStripeCheckoutSessionCreate:     KindStripeCheckoutSessionCreate,
	"checkout_session.create":           KindStripeCheckoutSessionCreate,
	"stripe.checkout_session.create":    KindStripeCheckoutSessionCreate,
	"stripe.checkout_session.create.v1": KindStripeCheckoutSessionCreate,
	"stripe.checkout-session.create":    KindStripeCheckoutSessionCreate,

	KindStripeSetupIntentCreate:     KindStripeSetupIntentCreate,
	"setup_intent.create":           KindStripeSetupIntentCreate,
	"stripe.setup_intent.create":    KindStripeSetupIntentCreate,
	"stripe.setup_intent.create.v1": KindStripeSetupIntentCreate,
	"stripe.setup-intent.create":    KindStripeSetupIntentCreate,
	KindStripeSetupIntentGet:        KindStripeSetupIntentGet,
	"setup_intent.get":              KindStripeSetupIntentGet,
	"stripe.setup_intent.get":       KindStripeSetupIntentGet,
	"stripe.setup_intent.get.v1":    KindStripeSetupIntentGet,
	"stripe.setup-intent.get":       KindStripeSetupIntentGet,

	KindStripeRefundCreate:    KindStripeRefundCreate,
	"refund.create":           KindStripeRefundCreate,
	"stripe.refund":           KindStripeRefundCreate,
	"stripe.refund.create":    KindStripeRefundCreate,
	"stripe.refund.create.v1": KindStripeRefundCreate,

	KindStripeCustomerCreate:          KindStripeCustomerCreate,
	"customer.create":                 KindStripeCustomerCreate,
	"stripe.customer.create":          KindStripeCustomerCreate,
	"stripe.customer.create.v1":       KindStripeCustomerCreate,
	KindStripeFreeInvoiceFinalize:     KindStripeFreeInvoiceFinalize,
	"free_invoice.finalize":           KindStripeFreeInvoiceFinalize,
	"stripe.free_invoice.finalize":    KindStripeFreeInvoiceFinalize,
	"stripe.free_invoice.finalize.v1": KindStripeFreeInvoiceFinalize,
	"stripe.free-invoice.finalize":    KindStripeFreeInvoiceFinalize,
	KindStripeInvoiceItemCreate:       KindStripeInvoiceItemCreate,
	"invoice_item.create":             KindStripeInvoiceItemCreate,
	"stripe.invoice_item.create":      KindStripeInvoiceItemCreate,
	"stripe.invoice_item.create.v1":   KindStripeInvoiceItemCreate,
	"stripe.invoice-item.create":      KindStripeInvoiceItemCreate,
	KindStripeInvoiceCreate:           KindStripeInvoiceCreate,
	"invoice.create":                  KindStripeInvoiceCreate,
	"stripe.invoice.create":           KindStripeInvoiceCreate,
	"stripe.invoice.create.v1":        KindStripeInvoiceCreate,
	KindStripeInvoiceFinalize:         KindStripeInvoiceFinalize,
	"invoice.finalize":                KindStripeInvoiceFinalize,
	"stripe.invoice.finalize":         KindStripeInvoiceFinalize,
	"stripe.invoice.finalize.v1":      KindStripeInvoiceFinalize,
	KindStripeInvoiceMarkPaid:         KindStripeInvoiceMarkPaid,
	"invoice.mark_paid":               KindStripeInvoiceMarkPaid,
	"stripe.invoice.mark_paid":        KindStripeInvoiceMarkPaid,
	"stripe.invoice.mark_paid.v1":     KindStripeInvoiceMarkPaid,
	"stripe.invoice.mark-paid":        KindStripeInvoiceMarkPaid,

	KindStripeCouponUpsert:                KindStripeCouponUpsert,
	"coupon.upsert":                       KindStripeCouponUpsert,
	"stripe.coupon.upsert":                KindStripeCouponUpsert,
	"stripe.coupon.upsert.v1":             KindStripeCouponUpsert,
	"coupon.create":                       KindStripeCouponUpsert,
	"stripe.coupon.create":                KindStripeCouponUpsert,
	KindStripeCouponDelete:                KindStripeCouponDelete,
	"coupon.delete":                       KindStripeCouponDelete,
	"stripe.coupon.delete":                KindStripeCouponDelete,
	"stripe.coupon.delete.v1":             KindStripeCouponDelete,
	KindStripePromotionCodeUpsert:         KindStripePromotionCodeUpsert,
	"promotion_code.upsert":               KindStripePromotionCodeUpsert,
	"stripe.promotion_code.upsert":        KindStripePromotionCodeUpsert,
	"stripe.promotion_code.upsert.v1":     KindStripePromotionCodeUpsert,
	"promotion_code.create":               KindStripePromotionCodeUpsert,
	"stripe.promotion_code.create":        KindStripePromotionCodeUpsert,
	KindStripePromotionCodeDeactivate:     KindStripePromotionCodeDeactivate,
	"promotion_code.deactivate":           KindStripePromotionCodeDeactivate,
	"stripe.promotion_code.deactivate":    KindStripePromotionCodeDeactivate,
	"stripe.promotion_code.deactivate.v1": KindStripePromotionCodeDeactivate,

	KindFleetServerProvision:           KindFleetServerProvision,
	"fleet.provision":                  KindFleetServerProvision,
	"fleet.provision.request":          KindFleetServerProvision,
	KindFleetServerReconfigure:         KindFleetServerReconfigure,
	"fleet.reconfigure":                KindFleetServerReconfigure,
	"fleet.reconfigure.request":        KindFleetServerReconfigure,
	KindFleetServerSuspend:             KindFleetServerSuspend,
	"fleet.suspend":                    KindFleetServerSuspend,
	KindFleetServerResume:              KindFleetServerResume,
	"fleet.resume":                     KindFleetServerResume,
	KindFleetServerDeprovision:         KindFleetServerDeprovision,
	"fleet.deprovision":                KindFleetServerDeprovision,
	"fleet.deprovision.request":        KindFleetServerDeprovision,
	KindFleetExtensionApply:            KindFleetExtensionApply,
	"fleet.extension.apply.v1":         KindFleetExtensionApply,
	KindFleetRuntimeObservationExecute: KindFleetRuntimeObservationExecute,

	KindNotificationEmailSend: KindNotificationEmailSend,
	"workers.email.send":      KindNotificationEmailSend,

	KindServiceObservationExecute:  KindServiceObservationExecute,
	KindCapacityObservationExecute: KindCapacityObservationExecute,

	KindStatusSignalPublish: KindStatusSignalPublish,

	KindHTTPProbeExecute: KindHTTPProbeExecute,

	KindStorageExactObjectHead: KindStorageExactObjectHead,
}
