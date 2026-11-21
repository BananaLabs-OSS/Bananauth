package identity

import (
	"bytes"
	"context"
	"fmt"
	"github.com/bananalabs-oss/bananauth/internal/notification"
	"github.com/vmihailenco/msgpack/v5"
	"io"
	"strings"
	"unicode"
)

// These adapters retain the existing table-driven native owner test inputs.
// Serialization here is test fixture construction, never an application dispatch path.
type owner = Service
type accountErasureReferenceV1 = ErasureReference
type accountErasureLookupV1 = ErasureLookup

func decode(raw []byte, v any) error {
	if len(raw) == 0 {
		return fmt.Errorf("empty request")
	}
	return msgpack.Unmarshal(raw, v)
}
func encode(v any) ([]byte, error) { return msgpack.Marshal(v) }
func (o *Service) command(op, id string, request any, mutate func(*snapshot) (any, error)) ([]byte, error) {
	v, e := runCommand(o, op, id, request, mutate)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}

var _ = context.Background

func (o *Service) accountErasureGetV1(raw []byte) ([]byte, error) {
	if _, err := decodeErasureReferenceV1(raw); err != nil {
		return nil, err
	}
	var q ErasureReference
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.AccountErasureGetV1(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) accountGet(raw []byte) ([]byte, error) {
	var q AccountGetRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.AccountGet(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) nativeRegister(raw []byte) ([]byte, error) {
	var q NativeRegisterRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.NativeRegister(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) nativeAuthenticate(raw []byte) ([]byte, error) {
	var q NativeAuthenticateRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.NativeAuthenticate(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) nativeCredentialAttach(raw []byte) ([]byte, error) {
	var q NativeCredentialAttachRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.NativeCredentialAttach(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) passwordChange(raw []byte) ([]byte, error) {
	var q PasswordChangeRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.PasswordChange(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) passwordResetIssue(raw []byte) ([]byte, error) {
	var q PasswordResetIssueRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.PasswordResetIssue(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) passwordResetConsume(raw []byte) ([]byte, error) {
	var q PasswordResetConsumeRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.PasswordResetConsume(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) accountDelete(raw []byte) ([]byte, error) {
	var q AccountDeleteRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.AccountDelete(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) accountErase(raw []byte) ([]byte, error) {
	var q AccountEraseRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.AccountErase(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) retentionLeaseCreate(raw []byte) ([]byte, error) {
	var q RetentionLeaseCreateRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.RetentionLeaseCreate(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) retentionLeaseRenew(raw []byte) ([]byte, error) {
	var q RetentionLeaseRenewRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.RetentionLeaseRenew(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) retentionLeaseRelease(raw []byte) ([]byte, error) {
	var q RetentionLeaseReleaseRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.RetentionLeaseRelease(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) retentionLeaseList(raw []byte) ([]byte, error) {
	var q RetentionLeaseListRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.RetentionLeaseList(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) retentionEligibility(raw []byte) ([]byte, error) {
	var q RetentionEligibilityRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.RetentionEligibility(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) oauthStateIssue(raw []byte) ([]byte, error) {
	var q OAuthStateIssueRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.OauthStateIssue(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) oauthStateConsume(raw []byte) ([]byte, error) {
	var q OAuthStateConsumeRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.OauthStateConsume(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) oauthResolve(raw []byte) ([]byte, error) {
	var q OAuthResolveRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.OauthResolve(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) oauthUpsert(raw []byte) ([]byte, error) {
	var q OAuthUpsertRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.OauthUpsert(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) profileCreate(raw []byte) ([]byte, error) {
	var q ProfileCreateRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.ProfileCreate(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) profileGet(raw []byte) ([]byte, error) {
	var q ProfileGetRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.ProfileGet(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) profileUpdate(raw []byte) ([]byte, error) {
	var q ProfileUpdateRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.ProfileUpdate(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) rateCheck(raw []byte) ([]byte, error) {
	var q RateCheckRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.RateCheck(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) rateClear(raw []byte) ([]byte, error) {
	var q RateClearRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.RateClear(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) legacyImport(raw []byte) ([]byte, error) {
	var q LegacyImportRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.LegacyImport(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) effectsCheckDelivery(raw []byte) ([]byte, error) {
	var q notification.Lease
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.EffectsCheckDelivery(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) effectsClaim(raw []byte) ([]byte, error) {
	var q notification.ClaimRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.EffectsClaim(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) effectsAck(raw []byte) ([]byte, error) {
	var q notification.AcknowledgeRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.EffectsAck(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) effectsRetry(raw []byte) ([]byte, error) {
	var q notification.RetryRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.EffectsRetry(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) emailLoginIssueV2(raw []byte) ([]byte, error) {
	var q EmailVerificationIssueRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.EmailLoginIssueV2(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) emailSignupIssueV2(raw []byte) ([]byte, error) {
	var q EmailVerificationIssueRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.EmailSignupIssueV2(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) emailLoginConsumeV2(raw []byte) ([]byte, error) {
	var q EmailVerificationConsumeRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.EmailLoginConsumeV2(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) emailSignupConsumeV2(raw []byte) ([]byte, error) {
	var q EmailVerificationConsumeRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.EmailSignupConsumeV2(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) emailVerificationFactGetV2(raw []byte) ([]byte, error) {
	var q EmailVerificationFactRequestV2
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.EmailVerificationFactGetV2(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) retentionHoldAcquire(raw []byte) ([]byte, error) {
	if _, err := decodeRetentionHoldRequest(raw); err != nil {
		return msgpack.Marshal(failure[any]("invalid_request", err.Error()))
	}
	var q RetentionHoldRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.RetentionHoldAcquire(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) retentionHoldRelease(raw []byte) ([]byte, error) {
	if _, err := decodeRetentionHoldRequest(raw); err != nil {
		return msgpack.Marshal(failure[any]("invalid_request", err.Error()))
	}
	var q RetentionHoldRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.RetentionHoldRelease(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) observeConsumer(raw []byte) ([]byte, error) {
	var q notification.ObserveConsumerRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.ObserveConsumer(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
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
func decodeErasureReferenceV1(raw []byte) (accountErasureReferenceV1, error) {
	var q accountErasureReferenceV1
	if len(raw) == 0 || len(raw) > 2048 {
		return q, fmt.Errorf("bounded erasure reference required")
	}
	d := msgpack.NewDecoder(bytes.NewReader(raw))
	n, e := d.DecodeMapLen()
	if e != nil || n != 2 {
		return q, fmt.Errorf("exact erasure reference required")
	}
	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		k, e := d.DecodeString()
		if e != nil || seen[k] || (k != "operation" && k != "request_id") {
			return q, fmt.Errorf("closed erasure reference required")
		}
		seen[k] = true
		v, e := d.DecodeString()
		if e != nil {
			return q, fmt.Errorf("opaque reference strings required")
		}
		if k == "operation" {
			q.Operation = v
		} else {
			q.RequestID = v
		}
	}
	if _, e := d.PeekCode(); e != io.EOF {
		return q, fmt.Errorf("trailing erasure reference data")
	}
	if (q.Operation != FnAccountErase && q.Operation != FnAccountDelete) || q.RequestID == "" || len(q.RequestID) > 512 || strings.TrimSpace(q.RequestID) != q.RequestID || strings.ContainsAny(q.RequestID, "\r\n\x00") {
		return q, fmt.Errorf("closed erasure operation and request identity required")
	}
	return q, nil
}
