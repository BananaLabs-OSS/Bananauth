package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"net/mail"
	"strings"

	"github.com/bananalabs-oss/bananauth/internal/notification"
	"github.com/bananalabs-oss/bananauth/pkg/otpscope"
	"github.com/vmihailenco/msgpack/v5"
)

// Separate capabilities preserve V1 consumers. Purpose is selected by the
// selected typed operation, never by a request's claimed purpose/template/account flag.
const (
	FnEmailLoginIssueV2    = "auth.identity.v2.email-login.issue"
	FnEmailSignupIssueV2   = "auth.identity.v2.email-signup.issue"
	FnEmailLoginConsumeV2  = "auth.identity.v2.email-login.consume"
	FnEmailSignupConsumeV2 = "auth.identity.v2.email-signup.consume"
)

type EmailVerificationFactRequestV2 struct {
	EffectID string `msgpack:"effect_id" json:"effect_id"`
	Email    string `msgpack:"email" json:"email"`
	Now      int64  `msgpack:"now" json:"now"`
}

// Issuance facts prove this exact OTP only, never general mail permission or
// universal account email verification. No code, ciphertext or bearer is exposed.
type EmailVerificationFactV2 struct {
	MessageIdempotencyKey  string `msgpack:"message_idempotency_key" json:"message_idempotency_key"`
	EncryptedPayloadSHA256 string `msgpack:"encrypted_payload_sha256" json:"encrypted_payload_sha256"`
	EffectID               string `msgpack:"effect_id" json:"effect_id"`
	VerificationID         string `msgpack:"verification_id" json:"verification_id"`
	IssuanceRequestID      string `msgpack:"issuance_request_id" json:"issuance_request_id"`
	Recipient              string `msgpack:"recipient" json:"recipient"`
	Purpose                string `msgpack:"purpose" json:"purpose"`
	IssuedAt               int64  `msgpack:"issued_at_unix_milli" json:"issued_at_unix_milli"`
	ExpiresAt              int64  `msgpack:"expires_at_unix_milli" json:"expires_at_unix_milli"`
	AccountID              string `msgpack:"account_id,omitempty" json:"account_id,omitempty"`
	Active                 bool   `msgpack:"active" json:"active"`
}
type emailVerificationStateV2 struct {
	Fact       EmailVerificationFactV2 `msgpack:"fact" json:"fact"`
	ConsumedAt int64                   `msgpack:"consumed_at,omitempty" json:"consumed_at,omitempty"`
}

func strictAccountForEmailV2(s *snapshot, email string) (string, error) {
	id := ""
	for key, account := range s.Accounts {
		if otpscope.NormalizeEmail(account.Email) == email {
			if id != "" {
				return "", domain("conflict", "account email is ambiguous")
			}
			id = key
		}
	}
	return id, nil
}
func verificationTypeV2(purpose string) string { return "sessions_email_" + purpose + "_v2" }
func (o *Service) EmailLoginIssueV2(req EmailVerificationIssueRequest) (Result[EmailVerificationIssueResult], error) {
	return o.emailIssueV2(req, "login", FnEmailLoginIssueV2)
}
func (o *Service) EmailSignupIssueV2(req EmailVerificationIssueRequest) (Result[EmailVerificationIssueResult], error) {
	return o.emailIssueV2(req, "signup", FnEmailSignupIssueV2)
}
func (o *Service) emailIssueV2(req EmailVerificationIssueRequest, purpose, operation string) (Result[EmailVerificationIssueResult], error) {
	req.Email = otpscope.NormalizeEmail(req.Email)
	req.CallerKey = strings.TrimSpace(req.CallerKey)
	req.Code = strings.ToUpper(strings.TrimSpace(req.Code))
	return runCommand[EmailVerificationIssueResult](o, operation, req.RequestID, req, func(s *snapshot) (EmailVerificationIssueResult, error) {
		addr, err := mail.ParseAddress(req.Email)
		if err != nil || addr.Address != req.Email || blank(req.VerificationID) || blank(req.EffectID) || len(req.Code) != 6 || req.Now <= 0 || req.ExpiresAt <= req.Now || req.ExpiresAt-req.Now > emailVerificationWindowMillis {
			return zeroValue[EmailVerificationIssueResult](), domain("invalid_request", "verification issue is incomplete")
		}
		accountID, err := strictAccountForEmailV2(s, req.Email)
		if err != nil {
			return zeroValue[EmailVerificationIssueResult](), err
		}
		// An ordinary login must never silently create signup state; an existing
		// account's signup request also returns the same accepted/no-delivery shape.
		if (purpose == "login" && accountID == "") || (purpose == "signup" && accountID != "") {
			return EmailVerificationIssueResult{Accepted: true}, nil
		}
		pruneExpiredVerificationState(s, req.Now)
		if _, ok := s.OTPs[req.VerificationID]; ok {
			return zeroValue[EmailVerificationIssueResult](), domain("idempotency_conflict", "verification id already exists")
		}
		if _, ok := s.Effects[req.EffectID]; ok {
			return zeroValue[EmailVerificationIssueResult](), domain("idempotency_conflict", "effect id already exists")
		}
		if _, ok := s.VerificationFactsV2[req.EffectID]; ok {
			return zeroValue[EmailVerificationIssueResult](), domain("idempotency_conflict", "issuance fact already exists")
		}
		callerAllowed := true
		if req.CallerKey != "" {
			d := sha256.Sum256([]byte("bananauth:verification-caller:v1\x00" + req.CallerKey))
			callerAllowed = consumeIssueRate(s, rateKey("email_verification_issue_caller", hex.EncodeToString(d[:])), req.Now, emailVerificationCallerMax)
		}
		if !consumeIssueRate(s, rateKey("email_verification_issue_recipient", req.Email), req.Now, emailVerificationRecipientMax) || !callerAllowed {
			return EmailVerificationIssueResult{Accepted: true}, nil
		}
		outstanding := 0
		for _, otp := range s.OTPs {
			if otp.Email == req.Email && (otp.Type == "sessions_email_verification" || otp.Type == verificationTypeV2("login") || otp.Type == verificationTypeV2("signup")) {
				outstanding++
			}
		}
		if outstanding >= emailVerificationOutstanding {
			return EmailVerificationIssueResult{Accepted: true}, nil
		}
		kind := verificationTypeV2(purpose)
		s.OTPs[req.VerificationID] = otpRecord{ID: req.VerificationID, Email: req.Email, CodeHash: o.otpKeys.CodeMAC(req.VerificationID, req.Email, req.Code, kind), Type: kind, ExpiresAt: req.ExpiresAt, AccountID: accountID}
		intent, err := o.notificationIntent(req.EffectID, req.Email, "Your Sessions verification code", "Your verification code: "+req.Code+"\nExpires in 10 minutes.", req.ExpiresAt)
		if err != nil {
			return zeroValue[EmailVerificationIssueResult](), err
		}
		s.Effects[intent.ID] = ownerEffect{Message: intent, Status: string(notification.Pending), AvailableAt: req.Now, ExpiresAt: req.ExpiresAt}
		s.VerificationFactsV2[req.EffectID] = emailVerificationStateV2{Fact: EmailVerificationFactV2{MessageIdempotencyKey: intent.IdempotencyKey, EncryptedPayloadSHA256: encryptedIntentSHA256V2(intent), EffectID: req.EffectID, VerificationID: req.VerificationID, IssuanceRequestID: req.RequestID, Recipient: req.Email, Purpose: purpose, IssuedAt: req.Now, ExpiresAt: req.ExpiresAt, AccountID: accountID}}
		return EmailVerificationIssueResult{Accepted: true, EffectQueued: true}, nil
	})
}
func (o *Service) EmailLoginConsumeV2(req EmailVerificationConsumeRequest) (Result[EmailVerificationConsumeResult], error) {
	return o.emailConsumeV2(req, "login", FnEmailLoginConsumeV2)
}
func (o *Service) EmailSignupConsumeV2(req EmailVerificationConsumeRequest) (Result[EmailVerificationConsumeResult], error) {
	return o.emailConsumeV2(req, "signup", FnEmailSignupConsumeV2)
}
func (o *Service) emailConsumeV2(req EmailVerificationConsumeRequest, purpose, operation string) (Result[EmailVerificationConsumeResult], error) {
	req.Email = otpscope.NormalizeEmail(req.Email)
	req.Code = strings.ToUpper(strings.TrimSpace(req.Code))
	identity := req
	identity.Now = 0
	return runCommand[EmailVerificationConsumeResult](o, operation, req.RequestID, identity, func(s *snapshot) (EmailVerificationConsumeResult, error) {
		if req.Now <= 0 {
			return zeroValue[EmailVerificationConsumeResult](), domain("invalid_request", "trusted current time is required")
		}
		pruneExpiredVerificationState(s, req.Now)
		for _, otp := range s.OTPs {
			if otp.Email != req.Email || otp.Type != verificationTypeV2(purpose) || otp.ExpiresAt <= req.Now || !o.otpMatches(otp, req.Code) {
				continue
			}
			hasFact := false
			for _, record := range s.VerificationFactsV2 {
				fact := record.Fact
				original, originalExists := s.Effects[fact.EffectID]
				if originalExists && factIntentMatchesV2(fact, original) && fact.VerificationID == otp.ID && fact.Recipient == req.Email && fact.Purpose == purpose && record.ConsumedAt == 0 && fact.IssuedAt <= req.Now && fact.ExpiresAt == otp.ExpiresAt {
					hasFact = true
					break
				}
			}
			if !hasFact {
				return zeroValue[EmailVerificationConsumeResult](), domain("invalid_code", "issued purpose fact missing")
			}
			// Resolve the current account again; stale/deleted/ambiguous login members
			// cannot borrow a prior issuance, and signup can never overwrite an ID.
			accountID, err := strictAccountForEmailV2(s, req.Email)
			if err != nil {
				return zeroValue[EmailVerificationConsumeResult](), err
			}
			if purpose == "login" && (accountID == "" || accountID != otp.AccountID) {
				return zeroValue[EmailVerificationConsumeResult](), domain("invalid_code", "account binding changed")
			}
			if accountID == "" {
				if blank(req.AccountID) {
					return zeroValue[EmailVerificationConsumeResult](), domain("invalid_request", "new account id required")
				}
				if _, exists := s.Accounts[req.AccountID]; exists {
					return zeroValue[EmailVerificationConsumeResult](), domain("idempotency_conflict", "new account id occupied")
				}
				accountID = req.AccountID
				s.Accounts[accountID] = AccountProjection{AccountID: accountID, Email: req.Email, CreatedAt: req.Now}
			}
			for id, candidate := range s.OTPs {
				if candidate.Email == req.Email && (candidate.Type == verificationTypeV2("login") || candidate.Type == verificationTypeV2("signup")) {
					delete(s.OTPs, id)
				}
			}
			for id, fact := range s.VerificationFactsV2 {
				if fact.Fact.Recipient == req.Email {
					fact.ConsumedAt = req.Now
					s.VerificationFactsV2[id] = fact
				}
			}
			return EmailVerificationConsumeResult{Verified: true, AccountID: accountID, VerifiedEmail: req.Email, EmailVerifiedAtUnixMilli: req.Now, EmailVerificationExpiresAtUnixMilli: otp.ExpiresAt, VerificationRequestID: req.RequestID}, nil
		}
		return zeroValue[EmailVerificationConsumeResult](), domain("invalid_code", "invalid or expired verification code")
	})
}
func (o *Service) EmailVerificationFactGetV2(req EmailVerificationFactRequestV2) (Result[EmailVerificationFactV2], error) {
	req.Email = otpscope.NormalizeEmail(req.Email)
	return runQuery[EmailVerificationFactV2](o, func(s snapshot) (EmailVerificationFactV2, error) {
		record, ok := s.VerificationFactsV2[req.EffectID]
		if !ok || record.Fact.Recipient != req.Email || req.Now <= 0 {
			return zeroValue[EmailVerificationFactV2](), domain("not_found", "issued verification fact not found")
		}
		fact := record.Fact
		pending, hasEffect := s.Effects[fact.EffectID]
		if hasEffect {
			active, err := verificationDeliveryActive(&s, record, pending, req.Now)
			if err != nil {
				return zeroValue[EmailVerificationFactV2](), err
			}
			fact.Active = active
		}
		return fact, nil
	})
}

func verificationDeliveryActive(s *snapshot, record emailVerificationStateV2, pending ownerEffect, now int64) (bool, error) {
	fact := record.Fact
	otp, hasOTP := s.OTPs[fact.VerificationID]
	if (fact.Purpose != "login" && fact.Purpose != "signup") || record.ConsumedAt != 0 ||
		now < fact.IssuedAt || now >= fact.ExpiresAt || !hasOTP || otp.ID != fact.VerificationID ||
		otp.ExpiresAt != fact.ExpiresAt || otp.Email != fact.Recipient || otp.Type != verificationTypeV2(fact.Purpose) ||
		!factIntentMatchesV2(fact, pending) || pending.Status != string(notification.Pending) {
		return false, nil
	}
	id, err := strictAccountForEmailV2(s, fact.Recipient)
	if err != nil {
		return false, err
	}
	if fact.Purpose == "login" {
		return id != "" && id == fact.AccountID, nil
	}
	return fact.AccountID == "" || fact.AccountID == id, nil
}

func deleteVerificationFactsForAccountV2(s *snapshot, accountID, email string) {
	email = otpscope.NormalizeEmail(email)
	for id, record := range s.VerificationFactsV2 {
		if record.Fact.AccountID == accountID || (email != "" && record.Fact.Recipient == email) {
			delete(s.VerificationFactsV2, id)
		}
	}
}

// Hash only exact original encrypted bytes. Never render or expose OTP payload.
func encryptedIntentSHA256V2(intent notification.Message) string {
	sum := sha256.Sum256(func() []byte { raw, _ := msgpack.Marshal(intent.Ciphertext); return raw }())
	return hex.EncodeToString(sum[:])
}
func factIntentMatchesV2(fact EmailVerificationFactV2, record ownerEffect) bool {
	return record.Message.ID == fact.EffectID && record.Message.IdempotencyKey == fact.MessageIdempotencyKey && record.ExpiresAt == fact.ExpiresAt && fact.EncryptedPayloadSHA256 != "" && encryptedIntentSHA256V2(record.Message) == fact.EncryptedPayloadSHA256
}
