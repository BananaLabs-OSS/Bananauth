package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/notification"
	"github.com/bananalabs-oss/bananauth/pkg/otpscope"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/bananalabs-oss/bananauth/pkg/passwordcrypto"
	"github.com/vmihailenco/msgpack/v5"
)

type nativeCredential struct {
	ID           string `msgpack:"id" json:"id"`
	AccountID    string `msgpack:"account_id" json:"account_id"`
	Email        string `msgpack:"email" json:"email"`
	Username     string `msgpack:"username" json:"username"`
	PasswordHash string `msgpack:"password_hash" json:"password_hash"`
	CreatedAt    int64  `msgpack:"created_at" json:"created_at"`
}

type oauthLink struct {
	ID            string `msgpack:"id" json:"id"`
	AccountID     string `msgpack:"account_id" json:"account_id"`
	Provider      string `msgpack:"provider" json:"provider"`
	ProviderID    string `msgpack:"provider_id" json:"provider_id"`
	ProviderEmail string `msgpack:"provider_email" json:"provider_email"`
	CreatedAt     int64  `msgpack:"created_at" json:"created_at"`
}

type otpRecord struct {
	ID        string `msgpack:"id" json:"id"`
	Email     string `msgpack:"email" json:"email"`
	Code      string `msgpack:"code" json:"code"`
	CodeHash  string `msgpack:"code_hash,omitempty" json:"code_hash,omitempty"`
	Type      string `msgpack:"type" json:"type"`
	ExpiresAt int64  `msgpack:"expires_at" json:"expires_at"`
	AccountID string `msgpack:"account_id" json:"account_id"`
}

const (
	emailVerificationWindowMillis = int64((10 * time.Minute) / time.Millisecond)
	emailVerificationRecipientMax = 3
	emailVerificationCallerMax    = 10
	emailVerificationOutstanding  = 3
)

func (o *Service) otpMatches(record otpRecord, code string) bool {
	if record.CodeHash != "" {
		return o.otpKeys.VerifyCode(record.CodeHash, record.ID, record.Email, code, record.Type)
	}
	// Snapshots imported or written before the hashed OTP field remain
	// consumable until their original expiry, then ordinary pruning removes them.
	return record.Code != "" && record.Code == strings.ToUpper(strings.TrimSpace(code))
}

func pruneExpiredVerificationState(s *snapshot, now int64) {
	for id, record := range s.VerificationFactsV2 {
		if record.Fact.ExpiresAt <= now {
			delete(s.VerificationFactsV2, id)
		}
	}
	for id, record := range s.OTPs {
		if record.ExpiresAt <= now {
			delete(s.OTPs, id)
		}
	}
	for id, record := range s.Effects {
		if record.ExpiresAt > 0 && record.ExpiresAt <= now {
			delete(s.Effects, id)
		}
	}
}

func consumeIssueRate(s *snapshot, key string, now int64, maximum int) bool {
	record := s.Rates[key]
	if record.WindowStartedAt == 0 || now-record.WindowStartedAt >= emailVerificationWindowMillis {
		record = rateRecord{WindowStartedAt: now}
	}
	if record.Count >= maximum {
		return false
	}
	record.Count++
	s.Rates[key] = record
	return true
}

// notificationEmailPayload is the canonical kind-owned wire expected by the
// privileged notification executor. Templates are rendered before the intent
// crosses the owner boundary so the host never needs application state.
type notificationEmailPayload struct {
	To      string `msgpack:"to" json:"to"`
	Subject string `msgpack:"subject" json:"subject"`
	Text    string `msgpack:"text" json:"text"`
}

type rateRecord struct {
	Count           int   `msgpack:"count" json:"count"`
	WindowStartedAt int64 `msgpack:"window_started_at" json:"window_started_at"`
}

type snapshot struct {
	Format              string                              `msgpack:"format" json:"format"`
	VerificationFactsV2 map[string]emailVerificationStateV2 `msgpack:"verification_facts_v2,omitempty" json:"verification_facts_v2,omitempty"`
	Accounts            map[string]AccountProjection        `msgpack:"accounts" json:"accounts"`
	NativeByEmail       map[string]nativeCredential         `msgpack:"native_by_email" json:"native_by_email"`
	NativeByAccount     map[string]nativeCredential         `msgpack:"native_by_account" json:"native_by_account"`
	Usernames           map[string]string                   `msgpack:"usernames" json:"usernames"`
	OAuthStates         map[string]OAuthState               `msgpack:"oauth_states" json:"oauth_states"`
	OAuthLinks          map[string]oauthLink                `msgpack:"oauth_links" json:"oauth_links"`
	OTPs                map[string]otpRecord                `msgpack:"otps" json:"otps"`
	Profiles            map[string]Profile                  `msgpack:"profiles" json:"profiles"`
	Rates               map[string]rateRecord               `msgpack:"rates" json:"rates"`
	Effects             map[string]ownerEffect              `msgpack:"effects" json:"effects"`
	RetentionLeases     map[string]RetentionLease           `msgpack:"retention_leases" json:"retention_leases"`
	RetentionHolds      map[string]RetentionHold            `msgpack:"retention_holds" json:"retention_holds"`
}

func newSnapshot() snapshot {
	return snapshot{Format: "bananauth.identity.v2",
		VerificationFactsV2: map[string]emailVerificationStateV2{},
		Accounts:            map[string]AccountProjection{}, NativeByEmail: map[string]nativeCredential{},
		NativeByAccount: map[string]nativeCredential{}, Usernames: map[string]string{},
		OAuthStates: map[string]OAuthState{}, OAuthLinks: map[string]oauthLink{},
		OTPs: map[string]otpRecord{}, Profiles: map[string]Profile{}, Rates: map[string]rateRecord{},
		Effects:         map[string]ownerEffect{},
		RetentionLeases: map[string]RetentionLease{},
		RetentionHolds:  map[string]RetentionHold{},
	}
}

func (s snapshot) clone() snapshot {
	raw, _ := msgpack.Marshal(s)
	next := newSnapshot()
	_ = msgpack.Unmarshal(raw, &next)
	return next
}

type Service struct {
	mu       sync.Mutex
	state    snapshot
	receipts map[string]commandReceipt
	store    eventStore
	otpKeys  otpsecure.Keyring
}

func openOwner(ctx context.Context, store eventStore, otpKeys otpsecure.Keyring) (*Service, error) {
	if len(otpKeys.Current) == 0 {
		return nil, fmt.Errorf("open identity owner: OTP key is required")
	}
	if err := store.Migrate(ctx); err != nil {
		return nil, err
	}
	state, receipts, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	normalizeSnapshot(&state)
	return &Service{state: state, receipts: receipts, store: store, otpKeys: otpKeys}, nil
}

func normalizeSnapshot(state *snapshot) {
	if state.VerificationFactsV2 == nil {
		state.VerificationFactsV2 = map[string]emailVerificationStateV2{}
	}
	if state.RetentionHolds == nil {
		state.RetentionHolds = map[string]RetentionHold{}
	}
	// New durable fields must be usable when replaying snapshots written by an
	// earlier owner version.
	if state.RetentionLeases == nil {
		state.RetentionLeases = map[string]RetentionLease{}
	}
}

func (o *Service) notificationIntent(effectID, recipient, subject, text string, expiresAt int64) (notification.Message, error) {
	plain, err := msgpack.Marshal(notificationEmailPayload{To: recipient, Subject: subject, Text: text})
	if err != nil {
		return notification.Message{}, err
	}
	encrypted, err := o.otpKeys.Seal(effectID, recipient, expiresAt, plain)
	if err != nil {
		return notification.Message{}, err
	}
	return notification.NewMessage(effectID, effectID, encrypted)
}

func (o *Service) AccountGet(req AccountGetRequest) (Result[AccountProjection], error) {
	return runQuery[AccountProjection](o, func(s snapshot) (AccountProjection, error) {
		if req.AccountID == "" && strings.TrimSpace(req.Email) != "" {
			email := strings.ToLower(strings.TrimSpace(req.Email))
			var found *AccountProjection
			for _, account := range s.Accounts {
				if strings.ToLower(strings.TrimSpace(account.Email)) == email {
					if found != nil {
						return zeroValue[AccountProjection](), domain("conflict", "Account email is ambiguous")
					}
					copy := account
					found = &copy
				}
			}
			if found == nil {
				return zeroValue[AccountProjection](), domain("not_found", "Account not found")
			}
			return *found, nil
		}
		value, ok := s.Accounts[req.AccountID]
		if !ok {
			return zeroValue[AccountProjection](), domain("not_found", "Account not found")
		}
		return value, nil
	})
}

type domainError struct{ code, message string }

func (e domainError) Error() string     { return e.message }
func domain(code, message string) error { return domainError{code: code, message: message} }

func (o *Service) NativeRegister(req NativeRegisterRequest) (Result[AccountProjection], error) {
	req.Email = otpscope.NormalizeEmail(req.Email)
	return runCommand[AccountProjection](o, FnNativeRegister, req.RequestID, req, func(s *snapshot) (AccountProjection, error) {
		if blank(req.AccountID) || blank(req.CredentialID) || blank(req.Email) || blank(req.Username) || len(req.Password) < 8 || req.Now <= 0 {
			return zeroValue[AccountProjection](), domain("invalid_request", "native registration is incomplete")
		}
		if _, ok := s.NativeByEmail[req.Email]; ok {
			return zeroValue[AccountProjection](), domain("email_taken", "An account with this email already exists")
		}
		if _, ok := s.Usernames[req.Username]; ok {
			return zeroValue[AccountProjection](), domain("username_taken", "This username is already taken")
		}
		hash, err := passwordcrypto.Hash(req.Password)
		if err != nil {
			return zeroValue[AccountProjection](), err
		}
		account := AccountProjection{AccountID: req.AccountID, Email: req.Email, Username: req.Username, CreatedAt: req.Now}
		credential := nativeCredential{ID: req.CredentialID, AccountID: req.AccountID, Email: req.Email, Username: req.Username, PasswordHash: hash, CreatedAt: req.Now}
		s.Accounts[req.AccountID], s.NativeByEmail[req.Email], s.NativeByAccount[req.AccountID], s.Usernames[req.Username] =
			account, credential, credential, req.AccountID
		return account, nil
	})
}

func (o *Service) NativeAuthenticate(req NativeAuthenticateRequest) (Result[AccountProjection], error) {
	req.Email = otpscope.NormalizeEmail(req.Email)
	return runQuery[AccountProjection](o, func(s snapshot) (AccountProjection, error) {
		credential, ok := s.NativeByEmail[req.Email]
		if !ok || !passwordcrypto.Verify(credential.PasswordHash, req.Password) {
			return zeroValue[AccountProjection](), domain("invalid_credentials", "Invalid email or password")
		}
		return s.Accounts[credential.AccountID], nil
	})
}

func (o *Service) NativeCredentialAttach(req NativeCredentialAttachRequest) (Result[AccountProjection], error) {
	req.Email = otpscope.NormalizeEmail(req.Email)
	return runCommand[AccountProjection](o, FnNativeCredentialAttach, req.RequestID, req, func(s *snapshot) (AccountProjection, error) {
		account, exists := s.Accounts[req.AccountID]
		if !exists {
			return zeroValue[AccountProjection](), domain("not_found", "account not found")
		}
		if blank(req.CredentialID) || blank(req.Email) || blank(req.Username) || len(req.Password) < 8 || req.Now <= 0 {
			return zeroValue[AccountProjection](), domain("invalid_request", "native credential attach is incomplete")
		}
		if account.Email == "" || !strings.EqualFold(account.Email, req.Email) {
			return zeroValue[AccountProjection](), domain("invalid_email", "native email must match the authenticated account")
		}
		if _, exists := s.NativeByAccount[req.AccountID]; exists {
			return zeroValue[AccountProjection](), domain("native_exists", "account already has a native credential")
		}
		if existing, exists := s.NativeByEmail[req.Email]; exists && existing.AccountID != req.AccountID {
			return zeroValue[AccountProjection](), domain("email_taken", "email is already attached to another account")
		}
		if existing, exists := s.Usernames[req.Username]; exists && existing != req.AccountID {
			return zeroValue[AccountProjection](), domain("username_taken", "username is already taken")
		}
		hash, err := passwordcrypto.Hash(req.Password)
		if err != nil {
			return zeroValue[AccountProjection](), err
		}
		credential := nativeCredential{ID: req.CredentialID, AccountID: req.AccountID, Email: req.Email, Username: req.Username, PasswordHash: hash, CreatedAt: req.Now}
		s.NativeByAccount[req.AccountID], s.NativeByEmail[req.Email], s.Usernames[req.Username] = credential, credential, req.AccountID
		account.Username = req.Username
		s.Accounts[req.AccountID] = account
		return account, nil
	})
}

func (o *Service) PasswordChange(req PasswordChangeRequest) (Result[map[string]any], error) {
	return runCommand[map[string]any](o, FnNativePasswordChange, req.RequestID, req, func(s *snapshot) (map[string]any, error) {
		credential, ok := s.NativeByAccount[req.AccountID]
		if !ok {
			return zeroValue[map[string]any](), domain("not_found", "No native account found")
		}
		if !passwordcrypto.Verify(credential.PasswordHash, req.CurrentPassword) {
			return zeroValue[map[string]any](), domain("invalid_password", "Current password is incorrect")
		}
		if len(req.NewPassword) < 8 {
			return zeroValue[map[string]any](), domain("invalid_request", "new password is too short")
		}
		hash, err := passwordcrypto.Hash(req.NewPassword)
		if err != nil {
			return zeroValue[map[string]any](), err
		}
		credential.PasswordHash = hash
		s.NativeByAccount[req.AccountID], s.NativeByEmail[credential.Email] = credential, credential
		return map[string]any{"changed": true}, nil
	})
}

func (o *Service) PasswordResetIssue(req PasswordResetIssueRequest) (Result[PasswordResetIssueResult], error) {
	req.Email = otpscope.NormalizeEmail(req.Email)
	return runCommand[PasswordResetIssueResult](o, FnPasswordResetIssue, req.RequestID, req, func(s *snapshot) (PasswordResetIssueResult, error) {
		credential, exists := s.NativeByEmail[req.Email]
		if !exists {
			return PasswordResetIssueResult{Accepted: true}, nil
		}
		if blank(req.OTPID) || blank(req.EffectID) || blank(req.Code) || req.Now <= 0 || req.ExpiresAt <= req.Now {
			return zeroValue[PasswordResetIssueResult](), domain("invalid_request", "password reset issue is incomplete")
		}
		if _, exists := s.Effects[req.EffectID]; exists {
			return zeroValue[PasswordResetIssueResult](), domain("idempotency_conflict", "effect id already exists")
		}
		for id, value := range s.OTPs {
			if value.Email == req.Email && value.Type == "password_reset" {
				delete(s.OTPs, id)
			}
		}
		s.OTPs[req.OTPID] = otpRecord{ID: req.OTPID, Email: req.Email, CodeHash: o.otpKeys.CodeMAC(req.OTPID, req.Email, req.Code, "password_reset"), Type: "password_reset", ExpiresAt: req.ExpiresAt, AccountID: credential.AccountID}
		intent, err := o.notificationIntent(req.EffectID, req.Email, "Password reset code", fmt.Sprintf("Your reset code: %s\nExpires in 10 minutes.", strings.ToUpper(req.Code)), req.ExpiresAt)
		if err != nil {
			return zeroValue[PasswordResetIssueResult](), err
		}
		s.Effects[intent.ID] = ownerEffect{Message: intent, Status: string(notification.Pending), AvailableAt: req.Now, ExpiresAt: req.ExpiresAt}
		return PasswordResetIssueResult{Accepted: true, EffectQueued: true}, nil
	})
}

func (o *Service) PasswordResetConsume(req PasswordResetConsumeRequest) (Result[map[string]any], error) {
	req.Email = otpscope.NormalizeEmail(req.Email)
	return runCommand[map[string]any](o, FnPasswordResetConsume, req.RequestID, req, func(s *snapshot) (map[string]any, error) {
		var id string
		var otp otpRecord
		for key, candidate := range s.OTPs {
			if candidate.Email == req.Email && candidate.Type == "password_reset" && o.otpMatches(candidate, req.Code) && candidate.ExpiresAt > req.Now {
				id, otp = key, candidate
				break
			}
		}
		if id == "" {
			return zeroValue[map[string]any](), domain("invalid_code", "Invalid or expired reset code")
		}
		credential, ok := s.NativeByAccount[otp.AccountID]
		if !ok {
			return zeroValue[map[string]any](), domain("not_found", "native account not found")
		}
		hash, err := passwordcrypto.Hash(req.NewPassword)
		if err != nil {
			return zeroValue[map[string]any](), err
		}
		delete(s.OTPs, id)
		credential.PasswordHash = hash
		s.NativeByAccount[credential.AccountID], s.NativeByEmail[credential.Email] = credential, credential
		delete(s.Rates, "password_reset_email:"+req.Email)
		return map[string]any{"changed": true}, nil
	})
}

func (o *Service) AccountDelete(req AccountDeleteRequest) (Result[AccountProjection], error) {
	req.Email = otpscope.NormalizeEmail(req.Email)
	return runCommand[AccountProjection](o, FnAccountDelete, req.RequestID, req, func(s *snapshot) (AccountProjection, error) {
		account, ok := s.Accounts[req.AccountID]
		if !ok {
			return zeroValue[AccountProjection](), domain("not_found", "No account found")
		}
		live := activeRetentionLeases(s, req.AccountID, req.Now)
		if len(live) != 0 || len(activeRetentionHolds(s, req.AccountID)) != 0 {
			return zeroValue[AccountProjection](), domain("retention_active", "account has active retention protection")
		}
		if native, ok := s.NativeByAccount[req.AccountID]; ok {
			if !passwordcrypto.Verify(native.PasswordHash, req.Password) {
				return zeroValue[AccountProjection](), domain("invalid_password", "Password is incorrect")
			}
			delete(s.NativeByEmail, native.Email)
			delete(s.NativeByAccount, req.AccountID)
			delete(s.Usernames, native.Username)
			for id, otp := range s.OTPs {
				if otp.Email == native.Email {
					delete(s.OTPs, id)
				}
			}
		} else {
			authorized := false
			for _, link := range s.OAuthLinks {
				if link.AccountID == req.AccountID && strings.EqualFold(link.ProviderEmail, req.Email) {
					authorized = true
					break
				}
			}
			if !authorized {
				return zeroValue[AccountProjection](), domain("invalid_email", "Email does not match account")
			}
		}
		for key, link := range s.OAuthLinks {
			if link.AccountID == req.AccountID {
				delete(s.OAuthLinks, key)
			}
		}
		delete(s.Profiles, req.AccountID)
		for key, lease := range s.RetentionLeases {
			if lease.AccountID == req.AccountID {
				delete(s.RetentionLeases, key)
			}
		}
		for key, hold := range s.RetentionHolds {
			if hold.AccountID == req.AccountID {
				delete(s.RetentionHolds, key)
			}
		}
		deleteVerificationFactsForAccountV2(s, req.AccountID, account.Email)
		delete(s.Accounts, req.AccountID)
		return account, nil
	})
}

// accountErase is deliberately distinct from user-initiated accountDelete.
// Its authority is supplied by the authenticated erasure HTTP service credential, and it still
// performs the retention check in the same owner transaction as deletion so a
// concurrently renewed application lease always wins.
func (o *Service) AccountErase(req AccountEraseRequest) (Result[AccountProjection], error) {
	return runCommand[AccountProjection](o, FnAccountErase, req.RequestID, req, func(s *snapshot) (AccountProjection, error) {
		if blank(req.AccountID) || blank(req.ReasonID) || req.Now <= 0 {
			return zeroValue[AccountProjection](), domain("invalid_request", "account_id, reason_id, and now are required")
		}
		account, ok := s.Accounts[req.AccountID]
		if !ok {
			return zeroValue[AccountProjection](), domain("not_found", "No account found")
		}
		if live := activeRetentionLeases(s, req.AccountID, req.Now); len(live) != 0 || len(activeRetentionHolds(s, req.AccountID)) != 0 {
			return zeroValue[AccountProjection](), domain("retention_active", "account has active retention protection")
		}
		if native, ok := s.NativeByAccount[req.AccountID]; ok {
			delete(s.NativeByEmail, native.Email)
			delete(s.NativeByAccount, req.AccountID)
			delete(s.Usernames, native.Username)
			for id, otp := range s.OTPs {
				if otp.Email == native.Email {
					delete(s.OTPs, id)
				}
			}
		}
		for key, link := range s.OAuthLinks {
			if link.AccountID == req.AccountID {
				delete(s.OAuthLinks, key)
			}
		}
		delete(s.Profiles, req.AccountID)
		for key, lease := range s.RetentionLeases {
			if lease.AccountID == req.AccountID {
				delete(s.RetentionLeases, key)
			}
		}
		for key, hold := range s.RetentionHolds {
			if hold.AccountID == req.AccountID {
				delete(s.RetentionHolds, key)
			}
		}
		deleteVerificationFactsForAccountV2(s, req.AccountID, account.Email)
		delete(s.Accounts, req.AccountID)
		return account, nil
	})
}

func retentionLeaseKey(accountID, leaseID string) string { return accountID + "\x00" + leaseID }

func activeRetentionLeases(s *snapshot, accountID string, now int64) []RetentionLease {
	leases := make([]RetentionLease, 0)
	for key, lease := range s.RetentionLeases {
		if lease.ExpiresAt <= now {
			delete(s.RetentionLeases, key)
			continue
		}
		if lease.AccountID == accountID {
			leases = append(leases, lease)
		}
	}
	sort.Slice(leases, func(i, j int) bool { return leases[i].LeaseID < leases[j].LeaseID })
	return leases
}

func validateRetentionLease(lease RetentionLease, now int64) error {
	if blank(lease.AccountID) || blank(lease.LeaseID) || blank(lease.ReasonID) || lease.ExpiresAt <= now {
		return domain("invalid_request", "retention lease requires account_id, lease_id, reason_id, and future expires_at")
	}
	return nil
}

func (o *Service) RetentionLeaseCreate(req RetentionLeaseCreateRequest) (Result[RetentionLease], error) {
	return runCommand[RetentionLease](o, FnRetentionLeaseCreate, req.RequestID, req, func(s *snapshot) (RetentionLease, error) {
		if err := validateRetentionLease(req.Lease, req.Now); err != nil {
			return zeroValue[RetentionLease](), err
		}
		if _, ok := s.Accounts[req.Lease.AccountID]; !ok {
			return zeroValue[RetentionLease](), domain("not_found", "No account found")
		}
		key := retentionLeaseKey(req.Lease.AccountID, req.Lease.LeaseID)
		if _, exists := s.RetentionLeases[key]; exists {
			return zeroValue[RetentionLease](), domain("conflict", "retention lease already exists")
		}
		s.RetentionLeases[key] = req.Lease
		return req.Lease, nil
	})
}

func (o *Service) RetentionLeaseRenew(req RetentionLeaseRenewRequest) (Result[RetentionLease], error) {
	return runCommand[RetentionLease](o, FnRetentionLeaseRenew, req.RequestID, req, func(s *snapshot) (RetentionLease, error) {
		if err := validateRetentionLease(req.Lease, req.Now); err != nil {
			return zeroValue[RetentionLease](), err
		}
		key := retentionLeaseKey(req.Lease.AccountID, req.Lease.LeaseID)
		prior, exists := s.RetentionLeases[key]
		if !exists || prior.ExpiresAt <= req.Now {
			return zeroValue[RetentionLease](), domain("not_found", "retention lease not found")
		}
		if prior.ReasonID != req.Lease.ReasonID {
			return zeroValue[RetentionLease](), domain("conflict", "retention lease reason cannot change")
		}
		s.RetentionLeases[key] = req.Lease
		return req.Lease, nil
	})
}

func (o *Service) RetentionLeaseRelease(req RetentionLeaseReleaseRequest) (Result[RetentionEligibility], error) {
	return runCommand[RetentionEligibility](o, FnRetentionLeaseRelease, req.RequestID, req, func(s *snapshot) (RetentionEligibility, error) {
		if blank(req.AccountID) || blank(req.LeaseID) || blank(req.ReasonID) {
			return zeroValue[RetentionEligibility](), domain("invalid_request", "account_id, lease_id, and reason_id are required")
		}
		key := retentionLeaseKey(req.AccountID, req.LeaseID)
		lease, exists := s.RetentionLeases[key]
		if !exists || lease.ExpiresAt <= req.Now {
			delete(s.RetentionLeases, key)
			return retentionEligibilityFor(s, req.AccountID, req.Now), nil
		}
		if lease.ReasonID != req.ReasonID {
			return zeroValue[RetentionEligibility](), domain("conflict", "retention lease reason does not match")
		}
		delete(s.RetentionLeases, key)
		return retentionEligibilityFor(s, req.AccountID, req.Now), nil
	})
}

func (o *Service) RetentionLeaseList(req RetentionLeaseListRequest) (Result[RetentionLeaseListResult], error) {
	return runQuery[RetentionLeaseListResult](o, func(s snapshot) (RetentionLeaseListResult, error) {
		if blank(req.AccountID) {
			return zeroValue[RetentionLeaseListResult](), domain("invalid_request", "account_id is required")
		}
		return RetentionLeaseListResult{Leases: activeRetentionLeases(&s, req.AccountID, req.Now)}, nil
	})
}

func (o *Service) RetentionEligibility(req RetentionEligibilityRequest) (Result[RetentionEligibility], error) {
	return runQuery[RetentionEligibility](o, func(s snapshot) (RetentionEligibility, error) {
		if blank(req.AccountID) {
			return zeroValue[RetentionEligibility](), domain("invalid_request", "account_id is required")
		}
		return retentionEligibilityFor(&s, req.AccountID, req.Now), nil
	})
}

func (o *Service) OauthStateIssue(req OAuthStateIssueRequest) (Result[OAuthState], error) {
	return runCommand[OAuthState](o, FnOAuthStateIssue, req.RequestID, req, func(s *snapshot) (OAuthState, error) {
		if blank(req.State.State) || blank(req.State.Provider) || req.State.ExpiresAt <= 0 {
			return zeroValue[OAuthState](), domain("invalid_request", "OAuth state is incomplete")
		}
		if _, exists := s.OAuthStates[req.State.State]; exists {
			return zeroValue[OAuthState](), domain("conflict", "OAuth state already exists")
		}
		s.OAuthStates[req.State.State] = req.State
		return req.State, nil
	})
}

func (o *Service) OauthStateConsume(req OAuthStateConsumeRequest) (Result[OAuthState], error) {
	return runCommand[OAuthState](o, FnOAuthStateConsume, req.RequestID, req, func(s *snapshot) (OAuthState, error) {
		value, ok := s.OAuthStates[req.State]
		if !ok || value.ConsumedAt != 0 || value.ExpiresAt <= req.Now || value.Provider != req.Provider || value.RedirectBinding != req.RedirectBinding {
			return zeroValue[OAuthState](), domain("invalid_state", "OAuth state mismatch or expired")
		}
		value.ConsumedAt = req.Now
		s.OAuthStates[req.State] = value
		return value, nil
	})
}

func oauthKey(provider, id string) string { return provider + "\x00" + id }

func (o *Service) OauthResolve(req OAuthResolveRequest) (Result[AccountProjection], error) {
	return runQuery[AccountProjection](o, func(s snapshot) (AccountProjection, error) {
		link, ok := s.OAuthLinks[oauthKey(req.Provider, req.ProviderID)]
		if !ok {
			return zeroValue[AccountProjection](), domain("not_found", "OAuth link not found")
		}
		return s.Accounts[link.AccountID], nil
	})
}

func (o *Service) OauthUpsert(req OAuthUpsertRequest) (Result[OAuthUpsertResult], error) {
	return runCommand[OAuthUpsertResult](o, FnOAuthUpsert, req.RequestID, req, func(s *snapshot) (OAuthUpsertResult, error) {
		key := oauthKey(req.Provider, req.ProviderID)
		if link, ok := s.OAuthLinks[key]; ok {
			return OAuthUpsertResult{Account: s.Accounts[link.AccountID]}, nil
		}
		if blank(req.AccountID) || blank(req.LinkID) || blank(req.Provider) || blank(req.ProviderID) || req.Now <= 0 {
			return zeroValue[OAuthUpsertResult](), domain("invalid_request", "OAuth identity is incomplete")
		}
		account := AccountProjection{AccountID: req.AccountID, Email: req.ProviderEmail, CreatedAt: req.Now}
		s.Accounts[req.AccountID] = account
		s.OAuthLinks[key] = oauthLink{ID: req.LinkID, AccountID: req.AccountID, Provider: req.Provider, ProviderID: req.ProviderID, ProviderEmail: req.ProviderEmail, CreatedAt: req.Now}
		return OAuthUpsertResult{Account: account, Created: true}, nil
	})
}

func (o *Service) ProfileCreate(req ProfileCreateRequest) (Result[Profile], error) {
	return runCommand[Profile](o, FnProfileCreate, req.RequestID, req, func(s *snapshot) (Profile, error) {
		if _, ok := s.Accounts[req.Profile.AccountID]; !ok {
			return zeroValue[Profile](), domain("not_found", "account not found")
		}
		if _, ok := s.Profiles[req.Profile.AccountID]; ok {
			return zeroValue[Profile](), domain("profile_exists", "Profile already exists for this account")
		}
		if blank(req.Profile.DisplayName) || req.Profile.CreatedAt <= 0 {
			return zeroValue[Profile](), domain("invalid_request", "profile is incomplete")
		}
		s.Profiles[req.Profile.AccountID] = req.Profile
		return req.Profile, nil
	})
}

func (o *Service) ProfileGet(req ProfileGetRequest) (Result[Profile], error) {
	return runQuery[Profile](o, func(s snapshot) (Profile, error) {
		value, ok := s.Profiles[req.AccountID]
		if !ok {
			return zeroValue[Profile](), domain("not_found", "Profile not found")
		}
		return value, nil
	})
}

func (o *Service) ProfileUpdate(req ProfileUpdateRequest) (Result[Profile], error) {
	return runCommand[Profile](o, FnProfileUpdate, req.RequestID, req, func(s *snapshot) (Profile, error) {
		value, ok := s.Profiles[req.AccountID]
		if !ok {
			return zeroValue[Profile](), domain("not_found", "Profile not found")
		}
		if req.DisplayName != "" {
			value.DisplayName = req.DisplayName
		}
		value.UpdatedAt = req.Now
		s.Profiles[req.AccountID] = value
		return value, nil
	})
}

func rateKey(scope, key string) string { return scope + ":" + key }

func (o *Service) RateCheck(req RateCheckRequest) (Result[RateDecision], error) {
	return runCommand[RateDecision](o, FnRateCheck, req.RequestID, req, func(s *snapshot) (RateDecision, error) {
		if blank(req.Scope) || blank(req.Key) || req.Now <= 0 || req.WindowMillis <= 0 || req.MaxAttempts <= 0 {
			return zeroValue[RateDecision](), domain("invalid_request", "rate check is incomplete")
		}
		key := rateKey(req.Scope, req.Key)
		record := s.Rates[key]
		if record.WindowStartedAt == 0 || req.Now-record.WindowStartedAt >= req.WindowMillis {
			record = rateRecord{WindowStartedAt: req.Now}
		}
		if record.Count >= req.MaxAttempts {
			return RateDecision{Allowed: false, Count: record.Count, RetryAfterMillis: req.WindowMillis - (req.Now - record.WindowStartedAt)}, nil
		}
		record.Count++
		s.Rates[key] = record
		return RateDecision{Allowed: true, Count: record.Count}, nil
	})
}

func (o *Service) RateClear(req RateClearRequest) (Result[map[string]any], error) {
	return runCommand[map[string]any](o, FnRateClear, req.RequestID, req, func(s *snapshot) (map[string]any, error) {
		delete(s.Rates, rateKey(req.Scope, req.Key))
		return map[string]any{"cleared": true}, nil
	})
}

func (o *Service) LegacyImport(req LegacyImportRequest) (Result[LegacyImportResult], error) {
	return runCommand[LegacyImportResult](o, FnLegacyImport, req.RequestID, req, func(s *snapshot) (LegacyImportResult, error) {
		next := s.clone()
		for _, account := range req.Accounts {
			if blank(account.AccountID) || account.CreatedAt <= 0 {
				return zeroValue[LegacyImportResult](), domain("invalid_import", "legacy account is incomplete")
			}
			if prior, ok := next.Accounts[account.AccountID]; ok && prior != account {
				return zeroValue[LegacyImportResult](), domain("import_conflict", "legacy account conflicts with owner state")
			}
			next.Accounts[account.AccountID] = account
		}
		for _, row := range req.Native {
			row.Email = otpscope.NormalizeEmail(row.Email)
			if blank(row.ID) || blank(row.AccountID) || blank(row.Email) || blank(row.Username) || blank(row.PasswordHash) {
				return zeroValue[LegacyImportResult](), domain("invalid_import", "legacy native credential is incomplete")
			}
			value := nativeCredential(row)
			if prior, ok := next.NativeByEmail[row.Email]; ok && prior != value {
				return zeroValue[LegacyImportResult](), domain("import_conflict", "legacy native email conflicts with owner state")
			}
			if prior, ok := next.NativeByAccount[row.AccountID]; ok && prior != value {
				return zeroValue[LegacyImportResult](), domain("import_conflict", "legacy account has conflicting native credentials")
			}
			if ownerID, ok := next.Usernames[row.Username]; ok && ownerID != row.AccountID {
				return zeroValue[LegacyImportResult](), domain("import_conflict", "legacy username conflicts with owner state")
			}
			if _, ok := next.Accounts[row.AccountID]; !ok {
				return zeroValue[LegacyImportResult](), domain("invalid_import", "legacy native credential references a missing account")
			}
			next.NativeByEmail[row.Email], next.NativeByAccount[row.AccountID], next.Usernames[row.Username] = value, value, row.AccountID
		}
		for _, row := range req.OAuthLinks {
			value := oauthLink(row)
			key := oauthKey(row.Provider, row.ProviderID)
			if _, ok := next.Accounts[row.AccountID]; !ok {
				return zeroValue[LegacyImportResult](), domain("invalid_import", "legacy OAuth link references a missing account")
			}
			if prior, ok := next.OAuthLinks[key]; ok && prior != value {
				return zeroValue[LegacyImportResult](), domain("import_conflict", "legacy OAuth link conflicts with owner state")
			}
			next.OAuthLinks[key] = value
		}
		for _, row := range req.OTPs {
			row.Email = otpscope.NormalizeEmail(row.Email)
			value := otpRecord{ID: row.ID, Email: row.Email, CodeHash: o.otpKeys.CodeMAC(row.ID, row.Email, row.Code, row.Type), Type: row.Type, ExpiresAt: row.ExpiresAt, AccountID: row.AccountID}
			if row.AccountID != "" {
				if _, ok := next.Accounts[row.AccountID]; !ok {
					return zeroValue[LegacyImportResult](), domain("invalid_import", "legacy OTP references a missing account")
				}
			}
			if prior, ok := next.OTPs[row.ID]; ok && prior != value {
				return zeroValue[LegacyImportResult](), domain("import_conflict", "legacy OTP conflicts with owner state")
			}
			next.OTPs[row.ID] = value
		}
		for _, profile := range req.Profiles {
			if _, ok := next.Accounts[profile.AccountID]; !ok {
				return zeroValue[LegacyImportResult](), domain("invalid_import", "legacy profile references a missing account")
			}
			if prior, ok := next.Profiles[profile.AccountID]; ok && prior != profile {
				return zeroValue[LegacyImportResult](), domain("import_conflict", "legacy profile conflicts with owner state")
			}
			next.Profiles[profile.AccountID] = profile
		}
		*s = next
		return LegacyImportResult{Accounts: len(req.Accounts), Native: len(req.Native), OAuthLinks: len(req.OAuthLinks), OTPs: len(req.OTPs), Profiles: len(req.Profiles)}, nil
	})
}

const FnEffectsCheckDelivery = "auth.identity.effects.native.check-delivery"

func (o *Service) EffectsCheckDelivery(lease notification.Lease) (Result[bool], error) {
	return runQuery[bool](o, func(s snapshot) (bool, error) {
		now := time.Now().UnixMilli()
		record, ok := s.Effects[lease.Message.ID]
		if !ok || record.Lease == nil || record.Lease.LeaseID != lease.LeaseID ||
			record.Lease.ConsumerID != lease.ConsumerID || record.Lease.LeasedUntilUnixMilli <= now ||
			record.Status != string(notification.Pending) || !reflect.DeepEqual(record.Message, lease.Message) ||
			!legacyNotificationEffectHasLiveOTP(&s, record, now) {
			return false, nil
		}
		return verificationDeliveryAllowed(&s, record, now), nil
	})
}

func leaseToken(id, consumer string, until int64, attempt uint32) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%d", id, consumer, until, attempt)))
	return hex.EncodeToString(sum[:])
}

func legacyNotificationEffectHasLiveOTP(s *snapshot, record ownerEffect, now int64) bool {
	if record.ExpiresAt > 0 {
		return record.ExpiresAt > now
	}
	var payload notificationEmailPayload
	if err := msgpack.Unmarshal(record.Message.Ciphertext, &payload); err != nil || payload.To == "" {
		return false
	}
	for _, otp := range s.OTPs {
		if otp.ExpiresAt > now && strings.EqualFold(otp.Email, payload.To) {
			return true
		}
	}
	return false
}

func verificationDeliveryAllowed(s *snapshot, record ownerEffect, now int64) bool {
	fact, ok := s.VerificationFactsV2[record.Message.ID]
	if !ok {
		return true
	}
	active, err := verificationDeliveryActive(s, fact, record, now)
	return err == nil && active
}

func (o *Service) EffectsClaim(req notification.ClaimRequest) (notification.ClaimResult, error) {
	if err := req.Validate(); err != nil {
		return zeroValue[notification.ClaimResult](), fmt.Errorf("invalid identity effect claim")
	}
	now := time.Now().UTC().UnixMilli()
	// Idle polling is observational, not a domain command. Persisting every
	// empty poll serialized login behind needless PostgreSQL writes and could
	// let a valid consume commit only after the HTTP deadline.
	o.mu.Lock()
	// Another process may own the request-facing replica and append a new
	// effect after this worker replica last handled a command. Refresh the
	// latest durable snapshot before applying the empty-queue fast path;
	// otherwise an idle worker with an empty local map can never discover work
	// produced by its peer. LoadCommand is read-only here, so genuinely idle
	// polling still creates no journal rows.
	_, current, _, err := o.store.LoadCommand(context.Background(), "", "")
	if err != nil {
		o.mu.Unlock()
		return zeroValue[notification.ClaimResult](), fmt.Errorf("refresh %s: %w", FnEffectsClaim, err)
	}
	normalizeSnapshot(&current)
	o.state = current
	hasClaimable := false
	for _, record := range o.state.Effects {
		if record.Status == string(notification.Pending) && record.AvailableAt <= now &&
			(record.Lease == nil || record.Lease.LeasedUntilUnixMilli <= now) &&
			((record.ExpiresAt > 0 && record.ExpiresAt <= now) || verificationDeliveryAllowed(&o.state, record, now)) {
			hasClaimable = true
			break
		}
	}
	o.mu.Unlock()
	if !hasClaimable {
		return notification.ClaimResult{
			ConsumerID: req.ConsumerID, Leases: []notification.Lease{},
		}, nil
	}
	requestID := fmt.Sprintf("%s:%d", req.ConsumerID, time.Now().UTC().UnixNano())
	return runRawCommand[notification.ClaimResult](o, FnEffectsClaim, requestID, req, func(s *snapshot) (notification.ClaimResult, error) {
		pruneExpiredVerificationState(s, now)
		ids := make([]string, 0, len(s.Effects))
		for id := range s.Effects {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		leases := []notification.Lease{}
		for _, id := range ids {
			record := s.Effects[id]
			if !legacyNotificationEffectHasLiveOTP(s, record, now) {
				delete(s.Effects, id)
				continue
			}
			if record.Status != string(notification.Pending) || record.AvailableAt > now || (record.Lease != nil && record.Lease.LeasedUntilUnixMilli > now) {
				continue
			}
			if !verificationDeliveryAllowed(s, record, now) {
				continue
			}
			attempt := record.Attempts + 1
			until := now + req.LeaseDurationMillis
			lease := notification.Lease{ConsumerID: req.ConsumerID, LeaseID: leaseToken(id, req.ConsumerID, until, attempt), Attempt: attempt, LeasedUntilUnixMilli: until, Message: record.Message.Clone()}
			record.Lease = &lease
			record.Attempts = attempt
			s.Effects[id] = record
			leases = append(leases, lease.Clone())
			if uint32(len(leases)) == req.Limit {
				break
			}
		}
		return notification.ClaimResult{ConsumerID: req.ConsumerID, Leases: leases}, nil
	})
}

func (o *Service) EffectsAck(req notification.AcknowledgeRequest) (notification.SettlementResult, error) {
	return runRawCommand[notification.SettlementResult](o, FnEffectsAck, "ack:"+req.LeaseID, req, func(s *snapshot) (notification.SettlementResult, error) {
		for id, record := range s.Effects {
			if record.Lease == nil || record.Lease.LeaseID != req.LeaseID {
				continue
			}
			if err := req.ValidateFor(*record.Lease); err != nil {
				return zeroValue[notification.SettlementResult](), err
			}
			record.Receipt, record.LastLeaseID, record.LastConsumerID, record.Lease = &req.Receipt, req.LeaseID, req.ConsumerID, nil
			record.Status = string(req.Receipt.Status)
			s.Effects[id] = record
			return notification.SettlementResult{ConsumerID: req.ConsumerID, LeaseID: req.LeaseID, Settled: true}, nil
		}
		for _, record := range s.Effects {
			if record.LastLeaseID == req.LeaseID && record.LastConsumerID == req.ConsumerID && record.Receipt != nil && reflect.DeepEqual(*record.Receipt, req.Receipt) {
				return notification.SettlementResult{ConsumerID: req.ConsumerID, LeaseID: req.LeaseID, Settled: true}, nil
			}
		}
		return notification.SettlementResult{ConsumerID: req.ConsumerID, LeaseID: req.LeaseID}, nil
	})
}

func (o *Service) EffectsRetry(req notification.RetryRequest) (notification.SettlementResult, error) {
	return runRawCommand[notification.SettlementResult](o, FnEffectsRetry, "retry:"+req.LeaseID, req, func(s *snapshot) (notification.SettlementResult, error) {
		for id, record := range s.Effects {
			if record.Lease == nil || record.Lease.LeaseID != req.LeaseID {
				continue
			}
			if err := req.ValidateFor(*record.Lease); err != nil {
				return zeroValue[notification.SettlementResult](), err
			}
			record.AvailableAt, record.LastLeaseID, record.LastConsumerID, record.Lease = req.RetryAtUnixMilli, req.LeaseID, req.ConsumerID, nil
			s.Effects[id] = record
			return notification.SettlementResult{ConsumerID: req.ConsumerID, LeaseID: req.LeaseID, Settled: true}, nil
		}
		return notification.SettlementResult{ConsumerID: req.ConsumerID, LeaseID: req.LeaseID}, nil
	})
}

func success[T any](value T) Result[T] {
	return Result[T]{Version: ContractVersion, OK: true, Value: value}
}
func failure[T any](code, message string) Result[T] {
	return Result[T]{Version: ContractVersion, Error: &Error{Code: code, Message: message}}
}
func blank(value string) bool { return strings.TrimSpace(value) == "" }
