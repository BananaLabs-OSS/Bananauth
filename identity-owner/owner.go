package main

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

	"github.com/BananaLabs-OSS/Fiber/pulp/effect"
	"github.com/bananalabs-oss/bananauth/pkg/otpscope"
	"github.com/bananalabs-oss/bananauth/pkg/passwordcrypto"
	"github.com/vmihailenco/msgpack/v5"
)

type nativeCredential struct {
	ID           string `msgpack:"id"`
	AccountID    string `msgpack:"account_id"`
	Email        string `msgpack:"email"`
	Username     string `msgpack:"username"`
	PasswordHash string `msgpack:"password_hash"`
	CreatedAt    int64  `msgpack:"created_at"`
}

type oauthLink struct {
	ID            string `msgpack:"id"`
	AccountID     string `msgpack:"account_id"`
	Provider      string `msgpack:"provider"`
	ProviderID    string `msgpack:"provider_id"`
	ProviderEmail string `msgpack:"provider_email"`
	CreatedAt     int64  `msgpack:"created_at"`
}

type otpRecord struct {
	ID        string `msgpack:"id"`
	Email     string `msgpack:"email"`
	Code      string `msgpack:"code"`
	Type      string `msgpack:"type"`
	ExpiresAt int64  `msgpack:"expires_at"`
	AccountID string `msgpack:"account_id"`
}

// notificationEmailPayload is the canonical kind-owned wire expected by the
// privileged notification executor. Templates are rendered before the intent
// crosses the owner boundary so the host never needs application state.
type notificationEmailPayload struct {
	To      string `msgpack:"to"`
	Subject string `msgpack:"subject"`
	Text    string `msgpack:"text"`
}

type rateRecord struct {
	Count           int   `msgpack:"count"`
	WindowStartedAt int64 `msgpack:"window_started_at"`
}

type snapshot struct {
	Accounts        map[string]AccountProjection `msgpack:"accounts"`
	NativeByEmail   map[string]nativeCredential  `msgpack:"native_by_email"`
	NativeByAccount map[string]nativeCredential  `msgpack:"native_by_account"`
	Usernames       map[string]string            `msgpack:"usernames"`
	OAuthStates     map[string]OAuthState        `msgpack:"oauth_states"`
	OAuthLinks      map[string]oauthLink         `msgpack:"oauth_links"`
	OTPs            map[string]otpRecord         `msgpack:"otps"`
	Profiles        map[string]Profile           `msgpack:"profiles"`
	Rates           map[string]rateRecord        `msgpack:"rates"`
	Effects         map[string]ownerEffect       `msgpack:"effects"`
	RetentionLeases map[string]RetentionLease    `msgpack:"retention_leases"`
}

func newSnapshot() snapshot {
	return snapshot{
		Accounts: map[string]AccountProjection{}, NativeByEmail: map[string]nativeCredential{},
		NativeByAccount: map[string]nativeCredential{}, Usernames: map[string]string{},
		OAuthStates: map[string]OAuthState{}, OAuthLinks: map[string]oauthLink{},
		OTPs: map[string]otpRecord{}, Profiles: map[string]Profile{}, Rates: map[string]rateRecord{},
		Effects:         map[string]ownerEffect{},
		RetentionLeases: map[string]RetentionLease{},
	}
}

func (s snapshot) clone() snapshot {
	raw, _ := msgpack.Marshal(s)
	next := newSnapshot()
	_ = msgpack.Unmarshal(raw, &next)
	return next
}

type owner struct {
	mu       sync.Mutex
	state    snapshot
	receipts map[string]commandReceipt
	store    eventStore
}

func openOwner(ctx context.Context, store eventStore) (*owner, error) {
	if err := store.Migrate(ctx); err != nil {
		return nil, err
	}
	state, receipts, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	// New durable fields must be usable when replaying snapshots written by an
	// earlier owner version.
	if state.RetentionLeases == nil {
		state.RetentionLeases = map[string]RetentionLease{}
	}
	return &owner{state: state, receipts: receipts, store: store}, nil
}

func (o *owner) providers() map[string]func([]byte) ([]byte, error) {
	return map[string]func([]byte) ([]byte, error){
		FnNativeRegister: o.nativeRegister, FnNativeAuthenticate: o.nativeAuthenticate,
		FnNativePasswordChange: o.passwordChange, FnNativeCredentialAttach: o.nativeCredentialAttach,
		FnPasswordResetIssue:   o.passwordResetIssue,
		FnPasswordResetConsume: o.passwordResetConsume, FnAccountDelete: o.accountDelete, FnAccountErase: o.accountErase,
		FnRetentionLeaseCreate: o.retentionLeaseCreate, FnRetentionLeaseRenew: o.retentionLeaseRenew,
		FnRetentionLeaseRelease: o.retentionLeaseRelease, FnRetentionLeaseList: o.retentionLeaseList,
		FnRetentionEligibility:   o.retentionEligibility,
		FnEmailVerificationIssue: o.emailVerificationIssue, FnEmailVerificationConsume: o.emailVerificationConsume,
		FnOAuthStateIssue: o.oauthStateIssue, FnOAuthStateConsume: o.oauthStateConsume,
		FnOAuthResolve: o.oauthResolve, FnOAuthUpsert: o.oauthUpsert,
		FnProfileCreate: o.profileCreate, FnProfileGet: o.profileGet, FnProfileUpdate: o.profileUpdate,
		FnRateCheck: o.rateCheck, FnRateClear: o.rateClear,
		FnLegacyImport: o.legacyImport,
		FnEffectsClaim: o.effectsClaim, FnEffectsAck: o.effectsAck, FnEffectsRetry: o.effectsRetry,
	}
}

type domainError struct{ code, message string }

func (e domainError) Error() string     { return e.message }
func domain(code, message string) error { return domainError{code: code, message: message} }

func (o *owner) command(operation, requestID string, request any, mutate func(*snapshot) (any, error)) ([]byte, error) {
	if strings.TrimSpace(requestID) == "" {
		return encode(failure[any]("invalid_request", "request_id is required"))
	}
	requestWire, err := msgpack.Marshal(request)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(requestWire)
	digest := hex.EncodeToString(sum[:])
	key := operation + ":" + requestID
	o.mu.Lock()
	defer o.mu.Unlock()
	if prior, ok := o.receipts[key]; ok {
		if prior.Digest != digest {
			return encode(failure[any]("idempotency_conflict", "request_id was reused with a different payload"))
		}
		return append([]byte(nil), prior.Response...), nil
	}
	next := o.state.clone()
	value, err := mutate(&next)
	if err != nil {
		if typed, ok := err.(domainError); ok {
			return encode(failure[any](typed.code, typed.message))
		}
		return nil, err
	}
	response, err := encode(success(value))
	if err != nil {
		return nil, err
	}
	receipt := commandReceipt{Operation: operation, RequestID: requestID, Digest: digest, Response: response}
	if err := o.store.Append(context.Background(), durableRecord{Receipt: receipt, Snapshot: next}); err != nil {
		return nil, fmt.Errorf("persist %s: %w", operation, err)
	}
	o.state, o.receipts[key] = next, receipt
	return response, nil
}

func (o *owner) commandRaw(operation, requestID string, request any, mutate func(*snapshot) (any, error)) ([]byte, error) {
	if strings.TrimSpace(requestID) == "" {
		return nil, fmt.Errorf("request_id is required")
	}
	requestWire, err := msgpack.Marshal(request)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(requestWire)
	digest := hex.EncodeToString(sum[:])
	key := operation + ":" + requestID
	o.mu.Lock()
	defer o.mu.Unlock()
	if prior, ok := o.receipts[key]; ok {
		if prior.Digest != digest {
			return nil, fmt.Errorf("request_id was reused with a different payload")
		}
		return append([]byte(nil), prior.Response...), nil
	}
	next := o.state.clone()
	value, err := mutate(&next)
	if err != nil {
		return nil, err
	}
	response, err := msgpack.Marshal(value)
	if err != nil {
		return nil, err
	}
	receipt := commandReceipt{Operation: operation, RequestID: requestID, Digest: digest, Response: response}
	if err := o.store.Append(context.Background(), durableRecord{Receipt: receipt, Snapshot: next}); err != nil {
		return nil, fmt.Errorf("persist %s: %w", operation, err)
	}
	o.state, o.receipts[key] = next, receipt
	return response, nil
}

func (o *owner) query(run func(snapshot) (any, error)) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	value, err := run(o.state)
	if err != nil {
		if typed, ok := err.(domainError); ok {
			return encode(failure[any](typed.code, typed.message))
		}
		return nil, err
	}
	return encode(success(value))
}

func (o *owner) nativeRegister(raw []byte) ([]byte, error) {
	var req NativeRegisterRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	req.Email = otpscope.NormalizeEmail(req.Email)
	return o.command(FnNativeRegister, req.RequestID, req, func(s *snapshot) (any, error) {
		if blank(req.AccountID) || blank(req.CredentialID) || blank(req.Email) || blank(req.Username) || len(req.Password) < 8 || req.Now <= 0 {
			return nil, domain("invalid_request", "native registration is incomplete")
		}
		if _, ok := s.NativeByEmail[req.Email]; ok {
			return nil, domain("email_taken", "An account with this email already exists")
		}
		if _, ok := s.Usernames[req.Username]; ok {
			return nil, domain("username_taken", "This username is already taken")
		}
		hash, err := passwordcrypto.Hash(req.Password)
		if err != nil {
			return nil, err
		}
		account := AccountProjection{AccountID: req.AccountID, Email: req.Email, Username: req.Username, CreatedAt: req.Now}
		credential := nativeCredential{ID: req.CredentialID, AccountID: req.AccountID, Email: req.Email, Username: req.Username, PasswordHash: hash, CreatedAt: req.Now}
		s.Accounts[req.AccountID], s.NativeByEmail[req.Email], s.NativeByAccount[req.AccountID], s.Usernames[req.Username] =
			account, credential, credential, req.AccountID
		return account, nil
	})
}

func (o *owner) nativeAuthenticate(raw []byte) ([]byte, error) {
	var req NativeAuthenticateRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	req.Email = otpscope.NormalizeEmail(req.Email)
	return o.query(func(s snapshot) (any, error) {
		credential, ok := s.NativeByEmail[req.Email]
		if !ok || !passwordcrypto.Verify(credential.PasswordHash, req.Password) {
			return nil, domain("invalid_credentials", "Invalid email or password")
		}
		return s.Accounts[credential.AccountID], nil
	})
}

func (o *owner) nativeCredentialAttach(raw []byte) ([]byte, error) {
	var req NativeCredentialAttachRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	req.Email = otpscope.NormalizeEmail(req.Email)
	return o.command(FnNativeCredentialAttach, req.RequestID, req, func(s *snapshot) (any, error) {
		account, exists := s.Accounts[req.AccountID]
		if !exists {
			return nil, domain("not_found", "account not found")
		}
		if blank(req.CredentialID) || blank(req.Email) || blank(req.Username) || len(req.Password) < 8 || req.Now <= 0 {
			return nil, domain("invalid_request", "native credential attach is incomplete")
		}
		if account.Email == "" || !strings.EqualFold(account.Email, req.Email) {
			return nil, domain("invalid_email", "native email must match the authenticated account")
		}
		if _, exists := s.NativeByAccount[req.AccountID]; exists {
			return nil, domain("native_exists", "account already has a native credential")
		}
		if existing, exists := s.NativeByEmail[req.Email]; exists && existing.AccountID != req.AccountID {
			return nil, domain("email_taken", "email is already attached to another account")
		}
		if existing, exists := s.Usernames[req.Username]; exists && existing != req.AccountID {
			return nil, domain("username_taken", "username is already taken")
		}
		hash, err := passwordcrypto.Hash(req.Password)
		if err != nil {
			return nil, err
		}
		credential := nativeCredential{ID: req.CredentialID, AccountID: req.AccountID, Email: req.Email, Username: req.Username, PasswordHash: hash, CreatedAt: req.Now}
		s.NativeByAccount[req.AccountID], s.NativeByEmail[req.Email], s.Usernames[req.Username] = credential, credential, req.AccountID
		account.Username = req.Username
		s.Accounts[req.AccountID] = account
		return account, nil
	})
}

func (o *owner) passwordChange(raw []byte) ([]byte, error) {
	var req PasswordChangeRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnNativePasswordChange, req.RequestID, req, func(s *snapshot) (any, error) {
		credential, ok := s.NativeByAccount[req.AccountID]
		if !ok {
			return nil, domain("not_found", "No native account found")
		}
		if !passwordcrypto.Verify(credential.PasswordHash, req.CurrentPassword) {
			return nil, domain("invalid_password", "Current password is incorrect")
		}
		if len(req.NewPassword) < 8 {
			return nil, domain("invalid_request", "new password is too short")
		}
		hash, err := passwordcrypto.Hash(req.NewPassword)
		if err != nil {
			return nil, err
		}
		credential.PasswordHash = hash
		s.NativeByAccount[req.AccountID], s.NativeByEmail[credential.Email] = credential, credential
		return map[string]any{"changed": true}, nil
	})
}

func (o *owner) passwordResetIssue(raw []byte) ([]byte, error) {
	var req PasswordResetIssueRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	req.Email = otpscope.NormalizeEmail(req.Email)
	return o.command(FnPasswordResetIssue, req.RequestID, req, func(s *snapshot) (any, error) {
		credential, exists := s.NativeByEmail[req.Email]
		if !exists {
			return PasswordResetIssueResult{Accepted: true}, nil
		}
		if blank(req.OTPID) || blank(req.EffectID) || blank(req.Code) || req.Now <= 0 || req.ExpiresAt <= req.Now {
			return nil, domain("invalid_request", "password reset issue is incomplete")
		}
		for id, value := range s.OTPs {
			if value.Email == req.Email && value.Type == "password_reset" {
				delete(s.OTPs, id)
			}
		}
		s.OTPs[req.OTPID] = otpRecord{ID: req.OTPID, Email: req.Email, Code: strings.ToUpper(req.Code), Type: "password_reset", ExpiresAt: req.ExpiresAt, AccountID: credential.AccountID}
		intent, err := effect.NewIntent(req.EffectID, effect.KindNotificationEmailSend, req.EffectID, notificationEmailPayload{
			To:      req.Email,
			Subject: "Password reset code",
			Text:    fmt.Sprintf("Your reset code: %s\nExpires in 10 minutes.", strings.ToUpper(req.Code)),
		})
		if err != nil {
			return nil, err
		}
		s.Effects[intent.ID] = ownerEffect{Intent: intent, Status: string(effect.Pending), AvailableAt: req.Now}
		return PasswordResetIssueResult{Accepted: true, EffectQueued: true}, nil
	})
}

func (o *owner) passwordResetConsume(raw []byte) ([]byte, error) {
	var req PasswordResetConsumeRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	req.Email = otpscope.NormalizeEmail(req.Email)
	return o.command(FnPasswordResetConsume, req.RequestID, req, func(s *snapshot) (any, error) {
		var id string
		var otp otpRecord
		for key, candidate := range s.OTPs {
			if candidate.Email == req.Email && candidate.Type == "password_reset" && candidate.Code == strings.ToUpper(req.Code) && candidate.ExpiresAt > req.Now {
				id, otp = key, candidate
				break
			}
		}
		if id == "" {
			return nil, domain("invalid_code", "Invalid or expired reset code")
		}
		credential, ok := s.NativeByAccount[otp.AccountID]
		if !ok {
			return nil, domain("not_found", "native account not found")
		}
		hash, err := passwordcrypto.Hash(req.NewPassword)
		if err != nil {
			return nil, err
		}
		delete(s.OTPs, id)
		credential.PasswordHash = hash
		s.NativeByAccount[credential.AccountID], s.NativeByEmail[credential.Email] = credential, credential
		delete(s.Rates, "password_reset_email:"+req.Email)
		return map[string]any{"changed": true}, nil
	})
}

func (o *owner) emailVerificationIssue(raw []byte) ([]byte, error) {
	var req EmailVerificationIssueRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	req.Email = otpscope.NormalizeEmail(req.Email)
	return o.command(FnEmailVerificationIssue, req.RequestID, req, func(s *snapshot) (any, error) {
		if blank(req.VerificationID) || blank(req.EffectID) || blank(req.Email) || blank(req.Code) || req.Now <= 0 || req.ExpiresAt <= req.Now {
			return nil, domain("invalid_request", "email verification issue is incomplete")
		}
		for id, value := range s.OTPs {
			if value.Email == req.Email && value.Type == "sessions_email_verification" {
				delete(s.OTPs, id)
			}
		}
		s.OTPs[req.VerificationID] = otpRecord{ID: req.VerificationID, Email: req.Email, Code: strings.ToUpper(req.Code), Type: "sessions_email_verification", ExpiresAt: req.ExpiresAt}
		intent, err := effect.NewIntent(req.EffectID, effect.KindNotificationEmailSend, req.EffectID, notificationEmailPayload{
			To: req.Email, Subject: "Your Sessions verification code",
			Text: fmt.Sprintf("Your verification code: %s\nExpires in 30 minutes.", strings.ToUpper(req.Code)),
		})
		if err != nil {
			return nil, err
		}
		s.Effects[intent.ID] = ownerEffect{Intent: intent, Status: string(effect.Pending), AvailableAt: req.Now}
		return EmailVerificationIssueResult{Accepted: true, EffectQueued: true}, nil
	})
}

func (o *owner) emailVerificationConsume(raw []byte) ([]byte, error) {
	var req EmailVerificationConsumeRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	req.Email = otpscope.NormalizeEmail(req.Email)
	return o.command(FnEmailVerificationConsume, req.RequestID, req, func(s *snapshot) (any, error) {
		for id, value := range s.OTPs {
			if value.Email == req.Email && value.Type == "sessions_email_verification" && value.Code == strings.ToUpper(req.Code) && value.ExpiresAt > req.Now {
				accountID := accountIDForEmail(s, req.Email)
				if accountID == "" {
					if blank(req.AccountID) {
						return nil, domain("invalid_request", "email verification account id is required for a new identity")
					}
					accountID = req.AccountID
					s.Accounts[accountID] = AccountProjection{AccountID: accountID, Email: req.Email, CreatedAt: req.Now}
				}
				delete(s.OTPs, id)
				return EmailVerificationConsumeResult{Verified: true, AccountID: accountID}, nil
			}
		}
		return nil, domain("invalid_code", "invalid or expired verification code")
	})
}

// accountIDForEmail deliberately scans the small owner-local projection
// rather than introducing a second mutable email index. Native and OAuth
// accounts already persist their canonical email in this projection.
func accountIDForEmail(s *snapshot, email string) string {
	for accountID, account := range s.Accounts {
		if strings.EqualFold(account.Email, email) {
			return accountID
		}
	}
	return ""
}

func (o *owner) accountDelete(raw []byte) ([]byte, error) {
	var req AccountDeleteRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	req.Email = otpscope.NormalizeEmail(req.Email)
	return o.command(FnAccountDelete, req.RequestID, req, func(s *snapshot) (any, error) {
		account, ok := s.Accounts[req.AccountID]
		if !ok {
			return nil, domain("not_found", "No account found")
		}
		live := activeRetentionLeases(s, req.AccountID, req.Now)
		if len(live) != 0 {
			return nil, domain("retention_active", "account has active retention leases")
		}
		if native, ok := s.NativeByAccount[req.AccountID]; ok {
			if !passwordcrypto.Verify(native.PasswordHash, req.Password) {
				return nil, domain("invalid_password", "Password is incorrect")
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
				return nil, domain("invalid_email", "Email does not match account")
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
		delete(s.Accounts, req.AccountID)
		return account, nil
	})
}

// accountErase is deliberately distinct from user-initiated accountDelete.
// Its authority is supplied by Pulp's exact provider manifest, and it still
// performs the retention check in the same owner transaction as deletion so a
// concurrently renewed application lease always wins.
func (o *owner) accountErase(raw []byte) ([]byte, error) {
	var req AccountEraseRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnAccountErase, req.RequestID, req, func(s *snapshot) (any, error) {
		if blank(req.AccountID) || blank(req.ReasonID) || req.Now <= 0 {
			return nil, domain("invalid_request", "account_id, reason_id, and now are required")
		}
		account, ok := s.Accounts[req.AccountID]
		if !ok {
			return nil, domain("not_found", "No account found")
		}
		if live := activeRetentionLeases(s, req.AccountID, req.Now); len(live) != 0 {
			return nil, domain("retention_active", "account has active retention leases")
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

func (o *owner) retentionLeaseCreate(raw []byte) ([]byte, error) {
	var req RetentionLeaseCreateRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnRetentionLeaseCreate, req.RequestID, req, func(s *snapshot) (any, error) {
		if err := validateRetentionLease(req.Lease, req.Now); err != nil {
			return nil, err
		}
		if _, ok := s.Accounts[req.Lease.AccountID]; !ok {
			return nil, domain("not_found", "No account found")
		}
		key := retentionLeaseKey(req.Lease.AccountID, req.Lease.LeaseID)
		if _, exists := s.RetentionLeases[key]; exists {
			return nil, domain("conflict", "retention lease already exists")
		}
		s.RetentionLeases[key] = req.Lease
		return req.Lease, nil
	})
}

func (o *owner) retentionLeaseRenew(raw []byte) ([]byte, error) {
	var req RetentionLeaseRenewRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnRetentionLeaseRenew, req.RequestID, req, func(s *snapshot) (any, error) {
		if err := validateRetentionLease(req.Lease, req.Now); err != nil {
			return nil, err
		}
		key := retentionLeaseKey(req.Lease.AccountID, req.Lease.LeaseID)
		prior, exists := s.RetentionLeases[key]
		if !exists || prior.ExpiresAt <= req.Now {
			return nil, domain("not_found", "retention lease not found")
		}
		if prior.ReasonID != req.Lease.ReasonID {
			return nil, domain("conflict", "retention lease reason cannot change")
		}
		s.RetentionLeases[key] = req.Lease
		return req.Lease, nil
	})
}

func (o *owner) retentionLeaseRelease(raw []byte) ([]byte, error) {
	var req RetentionLeaseReleaseRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnRetentionLeaseRelease, req.RequestID, req, func(s *snapshot) (any, error) {
		if blank(req.AccountID) || blank(req.LeaseID) || blank(req.ReasonID) {
			return nil, domain("invalid_request", "account_id, lease_id, and reason_id are required")
		}
		key := retentionLeaseKey(req.AccountID, req.LeaseID)
		lease, exists := s.RetentionLeases[key]
		if !exists || lease.ExpiresAt <= req.Now {
			delete(s.RetentionLeases, key)
			return RetentionEligibility{Deletable: len(activeRetentionLeases(s, req.AccountID, req.Now)) == 0}, nil
		}
		if lease.ReasonID != req.ReasonID {
			return nil, domain("conflict", "retention lease reason does not match")
		}
		delete(s.RetentionLeases, key)
		live := activeRetentionLeases(s, req.AccountID, req.Now)
		return RetentionEligibility{Deletable: len(live) == 0, LiveLeases: live}, nil
	})
}

func (o *owner) retentionLeaseList(raw []byte) ([]byte, error) {
	var req RetentionLeaseListRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.query(func(s snapshot) (any, error) {
		if blank(req.AccountID) {
			return nil, domain("invalid_request", "account_id is required")
		}
		return RetentionLeaseListResult{Leases: activeRetentionLeases(&s, req.AccountID, req.Now)}, nil
	})
}

func (o *owner) retentionEligibility(raw []byte) ([]byte, error) {
	var req RetentionEligibilityRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.query(func(s snapshot) (any, error) {
		if blank(req.AccountID) {
			return nil, domain("invalid_request", "account_id is required")
		}
		live := activeRetentionLeases(&s, req.AccountID, req.Now)
		return RetentionEligibility{Deletable: len(live) == 0, LiveLeases: live}, nil
	})
}

func (o *owner) oauthStateIssue(raw []byte) ([]byte, error) {
	var req OAuthStateIssueRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnOAuthStateIssue, req.RequestID, req, func(s *snapshot) (any, error) {
		if blank(req.State.State) || blank(req.State.Provider) || req.State.ExpiresAt <= 0 {
			return nil, domain("invalid_request", "OAuth state is incomplete")
		}
		if _, exists := s.OAuthStates[req.State.State]; exists {
			return nil, domain("conflict", "OAuth state already exists")
		}
		s.OAuthStates[req.State.State] = req.State
		return req.State, nil
	})
}

func (o *owner) oauthStateConsume(raw []byte) ([]byte, error) {
	var req OAuthStateConsumeRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnOAuthStateConsume, req.RequestID, req, func(s *snapshot) (any, error) {
		value, ok := s.OAuthStates[req.State]
		if !ok || value.ConsumedAt != 0 || value.ExpiresAt <= req.Now || value.Provider != req.Provider || value.RedirectBinding != req.RedirectBinding {
			return nil, domain("invalid_state", "OAuth state mismatch or expired")
		}
		value.ConsumedAt = req.Now
		s.OAuthStates[req.State] = value
		return value, nil
	})
}

func oauthKey(provider, id string) string { return provider + "\x00" + id }

func (o *owner) oauthResolve(raw []byte) ([]byte, error) {
	var req OAuthResolveRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.query(func(s snapshot) (any, error) {
		link, ok := s.OAuthLinks[oauthKey(req.Provider, req.ProviderID)]
		if !ok {
			return nil, domain("not_found", "OAuth link not found")
		}
		return s.Accounts[link.AccountID], nil
	})
}

func (o *owner) oauthUpsert(raw []byte) ([]byte, error) {
	var req OAuthUpsertRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnOAuthUpsert, req.RequestID, req, func(s *snapshot) (any, error) {
		key := oauthKey(req.Provider, req.ProviderID)
		if link, ok := s.OAuthLinks[key]; ok {
			return OAuthUpsertResult{Account: s.Accounts[link.AccountID]}, nil
		}
		if blank(req.AccountID) || blank(req.LinkID) || blank(req.Provider) || blank(req.ProviderID) || req.Now <= 0 {
			return nil, domain("invalid_request", "OAuth identity is incomplete")
		}
		account := AccountProjection{AccountID: req.AccountID, Email: req.ProviderEmail, CreatedAt: req.Now}
		s.Accounts[req.AccountID] = account
		s.OAuthLinks[key] = oauthLink{ID: req.LinkID, AccountID: req.AccountID, Provider: req.Provider, ProviderID: req.ProviderID, ProviderEmail: req.ProviderEmail, CreatedAt: req.Now}
		return OAuthUpsertResult{Account: account, Created: true}, nil
	})
}

func (o *owner) profileCreate(raw []byte) ([]byte, error) {
	var req ProfileCreateRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnProfileCreate, req.RequestID, req, func(s *snapshot) (any, error) {
		if _, ok := s.Accounts[req.Profile.AccountID]; !ok {
			return nil, domain("not_found", "account not found")
		}
		if _, ok := s.Profiles[req.Profile.AccountID]; ok {
			return nil, domain("profile_exists", "Profile already exists for this account")
		}
		if blank(req.Profile.DisplayName) || req.Profile.CreatedAt <= 0 {
			return nil, domain("invalid_request", "profile is incomplete")
		}
		s.Profiles[req.Profile.AccountID] = req.Profile
		return req.Profile, nil
	})
}

func (o *owner) profileGet(raw []byte) ([]byte, error) {
	var req ProfileGetRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.query(func(s snapshot) (any, error) {
		value, ok := s.Profiles[req.AccountID]
		if !ok {
			return nil, domain("not_found", "Profile not found")
		}
		return value, nil
	})
}

func (o *owner) profileUpdate(raw []byte) ([]byte, error) {
	var req ProfileUpdateRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnProfileUpdate, req.RequestID, req, func(s *snapshot) (any, error) {
		value, ok := s.Profiles[req.AccountID]
		if !ok {
			return nil, domain("not_found", "Profile not found")
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

func (o *owner) rateCheck(raw []byte) ([]byte, error) {
	var req RateCheckRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnRateCheck, req.RequestID, req, func(s *snapshot) (any, error) {
		if blank(req.Scope) || blank(req.Key) || req.Now <= 0 || req.WindowMillis <= 0 || req.MaxAttempts <= 0 {
			return nil, domain("invalid_request", "rate check is incomplete")
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

func (o *owner) rateClear(raw []byte) ([]byte, error) {
	var req RateClearRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnRateClear, req.RequestID, req, func(s *snapshot) (any, error) {
		delete(s.Rates, rateKey(req.Scope, req.Key))
		return map[string]any{"cleared": true}, nil
	})
}

func (o *owner) legacyImport(raw []byte) ([]byte, error) {
	var req LegacyImportRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.command(FnLegacyImport, req.RequestID, req, func(s *snapshot) (any, error) {
		next := s.clone()
		for _, account := range req.Accounts {
			if blank(account.AccountID) || account.CreatedAt <= 0 {
				return nil, domain("invalid_import", "legacy account is incomplete")
			}
			if prior, ok := next.Accounts[account.AccountID]; ok && prior != account {
				return nil, domain("import_conflict", "legacy account conflicts with owner state")
			}
			next.Accounts[account.AccountID] = account
		}
		for _, row := range req.Native {
			row.Email = otpscope.NormalizeEmail(row.Email)
			if blank(row.ID) || blank(row.AccountID) || blank(row.Email) || blank(row.Username) || blank(row.PasswordHash) {
				return nil, domain("invalid_import", "legacy native credential is incomplete")
			}
			value := nativeCredential(row)
			if prior, ok := next.NativeByEmail[row.Email]; ok && prior != value {
				return nil, domain("import_conflict", "legacy native email conflicts with owner state")
			}
			if prior, ok := next.NativeByAccount[row.AccountID]; ok && prior != value {
				return nil, domain("import_conflict", "legacy account has conflicting native credentials")
			}
			if ownerID, ok := next.Usernames[row.Username]; ok && ownerID != row.AccountID {
				return nil, domain("import_conflict", "legacy username conflicts with owner state")
			}
			if _, ok := next.Accounts[row.AccountID]; !ok {
				return nil, domain("invalid_import", "legacy native credential references a missing account")
			}
			next.NativeByEmail[row.Email], next.NativeByAccount[row.AccountID], next.Usernames[row.Username] = value, value, row.AccountID
		}
		for _, row := range req.OAuthLinks {
			value := oauthLink(row)
			key := oauthKey(row.Provider, row.ProviderID)
			if _, ok := next.Accounts[row.AccountID]; !ok {
				return nil, domain("invalid_import", "legacy OAuth link references a missing account")
			}
			if prior, ok := next.OAuthLinks[key]; ok && prior != value {
				return nil, domain("import_conflict", "legacy OAuth link conflicts with owner state")
			}
			next.OAuthLinks[key] = value
		}
		for _, row := range req.OTPs {
			row.Email = otpscope.NormalizeEmail(row.Email)
			value := otpRecord{ID: row.ID, Email: row.Email, Code: strings.ToUpper(row.Code), Type: row.Type, ExpiresAt: row.ExpiresAt, AccountID: row.AccountID}
			if row.AccountID != "" {
				if _, ok := next.Accounts[row.AccountID]; !ok {
					return nil, domain("invalid_import", "legacy OTP references a missing account")
				}
			}
			if prior, ok := next.OTPs[row.ID]; ok && prior != value {
				return nil, domain("import_conflict", "legacy OTP conflicts with owner state")
			}
			next.OTPs[row.ID] = value
		}
		for _, profile := range req.Profiles {
			if _, ok := next.Accounts[profile.AccountID]; !ok {
				return nil, domain("invalid_import", "legacy profile references a missing account")
			}
			if prior, ok := next.Profiles[profile.AccountID]; ok && prior != profile {
				return nil, domain("import_conflict", "legacy profile conflicts with owner state")
			}
			next.Profiles[profile.AccountID] = profile
		}
		*s = next
		return LegacyImportResult{Accounts: len(req.Accounts), Native: len(req.Native), OAuthLinks: len(req.OAuthLinks), OTPs: len(req.OTPs), Profiles: len(req.Profiles)}, nil
	})
}

const effectOwner = "auth-identity"

func leaseToken(id, consumer string, until int64, attempt uint32) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%d", id, consumer, until, attempt)))
	return hex.EncodeToString(sum[:])
}

func (o *owner) effectsClaim(raw []byte) ([]byte, error) {
	var req effect.ClaimRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if err := req.Validate(); err != nil || req.Owner != effectOwner {
		return nil, fmt.Errorf("invalid identity effect claim")
	}
	now := time.Now().UTC().UnixMilli()
	requestID := fmt.Sprintf("%s:%d", req.ConsumerID, time.Now().UTC().UnixNano())
	return o.commandRaw(FnEffectsClaim, requestID, req, func(s *snapshot) (any, error) {
		ids := make([]string, 0, len(s.Effects))
		for id := range s.Effects {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		leases := []effect.Lease{}
		for _, id := range ids {
			record := s.Effects[id]
			if record.Status != string(effect.Pending) || record.AvailableAt > now || (record.Lease != nil && record.Lease.LeasedUntilUnixMilli > now) {
				continue
			}
			attempt := record.Attempts + 1
			until := now + req.LeaseDurationMillis
			lease := effect.Lease{Version: effect.OutboxVersionV1, Owner: effectOwner, ConsumerID: req.ConsumerID, LeaseID: leaseToken(id, req.ConsumerID, until, attempt), Attempt: attempt, LeasedUntilUnixMilli: until, Intent: record.Intent}
			record.Lease = &lease
			record.Attempts = attempt
			s.Effects[id] = record
			leases = append(leases, lease)
			if uint32(len(leases)) == req.Limit {
				break
			}
		}
		return effect.ClaimResult{Version: effect.OutboxVersionV1, Owner: effectOwner, ConsumerID: req.ConsumerID, Leases: leases}, nil
	})
}

func (o *owner) effectsAck(raw []byte) ([]byte, error) {
	var req effect.AcknowledgeRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.commandRaw(FnEffectsAck, "ack:"+req.LeaseID, req, func(s *snapshot) (any, error) {
		for id, record := range s.Effects {
			if record.Lease == nil || record.Lease.LeaseID != req.LeaseID {
				continue
			}
			if err := req.ValidateFor(*record.Lease); err != nil {
				return nil, err
			}
			record.Receipt, record.LastLeaseID, record.LastConsumerID, record.Lease = &req.Receipt, req.LeaseID, req.ConsumerID, nil
			record.Status = string(req.Receipt.Status)
			s.Effects[id] = record
			return effect.SettlementResult{Version: effect.OutboxVersionV1, Owner: effectOwner, ConsumerID: req.ConsumerID, LeaseID: req.LeaseID, Settled: true}, nil
		}
		for _, record := range s.Effects {
			if record.LastLeaseID == req.LeaseID && record.LastConsumerID == req.ConsumerID && record.Receipt != nil && reflect.DeepEqual(*record.Receipt, req.Receipt) {
				return effect.SettlementResult{Version: effect.OutboxVersionV1, Owner: effectOwner, ConsumerID: req.ConsumerID, LeaseID: req.LeaseID, Settled: true}, nil
			}
		}
		return effect.SettlementResult{Version: effect.OutboxVersionV1, Owner: effectOwner, ConsumerID: req.ConsumerID, LeaseID: req.LeaseID}, nil
	})
}

func (o *owner) effectsRetry(raw []byte) ([]byte, error) {
	var req effect.RetryRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	return o.commandRaw(FnEffectsRetry, "retry:"+req.LeaseID, req, func(s *snapshot) (any, error) {
		for id, record := range s.Effects {
			if record.Lease == nil || record.Lease.LeaseID != req.LeaseID {
				continue
			}
			if err := req.ValidateFor(*record.Lease); err != nil {
				return nil, err
			}
			record.AvailableAt, record.LastLeaseID, record.LastConsumerID, record.Lease = req.RetryAtUnixMilli, req.LeaseID, req.ConsumerID, nil
			s.Effects[id] = record
			return effect.SettlementResult{Version: effect.OutboxVersionV1, Owner: effectOwner, ConsumerID: req.ConsumerID, LeaseID: req.LeaseID, Settled: true}, nil
		}
		return effect.SettlementResult{Version: effect.OutboxVersionV1, Owner: effectOwner, ConsumerID: req.ConsumerID, LeaseID: req.LeaseID}, nil
	})
}

func success[T any](value T) Result[T] {
	return Result[T]{Version: ContractVersion, OK: true, Value: value}
}
func failure[T any](code, message string) Result[T] {
	return Result[T]{Version: ContractVersion, Error: &Error{Code: code, Message: message}}
}
func blank(value string) bool { return strings.TrimSpace(value) == "" }
func decode(raw []byte, value any) error {
	if len(raw) == 0 {
		return fmt.Errorf("empty request")
	}
	if err := msgpack.Unmarshal(raw, value); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	return nil
}
func encode(value any) ([]byte, error) { return msgpack.Marshal(value) }
