package main

import "github.com/BananaLabs-OSS/Fiber/pulp/effect"

const ContractVersion = "auth-identity.v1"

const (
	FnNativeRegister         = "auth.identity.v1.native.register"
	FnNativeAuthenticate     = "auth.identity.v1.native.authenticate"
	FnNativePasswordChange   = "auth.identity.v1.native.password.change"
	FnNativeCredentialAttach = "auth.identity.v1.native.attach"
	FnPasswordResetIssue     = "auth.identity.v1.password-reset.issue"
	FnPasswordResetConsume   = "auth.identity.v1.password-reset.consume"
	// Email verification is deliberately separate from password reset. Sessions
	// uses it for passwordless human login, so it must not depend on a native
	// account or mutate password-reset state.
	FnEmailVerificationIssue   = "auth.identity.v1.email-verification.issue"
	FnEmailVerificationConsume = "auth.identity.v1.email-verification.consume"
	FnAccountDelete            = "auth.identity.v1.account.delete"
	// AccountErase is a manifest-authorized automated erasure path. Unlike
	// account.delete it does not accept user credentials; it rechecks generic
	// retention eligibility at the owner transaction boundary instead.
	FnAccountErase = "auth.identity.v1.account.erase"
	// Retention leases are deliberately application-neutral. An application
	// supplies opaque lease/reason IDs and its own expiry policy; the identity
	// owner only answers whether deletion is currently safe.
	FnRetentionLeaseCreate  = "auth.identity.v1.retention-lease.create"
	FnRetentionLeaseRenew   = "auth.identity.v1.retention-lease.renew"
	FnRetentionLeaseRelease = "auth.identity.v1.retention-lease.release"
	FnRetentionLeaseList    = "auth.identity.v1.retention-lease.list"
	FnRetentionEligibility  = "auth.identity.v1.retention-eligibility.get"
	FnOAuthStateIssue       = "auth.identity.v1.oauth-state.issue"
	FnOAuthStateConsume     = "auth.identity.v1.oauth-state.consume"
	FnOAuthResolve          = "auth.identity.v1.oauth.resolve"
	FnOAuthUpsert           = "auth.identity.v1.oauth.upsert"
	FnProfileCreate         = "auth.identity.v1.profile.create"
	FnProfileGet            = "auth.identity.v1.profile.get"
	FnProfileUpdate         = "auth.identity.v1.profile.update"
	FnRateCheck             = "auth.identity.v1.rate.check"
	FnRateClear             = "auth.identity.v1.rate.clear"
	FnLegacyImport          = "auth.identity.v1.legacy.import"
	FnEffectsClaim          = "auth.identity.effects.v1.claim"
	FnEffectsAck            = "auth.identity.effects.v1.acknowledge"
	FnEffectsRetry          = "auth.identity.effects.v1.retry"
)

type Error struct {
	Code    string `msgpack:"code"`
	Message string `msgpack:"message"`
}

type Result[T any] struct {
	Version string `msgpack:"version"`
	OK      bool   `msgpack:"ok"`
	Value   T      `msgpack:"value,omitempty"`
	Error   *Error `msgpack:"error,omitempty"`
}

type AccountProjection struct {
	AccountID string `msgpack:"account_id"`
	Email     string `msgpack:"email,omitempty"`
	Username  string `msgpack:"username,omitempty"`
	CreatedAt int64  `msgpack:"created_at"`
}

type NativeRegisterRequest struct {
	RequestID    string `msgpack:"request_id"`
	AccountID    string `msgpack:"account_id"`
	CredentialID string `msgpack:"credential_id"`
	Email        string `msgpack:"email"`
	Username     string `msgpack:"username"`
	Password     string `msgpack:"password"`
	Now          int64  `msgpack:"now"`
}

type NativeAuthenticateRequest struct {
	Email    string `msgpack:"email"`
	Password string `msgpack:"password"`
}

type PasswordChangeRequest struct {
	RequestID       string `msgpack:"request_id"`
	AccountID       string `msgpack:"account_id"`
	CurrentPassword string `msgpack:"current_password"`
	NewPassword     string `msgpack:"new_password"`
	Now             int64  `msgpack:"now"`
}

// NativeCredentialAttachRequest adds a password credential to an existing
// OAuth-created account. It never creates or replaces the account identity.
type NativeCredentialAttachRequest struct {
	RequestID    string `msgpack:"request_id"`
	AccountID    string `msgpack:"account_id"`
	CredentialID string `msgpack:"credential_id"`
	Email        string `msgpack:"email"`
	Username     string `msgpack:"username"`
	Password     string `msgpack:"password"`
	Now          int64  `msgpack:"now"`
}

type PasswordResetIssueRequest struct {
	RequestID string `msgpack:"request_id"`
	OTPID     string `msgpack:"otp_id"`
	EffectID  string `msgpack:"effect_id"`
	Email     string `msgpack:"email"`
	Code      string `msgpack:"code"`
	ExpiresAt int64  `msgpack:"expires_at"`
	Now       int64  `msgpack:"now"`
}

type PasswordResetIssueResult struct {
	Accepted     bool `msgpack:"accepted"`
	EffectQueued bool `msgpack:"effect_queued"`
}

type PasswordResetConsumeRequest struct {
	RequestID   string `msgpack:"request_id"`
	Email       string `msgpack:"email"`
	Code        string `msgpack:"code"`
	NewPassword string `msgpack:"new_password"`
	Now         int64  `msgpack:"now"`
}

// EmailVerificationIssueRequest creates one single-use, time-bounded
// passwordless verification code and queues its delivery through the owner's
// generic notification outbox. The caller supplies identifiers so retries are
// deterministic and the owner never invents an ambient identity.
type EmailVerificationIssueRequest struct {
	RequestID      string `msgpack:"request_id"`
	VerificationID string `msgpack:"verification_id"`
	EffectID       string `msgpack:"effect_id"`
	Email          string `msgpack:"email"`
	Code           string `msgpack:"code"`
	Now            int64  `msgpack:"now"`
	ExpiresAt      int64  `msgpack:"expires_at"`
}

type EmailVerificationIssueResult struct {
	Accepted     bool `msgpack:"accepted"`
	EffectQueued bool `msgpack:"effect_queued"`
}

// EmailVerificationConsumeRequest validates and consumes one Sessions human
// login code. AccountID is supplied by the composed adapter only when this is
// the first passwordless login for an email. The owner reuses an existing
// account for that email, so a later login never forks the identity. The
// caller-supplied identifier keeps account creation deterministic under a
// retried command; the owner never invents ambient account IDs.
type EmailVerificationConsumeRequest struct {
	RequestID string `msgpack:"request_id"`
	AccountID string `msgpack:"account_id,omitempty"`
	Email     string `msgpack:"email"`
	Code      string `msgpack:"code"`
	Now       int64  `msgpack:"now"`
}

type EmailVerificationConsumeResult struct {
	Verified  bool   `msgpack:"verified"`
	AccountID string `msgpack:"account_id"`
}

type AccountDeleteRequest struct {
	RequestID string `msgpack:"request_id"`
	AccountID string `msgpack:"account_id"`
	Password  string `msgpack:"password,omitempty"`
	Email     string `msgpack:"email,omitempty"`
	Now       int64  `msgpack:"now"`
}

// AccountEraseRequest is for a trusted application policy such as Sessions'
// explicitly enabled expiry sweep. ReasonID is opaque and not interpreted by
// Bananauth. Provider authority, not a caller-supplied boolean, controls who
// may invoke it.
type AccountEraseRequest struct {
	RequestID string `msgpack:"request_id"`
	AccountID string `msgpack:"account_id"`
	ReasonID  string `msgpack:"reason_id"`
	Now       int64  `msgpack:"now"`
}

// RetentionLease is a caller-named, opaque retention claim on an identity.
// ReasonID is never interpreted by Bananauth. ExpiresAt is supplied by the
// application and may include whatever grace period its policy requires.
type RetentionLease struct {
	AccountID string `msgpack:"account_id"`
	LeaseID   string `msgpack:"lease_id"`
	ReasonID  string `msgpack:"reason_id"`
	ExpiresAt int64  `msgpack:"expires_at"`
}

type RetentionLeaseCreateRequest struct {
	RequestID string         `msgpack:"request_id"`
	Lease     RetentionLease `msgpack:"lease"`
	Now       int64          `msgpack:"now"`
}

type RetentionLeaseRenewRequest = RetentionLeaseCreateRequest

type RetentionLeaseReleaseRequest struct {
	RequestID string `msgpack:"request_id"`
	AccountID string `msgpack:"account_id"`
	LeaseID   string `msgpack:"lease_id"`
	ReasonID  string `msgpack:"reason_id"`
	Now       int64  `msgpack:"now"`
}

type RetentionLeaseListRequest struct {
	AccountID string `msgpack:"account_id"`
	Now       int64  `msgpack:"now"`
}

type RetentionLeaseListResult struct {
	Leases []RetentionLease `msgpack:"leases"`
}

type RetentionEligibilityRequest = RetentionLeaseListRequest

type RetentionEligibility struct {
	Deletable  bool             `msgpack:"deletable"`
	LiveLeases []RetentionLease `msgpack:"live_leases"`
}

type OAuthState struct {
	State           string `msgpack:"state"`
	Provider        string `msgpack:"provider"`
	RedirectBinding string `msgpack:"redirect_binding"`
	ExpiresAt       int64  `msgpack:"expires_at"`
	ConsumedAt      int64  `msgpack:"consumed_at,omitempty"`
}

type OAuthStateIssueRequest struct {
	RequestID string     `msgpack:"request_id"`
	State     OAuthState `msgpack:"state"`
}

type OAuthStateConsumeRequest struct {
	RequestID       string `msgpack:"request_id"`
	State           string `msgpack:"state"`
	Provider        string `msgpack:"provider"`
	RedirectBinding string `msgpack:"redirect_binding"`
	Now             int64  `msgpack:"now"`
}

type OAuthResolveRequest struct {
	Provider   string `msgpack:"provider"`
	ProviderID string `msgpack:"provider_id"`
}

type OAuthUpsertRequest struct {
	RequestID     string `msgpack:"request_id"`
	AccountID     string `msgpack:"account_id"`
	LinkID        string `msgpack:"link_id"`
	Provider      string `msgpack:"provider"`
	ProviderID    string `msgpack:"provider_id"`
	ProviderEmail string `msgpack:"provider_email"`
	Now           int64  `msgpack:"now"`
}

type OAuthUpsertResult struct {
	Account AccountProjection `msgpack:"account"`
	Created bool              `msgpack:"created"`
}

// ExternalServiceCredentialContractVersion describes non-secret ownership
// metadata for a provider-backed service credential. The credential material
// itself is deliberately outside this contract: it must remain in a sealed
// host capability and is never passed through an identity provider, Lua, or
// HTTP projection.
const ExternalServiceCredentialContractVersion = "auth.external-service-credential.v1"

// ExternalServiceCredentialReference is an opaque owner-issued handle. The
// provider identifies the external protocol, while ID identifies one sealed
// credential without revealing its material.
type ExternalServiceCredentialReference struct {
	ID       string `msgpack:"id" json:"id"`
	Provider string `msgpack:"provider" json:"provider"`
}

// ExternalServiceCredentialStatus describes only lifecycle state. It never
// implies that a caller can retrieve credential material.
type ExternalServiceCredentialStatus string

const (
	ExternalServiceCredentialPending ExternalServiceCredentialStatus = "pending"
	ExternalServiceCredentialActive  ExternalServiceCredentialStatus = "active"
	ExternalServiceCredentialExpired ExternalServiceCredentialStatus = "expired"
	ExternalServiceCredentialRevoked ExternalServiceCredentialStatus = "revoked"
	ExternalServiceCredentialFailed  ExternalServiceCredentialStatus = "failed"
)

// ExternalServiceCredentialMetadata is safe to persist, compare, and return
// to an application adapter. SubjectID is a provider's non-secret stable
// subject/profile identifier, never an OAuth access or refresh token.
type ExternalServiceCredentialMetadata struct {
	Version        string                             `msgpack:"version" json:"version"`
	Reference      ExternalServiceCredentialReference `msgpack:"reference" json:"reference"`
	SubjectID      string                             `msgpack:"subject_id,omitempty" json:"subject_id,omitempty"`
	Status         ExternalServiceCredentialStatus    `msgpack:"status" json:"status"`
	Revision       uint64                             `msgpack:"revision" json:"revision"`
	CreatedAt      int64                              `msgpack:"created_at" json:"created_at"`
	UpdatedAt      int64                              `msgpack:"updated_at" json:"updated_at"`
	ExpiresAt      int64                              `msgpack:"expires_at,omitempty" json:"expires_at,omitempty"`
	LastVerifiedAt int64                              `msgpack:"last_verified_at,omitempty" json:"last_verified_at,omitempty"`
}

// ExternalServiceCredentialDescribeRequest is the adapter-facing read DTO.
// It can yield metadata only; a future sealed-credential host boundary is
// responsible for material access on behalf of a protocol adapter.
type ExternalServiceCredentialDescribeRequest struct {
	Reference ExternalServiceCredentialReference `msgpack:"reference" json:"reference"`
	Now       int64                              `msgpack:"now" json:"now"`
}

type ExternalServiceCredentialDescribeResult struct {
	Metadata ExternalServiceCredentialMetadata `msgpack:"metadata" json:"metadata"`
}

// ExternalServiceCredentialObserveRequest records a provider adapter's
// non-secret lifecycle observation after it has performed protocol work.
// There is intentionally no credential payload field.
type ExternalServiceCredentialObserveRequest struct {
	RequestID      string                             `msgpack:"request_id" json:"request_id"`
	Reference      ExternalServiceCredentialReference `msgpack:"reference" json:"reference"`
	SubjectID      string                             `msgpack:"subject_id,omitempty" json:"subject_id,omitempty"`
	Status         ExternalServiceCredentialStatus    `msgpack:"status" json:"status"`
	Revision       uint64                             `msgpack:"revision" json:"revision"`
	ObservedAt     int64                              `msgpack:"observed_at" json:"observed_at"`
	ExpiresAt      int64                              `msgpack:"expires_at,omitempty" json:"expires_at,omitempty"`
	LastVerifiedAt int64                              `msgpack:"last_verified_at,omitempty" json:"last_verified_at,omitempty"`
}

type ExternalServiceCredentialObserveResult struct {
	Metadata ExternalServiceCredentialMetadata `msgpack:"metadata" json:"metadata"`
	Changed  bool                              `msgpack:"changed" json:"changed"`
}

type Profile struct {
	AccountID   string `msgpack:"account_id" json:"account_id"`
	DisplayName string `msgpack:"display_name" json:"display_name"`
	CreatedAt   int64  `msgpack:"created_at" json:"created_at"`
	UpdatedAt   int64  `msgpack:"updated_at" json:"updated_at"`
}

type ProfileCreateRequest struct {
	RequestID string  `msgpack:"request_id"`
	Profile   Profile `msgpack:"profile"`
}

type ProfileGetRequest struct {
	AccountID string `msgpack:"account_id"`
}

type ProfileUpdateRequest struct {
	RequestID   string `msgpack:"request_id"`
	AccountID   string `msgpack:"account_id"`
	DisplayName string `msgpack:"display_name"`
	Now         int64  `msgpack:"now"`
}

type RateCheckRequest struct {
	RequestID    string `msgpack:"request_id"`
	Scope        string `msgpack:"scope"`
	Key          string `msgpack:"key"`
	Now          int64  `msgpack:"now"`
	WindowMillis int64  `msgpack:"window_millis"`
	MaxAttempts  int    `msgpack:"max_attempts"`
}

type RateDecision struct {
	Allowed          bool  `msgpack:"allowed"`
	Count            int   `msgpack:"count"`
	RetryAfterMillis int64 `msgpack:"retry_after_millis,omitempty"`
}

type RateClearRequest struct {
	RequestID string `msgpack:"request_id"`
	Scope     string `msgpack:"scope"`
	Key       string `msgpack:"key"`
}

type LegacyNative struct {
	ID           string `msgpack:"id"`
	AccountID    string `msgpack:"account_id"`
	Email        string `msgpack:"email"`
	Username     string `msgpack:"username"`
	PasswordHash string `msgpack:"password_hash"`
	CreatedAt    int64  `msgpack:"created_at"`
}

type LegacyOAuthLink struct {
	ID            string `msgpack:"id"`
	AccountID     string `msgpack:"account_id"`
	Provider      string `msgpack:"provider"`
	ProviderID    string `msgpack:"provider_id"`
	ProviderEmail string `msgpack:"provider_email"`
	CreatedAt     int64  `msgpack:"created_at"`
}

type LegacyOTP struct {
	ID        string `msgpack:"id"`
	Email     string `msgpack:"email"`
	Code      string `msgpack:"code"`
	Type      string `msgpack:"type"`
	ExpiresAt int64  `msgpack:"expires_at"`
	AccountID string `msgpack:"account_id"`
}

type LegacyImportRequest struct {
	RequestID  string              `msgpack:"request_id"`
	Accounts   []AccountProjection `msgpack:"accounts"`
	Native     []LegacyNative      `msgpack:"native"`
	OAuthLinks []LegacyOAuthLink   `msgpack:"oauth_links"`
	OTPs       []LegacyOTP         `msgpack:"otps"`
	Profiles   []Profile           `msgpack:"profiles"`
}

type LegacyImportResult struct {
	Accounts   int `msgpack:"accounts"`
	Native     int `msgpack:"native"`
	OAuthLinks int `msgpack:"oauth_links"`
	OTPs       int `msgpack:"otps"`
	Profiles   int `msgpack:"profiles"`
}

type ownerEffect struct {
	Intent         effect.Intent   `msgpack:"intent"`
	Status         string          `msgpack:"status"`
	Attempts       uint32          `msgpack:"attempts"`
	AvailableAt    int64           `msgpack:"available_at"`
	Lease          *effect.Lease   `msgpack:"lease,omitempty"`
	Receipt        *effect.Receipt `msgpack:"receipt,omitempty"`
	LastLeaseID    string          `msgpack:"last_lease_id,omitempty"`
	LastConsumerID string          `msgpack:"last_consumer_id,omitempty"`
}
