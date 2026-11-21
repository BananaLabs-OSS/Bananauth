package identity

import "github.com/bananalabs-oss/bananauth/internal/notification"

const ContractVersion = "auth-identity.v1"

const (
	FnNativeRegister         = "auth.identity.v1.native.register"
	FnNativePasswordChange   = "auth.identity.v1.native.password.change"
	FnNativeCredentialAttach = "auth.identity.v1.native.attach"
	FnPasswordResetIssue     = "auth.identity.v1.password-reset.issue"
	FnPasswordResetConsume   = "auth.identity.v1.password-reset.consume"
	// Email verification is deliberately separate from password reset. Sessions
	// uses it for passwordless human login, so it must not depend on a native
	// account or mutate password-reset state.
	FnAccountDelete = "auth.identity.v1.account.delete"
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
	FnRetentionHoldAcquire  = "auth.identity.v1.retention-hold.acquire"
	FnRetentionHoldRelease  = "auth.identity.v1.retention-hold.release"
	FnOAuthStateIssue       = "auth.identity.v1.oauth-state.issue"
	FnOAuthStateConsume     = "auth.identity.v1.oauth-state.consume"
	FnOAuthUpsert           = "auth.identity.v1.oauth.upsert"
	FnProfileCreate         = "auth.identity.v1.profile.create"
	FnAccountGet            = "auth.identity.v1.account.get"
	FnProfileUpdate         = "auth.identity.v1.profile.update"
	FnRateCheck             = "auth.identity.v1.rate.check"
	FnRateClear             = "auth.identity.v1.rate.clear"
	FnLegacyImport          = "auth.identity.v1.legacy.import"
	FnEffectsClaim          = "notification.claim"
	FnEffectsAck            = "notification.acknowledge"
	FnEffectsRetry          = "notification.retry"
)

type Error struct {
	Code    string `msgpack:"code" json:"code"`
	Message string `msgpack:"message" json:"message"`
}

type Result[T any] struct {
	Version string `msgpack:"version" json:"version"`
	OK      bool   `msgpack:"ok" json:"ok"`
	Value   T      `msgpack:"value,omitempty" json:"value,omitempty"`
	Error   *Error `msgpack:"error,omitempty" json:"error,omitempty"`
}

type AccountProjection struct {
	AccountID string `msgpack:"account_id" json:"account_id"`
	Email     string `msgpack:"email,omitempty" json:"email,omitempty"`
	Username  string `msgpack:"username,omitempty" json:"username,omitempty"`
	CreatedAt int64  `msgpack:"created_at" json:"created_at"`
}

type AccountGetRequest struct {
	Email     string `msgpack:"email,omitempty" json:"email,omitempty"`
	AccountID string `msgpack:"account_id" json:"account_id"`
}

type NativeRegisterRequest struct {
	RequestID    string `msgpack:"request_id" json:"request_id"`
	AccountID    string `msgpack:"account_id" json:"account_id"`
	CredentialID string `msgpack:"credential_id" json:"credential_id"`
	Email        string `msgpack:"email" json:"email"`
	Username     string `msgpack:"username" json:"username"`
	Password     string `msgpack:"password" json:"password"`
	Now          int64  `msgpack:"now" json:"now"`
}

type NativeAuthenticateRequest struct {
	Email    string `msgpack:"email" json:"email"`
	Password string `msgpack:"password" json:"password"`
}

type PasswordChangeRequest struct {
	RequestID       string `msgpack:"request_id" json:"request_id"`
	AccountID       string `msgpack:"account_id" json:"account_id"`
	CurrentPassword string `msgpack:"current_password" json:"current_password"`
	NewPassword     string `msgpack:"new_password" json:"new_password"`
	Now             int64  `msgpack:"now" json:"now"`
}

// NativeCredentialAttachRequest adds a password credential to an existing
// OAuth-created account. It never creates or replaces the account identity.
type NativeCredentialAttachRequest struct {
	RequestID    string `msgpack:"request_id" json:"request_id"`
	AccountID    string `msgpack:"account_id" json:"account_id"`
	CredentialID string `msgpack:"credential_id" json:"credential_id"`
	Email        string `msgpack:"email" json:"email"`
	Username     string `msgpack:"username" json:"username"`
	Password     string `msgpack:"password" json:"password"`
	Now          int64  `msgpack:"now" json:"now"`
}

type PasswordResetIssueRequest struct {
	RequestID string `msgpack:"request_id" json:"request_id"`
	OTPID     string `msgpack:"otp_id" json:"otp_id"`
	EffectID  string `msgpack:"effect_id" json:"effect_id"`
	Email     string `msgpack:"email" json:"email"`
	Code      string `msgpack:"code" json:"code"`
	ExpiresAt int64  `msgpack:"expires_at" json:"expires_at"`
	Now       int64  `msgpack:"now" json:"now"`
}

type PasswordResetIssueResult struct {
	Accepted     bool `msgpack:"accepted" json:"accepted"`
	EffectQueued bool `msgpack:"effect_queued" json:"effect_queued"`
}

type PasswordResetConsumeRequest struct {
	RequestID   string `msgpack:"request_id" json:"request_id"`
	Email       string `msgpack:"email" json:"email"`
	Code        string `msgpack:"code" json:"code"`
	NewPassword string `msgpack:"new_password" json:"new_password"`
	Now         int64  `msgpack:"now" json:"now"`
}

// EmailVerificationIssueRequest creates one single-use, time-bounded
// passwordless verification code and queues its delivery through the owner's
// generic notification outbox. The caller supplies identifiers so retries are
// deterministic and the owner never invents an ambient identity.
type EmailVerificationIssueRequest struct {
	RequestID      string `msgpack:"request_id" json:"request_id"`
	VerificationID string `msgpack:"verification_id" json:"verification_id"`
	EffectID       string `msgpack:"effect_id" json:"effect_id"`
	Email          string `msgpack:"email" json:"email"`
	CallerKey      string `msgpack:"caller_key,omitempty" json:"caller_key,omitempty"`
	Code           string `msgpack:"code" json:"code"`
	Now            int64  `msgpack:"now" json:"now"`
	ExpiresAt      int64  `msgpack:"expires_at" json:"expires_at"`
}

type EmailVerificationIssueResult struct {
	Accepted     bool `msgpack:"accepted" json:"accepted"`
	EffectQueued bool `msgpack:"effect_queued" json:"effect_queued"`
}

// EmailVerificationConsumeRequest validates and consumes one Sessions human
// login code. AccountID is supplied by the composed adapter only when this is
// the first passwordless login for an email. The owner reuses an existing
// account for that email, so a later login never forks the identity. The
// caller-supplied identifier keeps account creation deterministic under a
// retried command; the owner never invents ambient account IDs.
type EmailVerificationConsumeRequest struct {
	RequestID string `msgpack:"request_id" json:"request_id"`
	AccountID string `msgpack:"account_id,omitempty" json:"account_id,omitempty"`
	Email     string `msgpack:"email" json:"email"`
	Code      string `msgpack:"code" json:"code"`
	Now       int64  `msgpack:"now" json:"now"`
}

type EmailVerificationConsumeResult struct {
	Verified                            bool   `msgpack:"verified" json:"verified"`
	AccountID                           string `msgpack:"account_id" json:"account_id"`
	VerifiedEmail                       string `msgpack:"verified_email,omitempty" json:"verified_email,omitempty"`
	EmailVerifiedAtUnixMilli            int64  `msgpack:"email_verified_at_unix_milli,omitempty" json:"email_verified_at_unix_milli,omitempty"`
	EmailVerificationExpiresAtUnixMilli int64  `msgpack:"email_verification_expires_at_unix_milli,omitempty" json:"email_verification_expires_at_unix_milli,omitempty"`
	VerificationRequestID               string `msgpack:"verification_request_id,omitempty" json:"verification_request_id,omitempty"`
}

type AccountDeleteRequest struct {
	RequestID string `msgpack:"request_id" json:"request_id"`
	AccountID string `msgpack:"account_id" json:"account_id"`
	Password  string `msgpack:"password,omitempty" json:"password,omitempty"`
	Email     string `msgpack:"email,omitempty" json:"email,omitempty"`
	Now       int64  `msgpack:"now" json:"now"`
}

// AccountEraseRequest is for a trusted application policy such as Sessions'
// explicitly enabled expiry sweep. ReasonID is opaque and not interpreted by
// Bananauth. Provider authority, not a caller-supplied boolean, controls who
// may invoke it.
type AccountEraseRequest struct {
	RequestID string `msgpack:"request_id" json:"request_id"`
	AccountID string `msgpack:"account_id" json:"account_id"`
	ReasonID  string `msgpack:"reason_id" json:"reason_id"`
	Now       int64  `msgpack:"now" json:"now"`
}

// RetentionLease is a caller-named, opaque retention claim on an identity.
// ReasonID is never interpreted by Bananauth. ExpiresAt is supplied by the
// application and may include whatever grace period its policy requires.
type RetentionLease struct {
	AccountID string `msgpack:"account_id" json:"account_id"`
	LeaseID   string `msgpack:"lease_id" json:"lease_id"`
	ReasonID  string `msgpack:"reason_id" json:"reason_id"`
	ExpiresAt int64  `msgpack:"expires_at" json:"expires_at"`
}

type RetentionLeaseCreateRequest struct {
	RequestID string         `msgpack:"request_id" json:"request_id"`
	Lease     RetentionLease `msgpack:"lease" json:"lease"`
	Now       int64          `msgpack:"now" json:"now"`
}

type RetentionLeaseRenewRequest = RetentionLeaseCreateRequest

type RetentionLeaseReleaseRequest struct {
	RequestID string `msgpack:"request_id" json:"request_id"`
	AccountID string `msgpack:"account_id" json:"account_id"`
	LeaseID   string `msgpack:"lease_id" json:"lease_id"`
	ReasonID  string `msgpack:"reason_id" json:"reason_id"`
	Now       int64  `msgpack:"now" json:"now"`
}

type RetentionLeaseListRequest struct {
	AccountID string `msgpack:"account_id" json:"account_id"`
	Now       int64  `msgpack:"now" json:"now"`
}

type RetentionLeaseListResult struct {
	Leases []RetentionLease `msgpack:"leases" json:"leases"`
}

type RetentionEligibilityRequest = RetentionLeaseListRequest

// RetentionHold protects an account until its exact acquisition is released.
// Released records remain as replay fences; there is no clock or expiry.
type RetentionHold struct {
	AccountID     string `msgpack:"account_id" json:"account_id"`
	HoldID        string `msgpack:"hold_id" json:"hold_id"`
	ReasonID      string `msgpack:"reason_id" json:"reason_id"`
	AcquisitionID string `msgpack:"acquisition_id" json:"acquisition_id"`
	Active        bool   `msgpack:"active" json:"active"`
}
type RetentionHoldRequest struct {
	RequestID     string `msgpack:"request_id" json:"request_id"`
	AccountID     string `msgpack:"account_id" json:"account_id"`
	HoldID        string `msgpack:"hold_id" json:"hold_id"`
	ReasonID      string `msgpack:"reason_id" json:"reason_id"`
	AcquisitionID string `msgpack:"acquisition_id" json:"acquisition_id"`
}

type RetentionEligibility struct {
	Deletable  bool             `msgpack:"deletable" json:"deletable"`
	LiveLeases []RetentionLease `msgpack:"live_leases" json:"live_leases"`
	LiveHolds  []RetentionHold  `msgpack:"live_holds,omitempty" json:"live_holds,omitempty"`
}

type OAuthState struct {
	State           string `msgpack:"state" json:"state"`
	Provider        string `msgpack:"provider" json:"provider"`
	RedirectBinding string `msgpack:"redirect_binding" json:"redirect_binding"`
	ExpiresAt       int64  `msgpack:"expires_at" json:"expires_at"`
	ConsumedAt      int64  `msgpack:"consumed_at,omitempty" json:"consumed_at,omitempty"`
}

type OAuthStateIssueRequest struct {
	RequestID string     `msgpack:"request_id" json:"request_id"`
	State     OAuthState `msgpack:"state" json:"state"`
}

type OAuthStateConsumeRequest struct {
	RequestID       string `msgpack:"request_id" json:"request_id"`
	State           string `msgpack:"state" json:"state"`
	Provider        string `msgpack:"provider" json:"provider"`
	RedirectBinding string `msgpack:"redirect_binding" json:"redirect_binding"`
	Now             int64  `msgpack:"now" json:"now"`
}

type OAuthResolveRequest struct {
	Provider   string `msgpack:"provider" json:"provider"`
	ProviderID string `msgpack:"provider_id" json:"provider_id"`
}

type OAuthUpsertRequest struct {
	RequestID     string `msgpack:"request_id" json:"request_id"`
	AccountID     string `msgpack:"account_id" json:"account_id"`
	LinkID        string `msgpack:"link_id" json:"link_id"`
	Provider      string `msgpack:"provider" json:"provider"`
	ProviderID    string `msgpack:"provider_id" json:"provider_id"`
	ProviderEmail string `msgpack:"provider_email" json:"provider_email"`
	Now           int64  `msgpack:"now" json:"now"`
}

type OAuthUpsertResult struct {
	Account AccountProjection `msgpack:"account" json:"account"`
	Created bool              `msgpack:"created" json:"created"`
}

// ExternalServiceCredentialContractVersion describes non-secret ownership
// metadata for a provider-backed service credential. The credential material
// itself is deliberately outside this contract: it must remain in a sealed
// internal capability and is never passed through an identity provider or
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
	RequestID string  `msgpack:"request_id" json:"request_id"`
	Profile   Profile `msgpack:"profile" json:"profile"`
}

type ProfileGetRequest struct {
	AccountID string `msgpack:"account_id" json:"account_id"`
}

type ProfileUpdateRequest struct {
	RequestID   string `msgpack:"request_id" json:"request_id"`
	AccountID   string `msgpack:"account_id" json:"account_id"`
	DisplayName string `msgpack:"display_name" json:"display_name"`
	Now         int64  `msgpack:"now" json:"now"`
}

type RateCheckRequest struct {
	RequestID    string `msgpack:"request_id" json:"request_id"`
	Scope        string `msgpack:"scope" json:"scope"`
	Key          string `msgpack:"key" json:"key"`
	Now          int64  `msgpack:"now" json:"now"`
	WindowMillis int64  `msgpack:"window_millis" json:"window_millis"`
	MaxAttempts  int    `msgpack:"max_attempts" json:"max_attempts"`
}

type RateDecision struct {
	Allowed          bool  `msgpack:"allowed" json:"allowed"`
	Count            int   `msgpack:"count" json:"count"`
	RetryAfterMillis int64 `msgpack:"retry_after_millis,omitempty" json:"retry_after_millis,omitempty"`
}

type RateClearRequest struct {
	RequestID string `msgpack:"request_id" json:"request_id"`
	Scope     string `msgpack:"scope" json:"scope"`
	Key       string `msgpack:"key" json:"key"`
}

type LegacyNative struct {
	ID           string `msgpack:"id" json:"id"`
	AccountID    string `msgpack:"account_id" json:"account_id"`
	Email        string `msgpack:"email" json:"email"`
	Username     string `msgpack:"username" json:"username"`
	PasswordHash string `msgpack:"password_hash" json:"password_hash"`
	CreatedAt    int64  `msgpack:"created_at" json:"created_at"`
}

type LegacyOAuthLink struct {
	ID            string `msgpack:"id" json:"id"`
	AccountID     string `msgpack:"account_id" json:"account_id"`
	Provider      string `msgpack:"provider" json:"provider"`
	ProviderID    string `msgpack:"provider_id" json:"provider_id"`
	ProviderEmail string `msgpack:"provider_email" json:"provider_email"`
	CreatedAt     int64  `msgpack:"created_at" json:"created_at"`
}

type LegacyOTP struct {
	ID        string `msgpack:"id" json:"id"`
	Email     string `msgpack:"email" json:"email"`
	Code      string `msgpack:"code" json:"code"`
	Type      string `msgpack:"type" json:"type"`
	ExpiresAt int64  `msgpack:"expires_at" json:"expires_at"`
	AccountID string `msgpack:"account_id" json:"account_id"`
}

type LegacyImportRequest struct {
	RequestID  string              `msgpack:"request_id" json:"request_id"`
	Accounts   []AccountProjection `msgpack:"accounts" json:"accounts"`
	Native     []LegacyNative      `msgpack:"native" json:"native"`
	OAuthLinks []LegacyOAuthLink   `msgpack:"oauth_links" json:"oauth_links"`
	OTPs       []LegacyOTP         `msgpack:"otps" json:"otps"`
	Profiles   []Profile           `msgpack:"profiles" json:"profiles"`
}

type LegacyImportResult struct {
	Accounts   int `msgpack:"accounts" json:"accounts"`
	Native     int `msgpack:"native" json:"native"`
	OAuthLinks int `msgpack:"oauth_links" json:"oauth_links"`
	OTPs       int `msgpack:"otps" json:"otps"`
	Profiles   int `msgpack:"profiles" json:"profiles"`
}

type ownerEffect struct {
	Message        notification.Message  `msgpack:"message" json:"message"`
	Status         string                `msgpack:"status" json:"status"`
	Attempts       uint32                `msgpack:"attempts" json:"attempts"`
	AvailableAt    int64                 `msgpack:"available_at" json:"available_at"`
	ExpiresAt      int64                 `msgpack:"expires_at,omitempty" json:"expires_at,omitempty"`
	Lease          *notification.Lease   `msgpack:"lease,omitempty" json:"lease,omitempty"`
	Receipt        *notification.Receipt `msgpack:"receipt,omitempty" json:"receipt,omitempty"`
	LastLeaseID    string                `msgpack:"last_lease_id,omitempty" json:"last_lease_id,omitempty"`
	LastConsumerID string                `msgpack:"last_consumer_id,omitempty" json:"last_consumer_id,omitempty"`
}
