package browser

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/session"
	hostjwt "github.com/bananalabs-oss/bananauth/internal/token"
)

const (
	identityConsumeProvider = "auth.identity.v1.email-verification.consume"
	sessionCreateProvider   = "auth.session.v1.create-email-verified-owned"
	identityVersion         = "auth-identity.v1"
	defaultSessionLifetime  = int64((24 * time.Hour) / time.Millisecond)
)

type emailSessionCompleter struct {
	consume         func(identity.EmailVerificationConsumeRequest) (identity.Result[identity.EmailVerificationConsumeResult], error)
	consumeLoginV2  func(identity.EmailVerificationConsumeRequest) (identity.Result[identity.EmailVerificationConsumeResult], error)
	consumeSignupV2 func(identity.EmailVerificationConsumeRequest) (identity.Result[identity.EmailVerificationConsumeResult], error)
	authIntentV2    string
	create          func(session.CreateEmailVerifiedOwnedRequest) (session.Result[session.Session], error)
	sign            func(hostjwt.SignRequest) (string, error)
	now             func() time.Time
}

func deterministicOpaqueID(namespace, requestID string) string {
	digest := sha256.Sum256([]byte(namespace + "\x00" + requestID))
	return hex.EncodeToString(digest[:16])
}

func (c emailSessionCompleter) completeRequest(request CompleteEmailVerificationRequest) CompleteEmailVerificationResult {
	denied := func(code string) CompleteEmailVerificationResult {
		return CompleteEmailVerificationResult{Version: ContractVersion, Error: code}
	}
	if c.consume == nil || c.create == nil || c.sign == nil || c.now == nil {
		return denied("unavailable")
	}
	if request.Version != ContractVersion || !opaqueID(request.RequestID) {
		return denied("invalid_request")
	}
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	request.Code = strings.ToUpper(strings.TrimSpace(request.Code))
	if len(request.Email) < 3 || len(request.Email) > 254 || !strings.Contains(request.Email, "@") || len(request.Code) != 6 || !utf8.ValidString(request.Email) {
		return denied("invalid_request")
	}
	now := c.now().UTC().UnixMilli()
	if c.authIntentV2 != "login" && c.authIntentV2 != "signup" {
		return denied("invalid_request")
	}
	operationPrefix := "email-session:v2:" + c.authIntentV2 + ":"
	accountNamespace := "bananauth:email-account:v2:" + c.authIntentV2
	sessionNamespace := "bananauth:email-session:v2:" + c.authIntentV2
	accountCandidate := deterministicOpaqueID(accountNamespace, request.RequestID)
	verified, err := c.consume(identity.EmailVerificationConsumeRequest{
		RequestID: operationPrefix + "identity:" + request.RequestID, AccountID: accountCandidate,
		Email: request.Email, Code: request.Code, Now: now,
	})
	if err != nil {
		return denied("identity_unavailable")
	}
	if verified.Version != identityVersion || !verified.OK || !verified.Value.Verified || !opaqueID(verified.Value.AccountID) {
		return denied("invalid_code")
	}
	// Immutable proof is supplied only by the identity owner. Expiry at FIRST
	// session creation is checked atomically by the session owner; exact
	// completed session replay must retain its original lifetime.
	if verified.Value.VerifiedEmail != request.Email || verified.Value.EmailVerifiedAtUnixMilli <= 0 ||
		verified.Value.EmailVerificationExpiresAtUnixMilli <= verified.Value.EmailVerifiedAtUnixMilli ||
		verified.Value.EmailVerifiedAtUnixMilli > now || verified.Value.VerificationRequestID != operationPrefix+"identity:"+request.RequestID {
		return denied("invalid_code")
	}

	sessionID := deterministicOpaqueID(sessionNamespace, request.RequestID)
	created, err := c.create(session.CreateEmailVerifiedOwnedRequest{
		RequestID: operationPrefix + "create:" + request.RequestID, SessionID: sessionID, AccountID: verified.Value.AccountID, LifetimeMillis: defaultSessionLifetime,
		VerifiedEmail: verified.Value.VerifiedEmail, EmailVerifiedAtUnixMilli: verified.Value.EmailVerifiedAtUnixMilli,
		EmailVerificationExpiresAtUnixMilli: verified.Value.EmailVerificationExpiresAtUnixMilli, VerificationRequestID: verified.Value.VerificationRequestID,
	})
	if err != nil {
		return denied("session_unavailable")
	}
	if created.Error != nil && (created.Error.Code == "verification_expired" || created.Error.Code == "invalid_verification") {
		return denied("invalid_code")
	}
	if created.Version != sessionContractVersion || !created.OK || !created.Value.Active || created.Value.AccountID != verified.Value.AccountID || created.Value.SessionID != sessionID || created.Value.ExpiresAt <= now {
		return denied("session_unavailable")
	}

	email, assured, valid := verifiedSessionEmail(created.Value)
	if !valid || !assured || email != verified.Value.VerifiedEmail || created.Value.VerificationRequestID != verified.Value.VerificationRequestID {
		return denied("session_unavailable")
	}

	token, err := c.sign(hostjwt.SignRequest{AccountID: verified.Value.AccountID, SessionID: sessionID, ExpiresAt: created.Value.ExpiresAt})
	if err != nil || token == "" {
		return denied("session_unavailable")
	}
	return CompleteEmailVerificationResult{
		Version: ContractVersion, OK: true, AccessToken: token, AccountID: verified.Value.AccountID,
		SessionID: sessionID, ExpiresIn: (created.Value.ExpiresAt - now) / 1000, ExpiresAtUnixMilli: created.Value.ExpiresAt,
	}
}

// Complete selects the requested strict authentication intent without fallback.
func (c emailSessionCompleter) completeIntent(request CompleteEmailVerificationRequestV2) CompleteEmailVerificationResult {
	intent := request.Intent
	if intent == "" {
		intent = "login"
	}
	switch intent {
	case "login":
		c.consume = c.consumeLoginV2
	case "signup":
		c.consume = c.consumeSignupV2
	default:
		return CompleteEmailVerificationResult{Version: ContractVersion, Error: "invalid_request"}
	}
	c.authIntentV2 = intent
	return c.completeRequest(CompleteEmailVerificationRequest{Version: request.Version, RequestID: request.RequestID, Email: request.Email, Code: request.Code})
}
