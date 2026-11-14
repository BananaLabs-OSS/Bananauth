package browser

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	hostjwt "github.com/bananalabs-oss/bananauth/internal/token"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	identityConsumeProvider = "auth.identity.v1.email-verification.consume"
	sessionCreateProvider   = "auth.session.v1.create-email-verified-owned"
	identityVersion         = "auth-identity.v1"
	defaultSessionLifetime  = int64((24 * time.Hour) / time.Millisecond)
)

type emailSessionCompleter struct {
	consume         func([]byte) ([]byte, error)
	consumeLoginV2  func([]byte) ([]byte, error)
	consumeSignupV2 func([]byte) ([]byte, error)
	authIntentV2    string
	create          func([]byte) ([]byte, error)
	sign            func(hostjwt.SignRequest) (string, error)
	now             func() time.Time
}

func deterministicOpaqueID(namespace, requestID string) string {
	digest := sha256.Sum256([]byte(namespace + "\x00" + requestID))
	return hex.EncodeToString(digest[:16])
}

func (c emailSessionCompleter) complete(raw []byte) ([]byte, error) {
	result := c.completeValue(raw)
	return msgpack.Marshal(result)
}

func (c emailSessionCompleter) completeValue(raw []byte) CompleteEmailVerificationResult {
	denied := func(code string) CompleteEmailVerificationResult {
		return CompleteEmailVerificationResult{Version: ContractVersion, Error: code}
	}
	if c.consume == nil || c.create == nil || c.sign == nil || c.now == nil {
		return denied("unavailable")
	}
	var request CompleteEmailVerificationRequest
	if err := msgpack.Unmarshal(raw, &request); err != nil || request.Version != ContractVersion || !opaqueID(request.RequestID) {
		return denied("invalid_request")
	}
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	request.Code = strings.ToUpper(strings.TrimSpace(request.Code))
	if len(request.Email) < 3 || len(request.Email) > 254 || !strings.Contains(request.Email, "@") || len(request.Code) != 6 || !utf8.ValidString(request.Email) {
		return denied("invalid_request")
	}
	now := c.now().UTC().UnixMilli()
	operationPrefix := "email-session:"
	accountNamespace := "bananauth:email-account"
	sessionNamespace := "bananauth:email-session"
	if c.authIntentV2 != "" {
		operationPrefix = "email-session:v2:" + c.authIntentV2 + ":"
		accountNamespace += ":v2:" + c.authIntentV2
		sessionNamespace += ":v2:" + c.authIntentV2
	}
	accountCandidate := deterministicOpaqueID(accountNamespace, request.RequestID)
	consumeWire, err := msgpack.Marshal(map[string]any{
		"request_id": operationPrefix + "identity:" + request.RequestID,
		"account_id": accountCandidate, "email": request.Email, "code": request.Code, "now": now,
	})
	if err != nil {
		return denied("unavailable")
	}
	consumeResponse, err := c.consume(consumeWire)
	if err != nil {
		return denied("identity_unavailable")
	}
	var verified struct {
		Version string `msgpack:"version"`
		OK      bool   `msgpack:"ok"`
		Value   struct {
			Verified                            bool   `msgpack:"verified"`
			AccountID                           string `msgpack:"account_id"`
			VerifiedEmail                       string `msgpack:"verified_email"`
			EmailVerifiedAtUnixMilli            int64  `msgpack:"email_verified_at_unix_milli"`
			EmailVerificationExpiresAtUnixMilli int64  `msgpack:"email_verification_expires_at_unix_milli"`
			VerificationRequestID               string `msgpack:"verification_request_id"`
		} `msgpack:"value"`
	}
	if msgpack.Unmarshal(consumeResponse, &verified) != nil || verified.Version != identityVersion || !verified.OK || !verified.Value.Verified || !opaqueID(verified.Value.AccountID) {
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
	createWire, err := msgpack.Marshal(map[string]any{
		"request_id": operationPrefix + "create:" + request.RequestID,
		"session_id": sessionID, "account_id": verified.Value.AccountID, "lifetime_millis": defaultSessionLifetime,
		"verified_email":                           verified.Value.VerifiedEmail,
		"email_verified_at_unix_milli":             verified.Value.EmailVerifiedAtUnixMilli,
		"email_verification_expires_at_unix_milli": verified.Value.EmailVerificationExpiresAtUnixMilli,
		"verification_request_id":                  verified.Value.VerificationRequestID,
	})
	if err != nil {
		return denied("unavailable")
	}
	createResponse, err := c.create(createWire)
	if err != nil {
		return denied("session_unavailable")
	}
	var created struct {
		Version string        `msgpack:"version"`
		OK      bool          `msgpack:"ok"`
		Value   sessionFact   `msgpack:"value"`
		Error   *sessionError `msgpack:"error,omitempty"`
	}
	if msgpack.Unmarshal(createResponse, &created) == nil && created.Error != nil && (created.Error.Code == "verification_expired" || created.Error.Code == "invalid_verification") {
		return denied("invalid_code")
	}
	if msgpack.Unmarshal(createResponse, &created) != nil || created.Version != sessionContractVersion || !created.OK || !created.Value.Active || created.Value.AccountID != verified.Value.AccountID || created.Value.SessionID != sessionID || created.Value.ExpiresAt <= now {
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

// V2 selects only the explicitly granted strict owner. No legacy fallback.
func (c emailSessionCompleter) completeV2(raw []byte) ([]byte, error) {
	var request CompleteEmailVerificationRequestV2
	if msgpack.Unmarshal(raw, &request) != nil {
		return msgpack.Marshal(CompleteEmailVerificationResult{Version: ContractVersion, Error: "invalid_request"})
	}
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
		return msgpack.Marshal(CompleteEmailVerificationResult{Version: ContractVersion, Error: "invalid_request"})
	}
	c.authIntentV2 = intent
	wire, err := msgpack.Marshal(CompleteEmailVerificationRequest{Version: request.Version, RequestID: request.RequestID, Email: request.Email, Code: request.Code})
	if err != nil {
		return nil, err
	}
	return c.complete(wire)
}
