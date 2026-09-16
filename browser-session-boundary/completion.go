package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	hostjwt "github.com/BananaLabs-OSS/Fiber/pulp/jwt"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	identityConsumeProvider = "auth.identity.v1.email-verification.consume"
	sessionCreateProvider   = "auth.session.v1.create-owned"
	identityVersion         = "auth-identity.v1"
	defaultSessionLifetime  = int64((24 * time.Hour) / time.Millisecond)
)

type emailSessionCompleter struct {
	consume func([]byte) ([]byte, error)
	create  func([]byte) ([]byte, error)
	sign    func(hostjwt.SignRequest) (string, error)
	now     func() time.Time
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
	accountCandidate := deterministicOpaqueID("bananauth:email-account", request.RequestID)
	consumeWire, err := msgpack.Marshal(map[string]any{
		"request_id": "email-session:identity:" + request.RequestID,
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
			Verified  bool   `msgpack:"verified"`
			AccountID string `msgpack:"account_id"`
		} `msgpack:"value"`
	}
	if msgpack.Unmarshal(consumeResponse, &verified) != nil || verified.Version != identityVersion || !verified.OK || !verified.Value.Verified || !opaqueID(verified.Value.AccountID) {
		return denied("invalid_code")
	}
	sessionID := deterministicOpaqueID("bananauth:email-session", request.RequestID)
	createWire, err := msgpack.Marshal(map[string]any{
		"request_id": "email-session:create:" + request.RequestID,
		"session_id": sessionID, "account_id": verified.Value.AccountID, "lifetime_millis": defaultSessionLifetime,
	})
	if err != nil {
		return denied("unavailable")
	}
	createResponse, err := c.create(createWire)
	if err != nil {
		return denied("session_unavailable")
	}
	var created struct {
		Version string      `msgpack:"version"`
		OK      bool        `msgpack:"ok"`
		Value   sessionFact `msgpack:"value"`
	}
	if msgpack.Unmarshal(createResponse, &created) != nil || created.Version != sessionContractVersion || !created.OK || !created.Value.Active || created.Value.AccountID != verified.Value.AccountID || created.Value.SessionID != sessionID || created.Value.ExpiresAt <= now {
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
