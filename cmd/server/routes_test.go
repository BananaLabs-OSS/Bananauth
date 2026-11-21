package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/browser"
	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/session"
	"github.com/bananalabs-oss/bananauth/internal/token"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/google/uuid"
)

func TestNativeAccountSessionLifecycle(t *testing.T) {
	folder := t.TempDir()
	keys, err := otpsecure.Parse(strings.Repeat("k", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	identities, closer, err := identity.Open(context.Background(), filepath.Join(folder, "identity.db"), keys)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	db, err := sql.Open("sqlite", filepath.Join(folder, "session.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	sessions, err := session.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	key := token.Key(strings.Repeat("s", 32))
	commands, err := browser.New(identities, sessions, key)
	if err != nil {
		t.Fatal(err)
	}
	mux := routes(commands.Resolve, identities)
	exchanges := 0
	discord := &discordProvider{
		clientID: "fixture", clientSecret: "fixture-secret", base: "https://discord.example",
		redirectURL: "https://bananauth.example/auth/oauth/discord/callback",
		client: &http.Client{Transport: testTransport(func(request *http.Request) (*http.Response, error) {
			body := `{"id":"discord-user-1","email":"discord@example.com"}`
			if request.URL.Path == "/api/oauth2/token" {
				exchanges++
				if err := request.ParseForm(); err != nil || request.Form.Get("code") != "fixture-code" || request.Form.Get("redirect_uri") != "https://bananauth.example/auth/oauth/discord/callback" {
					t.Fatal("bad Discord exchange request")
				}
				body = `{"access_token":"provider-fixture"}`
			} else if request.Header.Get("Authorization") != "Bearer provider-fixture" {
				t.Fatal("missing Discord profile credential")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		})},
	}
	registerAccountRoutes(mux, identities, sessions, &SessionManager{key: key, expiry: time.Hour, newSessionID: uuid.NewString}, discord, commands.CompleteEmailVerification, []byte(strings.Repeat("r", 32)))
	for _, retired := range []string{"/auth/email-verification/v2", "/auth/email-verification/v2/consume", "/auth/email-verification/v2/session"} {
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, httptest.NewRequest("POST", retired, strings.NewReader(`{"email":"retired@example.com","intent":"signup"}`)))
		if r.Code != http.StatusNotFound {
			t.Fatalf("retired route %s returned %d", retired, r.Code)
		}
	}
	call := func(status int, method, path, proof, payload string) map[string]any {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(payload))
		if proof != "" {
			request.Header.Set("Authorization", "Bearer "+proof)
		}
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("%s %s returned %d, want %d: %s", method, path, response.Code, status, response.Body)
		}
		var result map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	startOAuth := func() string {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/auth/oauth/discord", nil))
		location, err := url.Parse(w.Header().Get("Location"))
		if w.Code != 307 || err != nil || location.Query().Get("state") == "" {
			t.Fatalf("invalid OAuth redirect with status %d", w.Code)
		}
		return "/auth/oauth/discord/callback?code=fixture-code&state=" + url.QueryEscape(location.Query().Get("state"))
	}
	callback := startOAuth()
	first := call(201, "GET", callback, "", "")
	call(400, "GET", callback, "", "")
	second := call(200, "GET", startOAuth(), "", "")
	if exchanges != 2 || first["account_id"] != second["account_id"] {
		t.Fatal("OAuth state replay or linked account mismatch")
	}
	call(200, "GET", "/auth/session", second["access_token"].(string), "")

	const credentials = `{"email":"alice@example.com","username":"alice","password":"A-native-test-password-123"}`
	registration := call(201, "POST", "/auth/register", "", credentials)
	proof, ok := registration["access_token"].(string)
	if !ok || proof == "" {
		t.Fatal("registration did not issue a session")
	}
	accountPath := "/profiles/" + registration["account_id"].(string)
	if result := call(200, "GET", "/auth/session", proof, ""); result["username"] != "alice" || result["display_name"] != "alice" {
		t.Fatalf("unconfigured session labels: %v", result)
	}
	if result := call(200, "GET", accountPath, "", ""); result["display_name"] != "alice" {
		t.Fatalf("unconfigured profile label: %v", result)
	}
	call(404, "GET", "/profiles/unknown-account", "", "")
	call(201, "POST", "/profiles", proof, `{"display_name":"Alice"}`)
	if result := call(200, "GET", accountPath, "", ""); result["display_name"] != "Alice" {
		t.Fatalf("custom profile label: %v", result)
	}
	if result := call(200, "GET", "/auth/session", proof, ""); result["username"] != "alice" || result["display_name"] != "Alice" {
		t.Fatalf("custom session labels: %v", result)
	}
	const serviceToken = "fixture-identity-service-token-1234567890"
	registerIdentityRoutes(mux, identities, serviceToken)
	callIdentity := func(path, token string, input any, status int) []byte {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, req)
		if out.Code != status {
			t.Fatalf("%s returned %d, want %d", path, out.Code, status)
		}
		if status == 200 && (out.Header().Get("Content-Type") != "application/json" || out.Header().Get("Cache-Control") != "no-store") {
			t.Fatal("unexpected response headers")
		}
		if status == 200 {
			var value map[string]any
			if json.Unmarshal(out.Body.Bytes(), &value) != nil {
				t.Fatal("invalid private JSON")
			}
			for _, key := range []string{"version", "value", "audience"} {
				if _, exists := value[key]; exists {
					t.Fatalf("private response contains retired protocol field %s", key)
				}
			}
		}
		return out.Body.Bytes()
	}
	accountID := registration["account_id"].(string)
	lookup := identity.AccountGetRequest{AccountID: accountID}
	callIdentity("/internal/identity/accounts/lookup", "invalid", lookup, http.StatusUnauthorized)
	const erasureToken = "fixture-erasure-service-token-1234567890"
	registerAccountErasureRoutes(mux, identities, erasureToken)
	callIdentity("/internal/erasure/accounts/erase", serviceToken, lookup, http.StatusUnauthorized)
	callIdentity("/internal/erasure/accounts/lookup", erasureToken, lookup, http.StatusOK)
	erasureFixture := call(201, "POST", "/auth/register", "", `{"email":"erase@example.test","username":"erasure-fixture","password":"Synthetic-erasure-password-123"}`)
	eraseID := erasureFixture["account_id"].(string)
	erase := identity.AccountEraseRequest{RequestID: "erasure-fixture", AccountID: eraseID, ReasonID: "fixture", Now: time.Now().UnixMilli()}
	var erased identity.AccountProjection
	erasedWire := callIdentity("/internal/erasure/accounts/erase", erasureToken, erase, http.StatusOK)
	if err := json.Unmarshal(erasedWire, &erased); err != nil || erased.AccountID != eraseID {
		t.Fatalf("fixture erasure failed: %v, %+v", err, erased)
	}
	if replay := callIdentity("/internal/erasure/accounts/erase", erasureToken, erase, http.StatusOK); !bytes.Equal(replay, erasedWire) {
		t.Fatal("erasure retry changed the response")
	}
	ref := map[string]string{"operation": identity.FnAccountErase, "request_id": erase.RequestID}
	var receipt identity.ErasureLookup
	if err := json.Unmarshal(callIdentity("/internal/erasure/receipts/lookup", erasureToken, ref, 200), &receipt); err != nil || !receipt.Found || receipt.Fact == nil || receipt.Fact.AccountID != eraseID || receipt.Fact.OwnerRevision <= 0 {
		t.Fatalf("erasure receipt lookup failed: %v", err)
	}

	var account identity.AccountProjection
	raw := callIdentity("/internal/identity/accounts/lookup", serviceToken, lookup, http.StatusOK)
	if err := json.Unmarshal(raw, &account); err != nil || account.AccountID != accountID {
		t.Fatalf("lookup failed: %v", err)
	}
	hold := identity.RetentionHoldRequest{RequestID: "migration-test", AccountID: first["account_id"].(string), HoldID: "fixture-hold", ReasonID: "fixture", AcquisitionID: "fixture-acquisition"}
	raw = callIdentity("/internal/identity/holds/acquire", serviceToken, hold, http.StatusOK)
	var acquired identity.RetentionHold
	if err := json.Unmarshal(raw, &acquired); err != nil || !acquired.Active {
		t.Fatalf("hold failed: %v", err)
	}
	if replay := callIdentity("/internal/identity/holds/acquire", serviceToken, hold, http.StatusOK); !bytes.Equal(raw, replay) {
		t.Fatal("hold replay changed the receipt")
	}

	login := call(200, "POST", "/auth/login", "", credentials)
	loginProof := login["access_token"].(string)
	call(200, "POST", "/auth/logout", loginProof, "")
	call(401, "GET", "/auth/session", loginProof, "")
	call(200, "GET", "/auth/session", proof, "")
	call(202, "POST", "/auth/email-verification", "", `{"email":"code@example.com","intent":"signup"}`)
	worker := newDeliveryWorker(identities, keys, "fixture-key", "fixture@example.com")
	var code, idempotency string
	var deliveries int
	expectedRecipient := "code@example.com"
	worker.client.Transport = testTransport(func(request *http.Request) (*http.Response, error) {
		deliveries++
		idempotency = request.Header.Get("Idempotency-Key")
		var message struct {
			To   []string `json:"to"`
			Text string   `json:"text"`
		}
		if err := json.NewDecoder(request.Body).Decode(&message); err != nil {
			t.Fatal(err)
		}
		if len(message.To) != 1 || message.To[0] != expectedRecipient || idempotency == "" {
			t.Fatal("invalid notification recipient or missing idempotency key")
		}
		code = regexp.MustCompile(`\b[A-Z0-9]{6}\b`).FindString(message.Text)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"sent-fixture"}`))}, nil
	})
	for range 2 {
		if err := worker.drain(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if deliveries != 1 || code == "" {
		t.Fatal("outbox did not deliver and settle exactly once")
	}
	const workflowToken = "fixture-browser-workflow-token-12345"
	registerBrowserWorkflowRoutes(mux, identities, commands, workflowToken)
	complete := map[string]string{"email": "code@example.com", "code": code, "request_id": uuid.NewString(), "intent": "signup"}
	callIdentity("/internal/browser/email/complete", serviceToken, complete, http.StatusUnauthorized)
	readCompletion := func(path string, input map[string]string) browser.CompleteEmailVerificationResult {
		t.Helper()
		wire := callIdentity(path, workflowToken, input, http.StatusOK)
		var result browser.CompleteEmailVerificationResult
		if err := json.Unmarshal(wire, &result); err != nil || result.AccessToken == "" {
			t.Fatalf("private completion failed: %v (%s)", err, result.Error)
		}
		return result
	}
	passwordless := readCompletion("/internal/browser/email/complete", complete)
	call(200, "GET", "/auth/session", passwordless.AccessToken, "")

	expectedRecipient = "signup@example.com"
	call(202, "POST", "/auth/email-verification", "", `{"email":"signup@example.com","intent":"login"}`)
	if err := worker.drain(context.Background()); err != nil || deliveries != 1 {
		t.Fatal("login for an unknown account must not deliver a signup code", err)
	}
	call(202, "POST", "/auth/email-verification", "", `{"email":"signup@example.com","intent":"signup"}`)
	if err := worker.drain(context.Background()); err != nil || deliveries != 2 {
		t.Fatal("signup challenge was not delivered", err)
	}
	signup := map[string]string{"email": "signup@example.com", "code": code, "request_id": uuid.NewString(), "intent": "signup"}
	created := readCompletion("/internal/browser/email/complete", signup)
	replayed := readCompletion("/internal/browser/email/complete", signup)
	if created.SessionID != replayed.SessionID || created.AccountID != replayed.AccountID {
		t.Fatal("signup replay minted a second session")
	}
	call(200, "GET", "/auth/session", created.AccessToken, "")

	const replayEmail = "replay@example.com"
	const replayCode = "ABC123"
	const replayRequest = "verification-submit:e4ea8c49c272e26b802e69ae7b7bd71aa05a7afa9f39244ce6bba819e4173129:bananauth-consume"
	const replayAccount = "c8848ada-b6fe-4283-8266-64dee986ab6b"
	now := time.Now().Add(-time.Second).UnixMilli()
	issued, err := identities.EmailSignupIssueV2(identity.EmailVerificationIssueRequest{
		RequestID: "legacy-issue", VerificationID: "legacy-otp", EffectID: "legacy-effect", Email: replayEmail, Code: replayCode, Now: now, ExpiresAt: now + 60_000,
	})
	if err != nil || !issued.OK || !issued.Value.EffectQueued {
		t.Fatal("legacy fixture issuance failed", err)
	}
	consumed, err := identities.EmailSignupConsumeV2(identity.EmailVerificationConsumeRequest{
		RequestID: replayRequest, AccountID: replayAccount, Email: replayEmail, Code: replayCode, Now: now + 1,
	})
	if err != nil || !consumed.OK || !consumed.Value.Verified {
		t.Fatal("legacy fixture consumption failed", err)
	}
	got := call(200, "POST", "/auth/email-verification/consume", "", `{"email":"Replay@example.com","code":" abc123 ","intent":"signup"}`)
	if got["account_id"] != replayAccount {
		t.Fatal("native retry did not recover the legacy account receipt")
	}
}

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestSessionHTTPDistinguishesDeniedFromUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name, header, outcome, message string
		status                         int
	}{
		{"missing", "", "", "missing authorization header", 401},
		{"malformed", "Basic example", "", "invalid authorization format, expected: Bearer <token>", 401},
		{"denied", "Bearer example", "unauthorized", "invalid or expired token", 401},
		{"unavailable", "Bearer example", "unavailable", "session service unavailable", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := routes(func(browser.ResolveRequest) browser.ResolveResult {
				if tc.outcome == "" {
					t.Fatal("resolver called for malformed or absent credentials")
				}
				return browser.ResolveResult{Version: browser.ContractVersion, Error: tc.outcome}
			}, nil)
			request := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
			request.Header.Set("Authorization", tc.header)
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)
			var body errorResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || recorder.Code != tc.status || body.Error != tc.message {
				t.Fatalf("response %d %s, want %d %q", recorder.Code, recorder.Body, tc.status, tc.message)
			}
		})
	}
}
