package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bananalabs-oss/bananauth/internal/storage"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/browser"
	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/session"
	"github.com/bananalabs-oss/bananauth/internal/token"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	proxies, err := parseTrustedProxies(os.Getenv("BANANAUTH_TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return err
	}
	identityPath := os.Getenv("BANANAUTH_IDENTITY_DB")
	sessionPath := os.Getenv("BANANAUTH_SESSION_DB")
	key := token.Key(os.Getenv("JWT_SECRET"))
	if identityPath == "" || sessionPath == "" || len(key) < 32 {
		return errors.New("identity database, session database, and a JWT secret of at least 32 bytes are required")
	}
	keys, err := otpsecure.Parse(setting("BANANAUTH_OTP_KEY_CURRENT", "BANANAAUTH_OTP_KEY_CURRENT"), setting("BANANAUTH_OTP_KEY_PREVIOUS", "BANANAAUTH_OTP_KEY_PREVIOUS"))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	identities, identityDB, err := identity.Open(ctx, identityPath, keys)
	if err != nil {
		return err
	}
	defer identityDB.Close()

	sessionDB, err := storage.Open(sessionPath)
	if err != nil {
		return err
	}
	defer sessionDB.Close()
	sessions, err := session.Open(sessionDB)
	if err != nil {
		return err
	}
	commands, err := browser.Commands(identities, sessions, key)
	if err != nil {
		return err
	}

	if strings.EqualFold(strings.TrimSpace(os.Getenv("OUTBOUND_DELIVERY_ENABLED")), "true") {
		apiKey, from := os.Getenv("RESEND_API_KEY"), os.Getenv("RESEND_FROM")
		if apiKey == "" {
			return errors.New("RESEND_API_KEY is required when outbound email is enabled")
		}
		if from == "" {
			from = "no-reply@example.com"
		}
		testRecipients, err := parseTestRecipients(os.Getenv("SESSIONS_TRANSACTIONAL_TEST_RECIPIENTS"), os.Getenv("SESSIONS_TRANSACTIONAL_TEST_RECIPIENTS_REQUIRED"))
		if err != nil {
			return err
		}
		worker := newDeliveryWorker(identities, keys, apiKey, from)
		worker.testRecipients = testRecipients
		emailCtx, cancel := context.WithCancel(ctx)
		workerDone := make(chan struct{})
		go func() {
			defer close(workerDone)
			worker.run(emailCtx)
		}()
		defer func() { cancel(); <-workerDone }()
	}

	address := os.Getenv("LISTEN_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	var discord *discordProvider
	clientID, clientSecret, redirect := setting("DISCORD_CLIENT_ID", "PULP_OAUTH_DISCORD_CLIENT_ID"), setting("DISCORD_CLIENT_SECRET", "PULP_OAUTH_DISCORD_CLIENT_SECRET"), setting("DISCORD_REDIRECT_URL", "PULP_OAUTH_DISCORD_REDIRECT_URL")
	if clientID != "" || clientSecret != "" || redirect != "" {
		if clientID == "" || clientSecret == "" || redirect == "" {
			return errors.New("Discord OAuth requires client ID, client secret, and redirect URL")
		}
		discord = &discordProvider{clientID: clientID, clientSecret: clientSecret, redirectURL: redirect, base: "https://discord.com",
			client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	}
	mux := routes(commands[browser.ProviderResolve])
	if serviceToken := os.Getenv("BANANAUTH_IDENTITY_SERVICE_TOKEN"); serviceToken != "" {
		if len(serviceToken) < 32 {
			return errors.New("BANANAUTH_IDENTITY_SERVICE_TOKEN must be at least 32 bytes")
		}
		registerIdentityRoutes(mux, identities, serviceToken)
	}
	if workflowToken := os.Getenv("BANANAUTH_BROWSER_SERVICE_TOKEN"); workflowToken != "" {
		if len(workflowToken) < 32 || workflowToken == os.Getenv("BANANAUTH_IDENTITY_SERVICE_TOKEN") {
			return errors.New("BANANAUTH_BROWSER_SERVICE_TOKEN must be a separate token of at least 32 bytes")
		}
		registerBrowserWorkflowRoutes(mux, identities, commands, workflowToken)
	}

	if erasureToken := os.Getenv("BANANAUTH_ERASURE_SERVICE_TOKEN"); erasureToken != "" {
		if len(erasureToken) < 32 || erasureToken == os.Getenv("BANANAUTH_IDENTITY_SERVICE_TOKEN") || erasureToken == os.Getenv("BANANAUTH_BROWSER_SERVICE_TOKEN") {
			return errors.New("BANANAUTH_ERASURE_SERVICE_TOKEN must be a separate token of at least 32 bytes")
		}
		registerAccountErasureRoutes(mux, identities, erasureToken)
	}

	replayKey := []byte(os.Getenv("BANANAUTH_VERIFICATION_REPLAY_KEY"))
	if len(replayKey) == 0 {
		replayKey = key
	}
	registerAccountRoutes(mux, identities, sessions, &SessionManager{
		key: key, expiry: 24 * time.Hour, newSessionID: uuid.NewString,
	}, discord, commands[browser.ProviderCompleteEmailVerificationV2], replayKey)
	server := &http.Server{
		Addr: address, Handler: trustForwardedAddresses(mux, proxies), ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

func routes(resolve func([]byte) ([]byte, error)) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "healthy", "service": "bananauth"})
	})
	mux.HandleFunc("GET /auth/session", func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" {
			writeJSON(w, 401, errorResponse{Error: "missing authorization header"})
			return
		}
		scheme, _, valid := strings.Cut(header, " ")
		if !valid || !strings.EqualFold(scheme, "Bearer") {
			writeJSON(w, 401, errorResponse{Error: "invalid authorization format, expected: Bearer <token>"})
			return
		}
		request, err := msgpack.Marshal(browser.ResolveRequest{
			Version: browser.ContractVersion, Audience: browser.AccountAudience,
			Credential: header,
		})
		if err != nil {
			writeJSON(w, 503, errorResponse{Error: "session service unavailable"})
			return
		}
		raw, err := resolve(request)
		var response browser.ResolveResult
		if err != nil || msgpack.Unmarshal(raw, &response) != nil || response.Version != browser.ContractVersion || response.Error == "unavailable" {
			writeJSON(w, 503, errorResponse{Error: "session service unavailable"})
			return
		}
		if !response.OK {
			writeJSON(w, 401, errorResponse{Error: "invalid or expired token"})
			return
		}
		writeJSON(w, 200, map[string]any{"valid": true, "account_id": response.AccountID})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func setting(current, legacy string) string {
	if value := os.Getenv(current); value != "" {
		return value
	}
	return os.Getenv(legacy)
}
