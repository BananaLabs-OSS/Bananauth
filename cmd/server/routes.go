package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}
type AuthHandler struct {
	identity              sessionDispatcher
	completeV2            func([]byte) ([]byte, error)
	sessions              *SessionManager
	verificationReplayKey []byte
}
type ProfileHandler struct{ identity sessionDispatcher }
type authenticatedAccount struct{ account, session string }
type authContextKey struct{}

const resetPwMaxTry = 5
const resetPwWindow = 10 * time.Second

func readJSON(w http.ResponseWriter, r *http.Request, value any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(value)
}
func clientIP(r *http.Request) string {
	if forwarded, ok := r.Context().Value(clientAddressKey{}).(string); ok {
		return forwarded
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
func authentication(r *http.Request) authenticatedAccount {
	proof, _ := r.Context().Value(authContextKey{}).(authenticatedAccount)
	return proof
}
func accountID(r *http.Request) string { return authentication(r).account }

func (m *SessionManager) protect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		scheme, proof, _ := strings.Cut(header, " ")
		claims, err := m.key.Verify(proof)
		if !strings.EqualFold(scheme, "Bearer") || err != nil {
			writeJSON(w, 401, errorResponse{Error: "unauthorized"})
			return
		}
		active, err := m.check(claims.AccountID, claims.SessionID)
		if err != nil {
			writeJSON(w, 503, errorResponse{Error: "session_unavailable"})
			return
		}
		if !active {
			writeJSON(w, 401, errorResponse{Error: "unauthorized"})
			return
		}
		identity := authenticatedAccount{account: claims.AccountID, session: claims.SessionID}
		next(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, identity)))
	}
}

func registerAccountRoutes(mux *http.ServeMux, identities, sessions map[string]func([]byte) ([]byte, error), manager *SessionManager, discord *discordProvider, completeV2 func([]byte) ([]byte, error), replayKey []byte) {
	identityCall := func(event string, wire []byte) ([]byte, error) {
		operation, version, ok := strings.Cut(strings.TrimPrefix(event, "bananauth.identity."), ".v")
		if !ok || operation == "" || (version != "1" && version != "2") {
			return nil, fmt.Errorf("unknown identity operation %q", event)
		}
		name := "auth.identity.v" + version + "." + operation
		execute := identities[name]
		if execute == nil {
			return nil, fmt.Errorf("unknown identity operation %q", event)
		}
		return execute(wire)
	}
	sessionNames := map[string]string{
		sessionCreatedEvent: "auth.session.v1.create", sessionCreatedOwnedEvent: "auth.session.v1.create-owned",
		sessionVerifiedEvent: "auth.session.v1.get", sessionRevokedOwnedEvent: "auth.session.v1.revoke-owned",
	}
	manager.dispatch = func(event string, wire []byte) ([]byte, error) {
		execute := sessions[sessionNames[event]]
		if execute == nil {
			return nil, fmt.Errorf("unknown session operation %q", event)
		}
		return execute(wire)
	}
	auth := &AuthHandler{identity: identityCall, sessions: manager, completeV2: completeV2, verificationReplayKey: replayKey}
	profiles := &ProfileHandler{identity: identityCall}
	methods := []string{"password"}
	if discord != nil {
		oauth := &OAuthHandler{identity: identityCall, sessions: manager, redirectBinding: discord.redirectURL, discord: discord}
		mux.HandleFunc("GET /auth/oauth/discord", oauth.discordAuthorizeComposed)
		mux.HandleFunc("GET /auth/oauth/discord/callback", oauth.discordCallbackComposed)
		methods = append(methods, "discord")
	}
	mux.HandleFunc("GET /auth/config", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string][]string{"methods": methods})
	})
	mux.HandleFunc("POST /auth/register", auth.registerComposed)
	mux.HandleFunc("POST /auth/login", auth.loginComposed)
	mux.HandleFunc("POST /auth/password/forgot", auth.forgotPasswordComposed)
	mux.HandleFunc("POST /auth/password/reset", auth.resetPasswordComposed)
	mux.HandleFunc("POST /auth/email-verification", auth.issueEmailVerificationComposed)
	mux.HandleFunc("POST /auth/email-verification/consume", auth.consumeEmailVerificationComposed)
	mux.HandleFunc("POST /auth/email-verification/session", auth.completeEmailVerificationSessionComposed)
	mux.HandleFunc("POST /auth/email-verification/v2", auth.IssueEmailVerificationV2)
	mux.HandleFunc("POST /auth/email-verification/v2/consume", auth.ConsumeEmailVerificationV2)
	mux.HandleFunc("POST /auth/email-verification/v2/session", auth.CompleteEmailVerificationSessionV2)
	mux.HandleFunc("POST /auth/logout", manager.protect(func(w http.ResponseWriter, r *http.Request) {
		if err := manager.RevokeChecked(authentication(r).session); err != nil {
			writeJSON(w, 503, errorResponse{Error: "session_revoke_unavailable"})
			return
		}
		writeJSON(w, 200, map[string]string{"message": "logged out"})
	}))
	mux.HandleFunc("POST /auth/password", manager.protect(auth.changePasswordComposed))
	mux.HandleFunc("POST /auth/password/attach", manager.protect(auth.attachNativeCredentialComposed))
	mux.HandleFunc("DELETE /auth/account", manager.protect(auth.deleteAccountComposed))
	mux.HandleFunc("GET /profiles/{id}", profiles.getComposed)
	mux.HandleFunc("POST /profiles", manager.protect(profiles.createComposed))
	mux.HandleFunc("PUT /profiles", manager.protect(profiles.updateComposed))
}
