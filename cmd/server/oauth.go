package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bananalabs-oss/bananauth/pkg/authcrypto"
	"github.com/google/uuid"
)

type oauthUpsertResult struct {
	Account identityAccount `msgpack:"account"`
	Created bool            `msgpack:"created"`
}

func (h *OAuthHandler) discordAuthorizeComposed(w http.ResponseWriter, r *http.Request) {
	state, err := authcrypto.GenerateState()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "state_error"})
		return
	}
	now := time.Now().UTC()
	result, err := callIdentity[map[string]any](h.identity, identityOAuthStateIssueEvent, map[string]any{
		"request_id": identityRequestID("oauth-state-issue"),
		"state": map[string]any{
			"state": state, "provider": "discord", "redirect_binding": h.redirectBinding,
			"expires_at": now.Add(10 * time.Minute).UnixMilli(),
		},
	})
	if err != nil || !result.OK {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "state_error"})
		return
	}
	params := url.Values{"client_id": {h.discord.clientID}, "redirect_uri": {h.redirectBinding},
		"response_type": {"code"}, "scope": {"identify email"}, "state": {state}}
	http.Redirect(w, r, h.discord.base+"/api/oauth2/authorize?"+params.Encode(), http.StatusTemporaryRedirect)
}

func (h *OAuthHandler) discordCallbackComposed(w http.ResponseWriter, r *http.Request) {
	code, state := r.URL.Query().Get("code"), r.URL.Query().Get("state")
	consumed, err := callIdentity[map[string]any](h.identity, identityOAuthStateConsumeEvent, map[string]any{
		"request_id": identityRequestID("oauth-state-consume"), "state": state,
		"provider": "discord", "redirect_binding": h.redirectBinding, "now": time.Now().UTC().UnixMilli(),
	})
	if err != nil || !consumed.OK {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_state", Message: "OAuth state mismatch or expired"})
		return
	}
	identity, err := h.discord.exchange(r.Context(), code, h.redirectBinding)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "exchange_failed", Message: "Failed to exchange OAuth code"})
		return
	}
	accountID, linkID := uuid.NewString(), uuid.NewString()
	result, err := callIdentity[oauthUpsertResult](h.identity, identityOAuthUpsertEvent, map[string]any{
		"request_id": identityRequestID("oauth-upsert"), "account_id": accountID, "link_id": linkID,
		"provider": "discord", "provider_id": identity.ID, "provider_email": identity.Email,
		"now": time.Now().UTC().UnixMilli(),
	})
	if err != nil || !result.OK {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "creation_failed"})
		return
	}
	parsed, err := uuid.Parse(result.Value.Account.AccountID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "session_error"})
		return
	}
	token, expires, err := h.sessions.Create(parsed)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "session_error"})
		return
	}
	status := http.StatusOK
	if result.Value.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, TokenResponse{AccessToken: token, ExpiresIn: expires, AccountID: result.Value.Account.AccountID})
}

type discordProvider struct {
	clientID, clientSecret, redirectURL, base string
	client                                    *http.Client
}

type OAuthHandler struct {
	identity        sessionDispatcher
	sessions        *SessionManager
	redirectBinding string
	discord         *discordProvider
}

type discordUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (d *discordProvider) exchange(ctx context.Context, code, redirect string) (discordUser, error) {
	var user discordUser
	if code == "" {
		return user, errors.New("OAuth code required")
	}
	form := url.Values{"client_id": {d.clientID}, "client_secret": {d.clientSecret},
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base+"/api/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return user, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := d.decode(request, &token); err != nil || token.AccessToken == "" {
		return user, errors.New("Discord token exchange failed")
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/api/users/@me", nil)
	if err != nil {
		return user, err
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	if err := d.decode(request, &user); err != nil || user.ID == "" {
		return discordUser{}, errors.New("Discord profile lookup failed")
	}
	return user, nil
}

func (d *discordProvider) decode(request *http.Request, result any) error {
	response, err := d.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("Discord rejected OAuth request")
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(result)
}
