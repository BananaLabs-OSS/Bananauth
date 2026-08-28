package main

import (
	"net/http"
	"time"

	pulpgin "github.com/BananaLabs-OSS/Fiber/pulp/gin"
	"github.com/BananaLabs-OSS/Fiber/pulp/gin/middleware"
	"github.com/BananaLabs-OSS/Fiber/pulp/oauth"
	"github.com/bananalabs-oss/bananauth/pkg/authcrypto"
	"github.com/google/uuid"
)

type oauthUpsertResult struct {
	Account identityAccount `msgpack:"account"`
	Created bool            `msgpack:"created"`
}

func (h *OAuthHandler) discordAuthorizeComposed(c *pulpgin.Context) {
	state, err := authcrypto.GenerateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "state_error"})
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
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "state_error"})
		return
	}
	authorization, err := oauth.AuthorizationURL(oauth.AuthorizationRequest{
		Provider: "discord", RedirectBinding: h.redirectBinding, State: state,
	})
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, middleware.ErrorResponse{Error: "provider_unavailable"})
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, authorization.URL)
}

func (h *OAuthHandler) discordCallbackComposed(c *pulpgin.Context) {
	code, state := c.Query("code"), c.Query("state")
	consumed, err := callIdentity[map[string]any](h.identity, identityOAuthStateConsumeEvent, map[string]any{
		"request_id": identityRequestID("oauth-state-consume"), "state": state,
		"provider": "discord", "redirect_binding": h.redirectBinding, "now": time.Now().UTC().UnixMilli(),
	})
	if err != nil || !consumed.OK {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_state", Message: "OAuth state mismatch or expired"})
		return
	}
	identity, err := oauth.Exchange(oauth.ExchangeRequest{
		Provider: "discord", Code: code, RedirectBinding: h.redirectBinding,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "exchange_failed", Message: "Failed to exchange OAuth code"})
		return
	}
	accountID, linkID := uuid.NewString(), uuid.NewString()
	result, err := callIdentity[oauthUpsertResult](h.identity, identityOAuthUpsertEvent, map[string]any{
		"request_id": identityRequestID("oauth-upsert"), "account_id": accountID, "link_id": linkID,
		"provider": identity.Provider, "provider_id": identity.Subject, "provider_email": identity.Email,
		"now": time.Now().UTC().UnixMilli(),
	})
	if err != nil || !result.OK {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "creation_failed"})
		return
	}
	parsed, err := uuid.Parse(result.Value.Account.AccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "session_error"})
		return
	}
	token, expires, err := h.sessions.Create(parsed)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "session_error"})
		return
	}
	status := http.StatusOK
	if result.Value.Created {
		status = http.StatusCreated
	}
	c.JSON(status, TokenResponse{AccessToken: token, ExpiresIn: expires, AccountID: result.Value.Account.AccountID})
}
