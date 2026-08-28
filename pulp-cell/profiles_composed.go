package main

import (
	"net/http"
	"time"

	pulpgin "github.com/BananaLabs-OSS/Fiber/pulp/gin"
	"github.com/BananaLabs-OSS/Fiber/pulp/gin/middleware"
)

type identityProfile struct {
	AccountID   string `msgpack:"account_id" json:"account_id"`
	DisplayName string `msgpack:"display_name" json:"display_name"`
	CreatedAt   int64  `msgpack:"created_at" json:"created_at"`
	UpdatedAt   int64  `msgpack:"updated_at" json:"updated_at"`
}

func (h *ProfileHandler) createComposed(c *pulpgin.Context) {
	var req CreateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	accountID, _ := c.Get("account_id")
	now := time.Now().UTC().UnixMilli()
	result, err := callIdentity[identityProfile](h.identity, identityProfileCreateEvent, map[string]any{
		"request_id": identityRequestID("profile-create"),
		"profile":    map[string]any{"account_id": accountID, "display_name": req.DisplayName, "created_at": now, "updated_at": now},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "creation_failed"})
		return
	}
	if !result.OK {
		identityFailure(c, result.Error, http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusCreated, result.Value)
}

func (h *ProfileHandler) getComposed(c *pulpgin.Context) {
	result, err := callIdentity[identityProfile](h.identity, identityProfileGetEvent, map[string]any{"account_id": c.Param("id")})
	if err != nil || !result.OK {
		c.JSON(http.StatusNotFound, middleware.ErrorResponse{Error: "not_found", Message: "Profile not found"})
		return
	}
	c.JSON(http.StatusOK, result.Value)
}

func (h *ProfileHandler) updateComposed(c *pulpgin.Context) {
	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	accountID, _ := c.Get("account_id")
	result, err := callIdentity[identityProfile](h.identity, identityProfileUpdateEvent, map[string]any{
		"request_id": identityRequestID("profile-update"), "account_id": accountID,
		"display_name": req.DisplayName, "now": time.Now().UTC().UnixMilli(),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "update_failed"})
		return
	}
	if !result.OK {
		identityFailure(c, result.Error, http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, result.Value)
}
