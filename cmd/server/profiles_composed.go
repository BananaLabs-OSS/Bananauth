package main

import (
	"net/http"
	"strings"
	"time"
)

type identityProfile struct {
	AccountID   string `msgpack:"account_id" json:"account_id"`
	DisplayName string `msgpack:"display_name" json:"display_name"`
	CreatedAt   int64  `msgpack:"created_at" json:"created_at"`
	UpdatedAt   int64  `msgpack:"updated_at" json:"updated_at"`
}

func (h *ProfileHandler) createComposed(w http.ResponseWriter, r *http.Request) {
	var req CreateProfileRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	accountID := accountID(r)
	now := time.Now().UTC().UnixMilli()
	result, err := callIdentity[identityProfile](h.identity, identityProfileCreateEvent, map[string]any{
		"request_id": identityRequestID("profile-create"),
		"profile":    map[string]any{"account_id": accountID, "display_name": req.DisplayName, "created_at": now, "updated_at": now},
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "creation_failed"})
		return
	}
	if !result.OK {
		identityFailure(w, r, result.Error, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, result.Value)
}

func (h *ProfileHandler) getComposed(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	request := map[string]any{"account_id": id}
	result, err := callIdentity[identityProfile](h.identity, identityProfileGetEvent, request)
	if err == nil && result.OK {
		writeJSON(w, http.StatusOK, result.Value)
		return
	}
	if err == nil && result.Error != nil && result.Error.Code == "not_found" {
		account, err := callIdentity[identityAccount](h.identity, identityAccountGetEvent, request)
		if err == nil && account.OK && strings.TrimSpace(account.Value.Username) != "" {
			writeJSON(w, http.StatusOK, identityProfile{AccountID: id, DisplayName: strings.TrimSpace(account.Value.Username)})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, errorResponse{Error: "not_found", Message: "Profile not found"})
}

func (h *ProfileHandler) updateComposed(w http.ResponseWriter, r *http.Request) {
	var req UpdateProfileRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	accountID := accountID(r)
	result, err := callIdentity[identityProfile](h.identity, identityProfileUpdateEvent, map[string]any{
		"request_id": identityRequestID("profile-update"), "account_id": accountID,
		"display_name": req.DisplayName, "now": time.Now().UTC().UnixMilli(),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "update_failed"})
		return
	}
	if !result.OK {
		identityFailure(w, r, result.Error, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, result.Value)
}
