package main

import (
	identitysvc "github.com/bananalabs-oss/bananauth/internal/identity"
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
	result, err := h.identity.ProfileCreate(identitysvc.ProfileCreateRequest{RequestID: identityRequestID("profile-create"), Profile: identitysvc.Profile{AccountID: accountID, DisplayName: req.DisplayName, CreatedAt: now, UpdatedAt: now}})
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
	result, err := h.identity.ProfileGet(identitysvc.ProfileGetRequest{AccountID: id})
	if err == nil && result.OK {
		writeJSON(w, http.StatusOK, result.Value)
		return
	}
	if err == nil && result.Error != nil && result.Error.Code == "not_found" {
		account, err := h.identity.AccountGet(identitysvc.AccountGetRequest{AccountID: id})
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
	result, err := h.identity.ProfileUpdate(identitysvc.ProfileUpdateRequest{RequestID: identityRequestID("profile-update"), AccountID: accountID, DisplayName: req.DisplayName, Now: time.Now().UTC().UnixMilli()})
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
