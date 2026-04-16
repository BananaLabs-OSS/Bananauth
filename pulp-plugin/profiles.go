package main

import (
	"net/http"
	"time"

	pulpgin "github.com/BananaLabs-OSS/Fiber/pulp/gin"
	"github.com/BananaLabs-OSS/Fiber/pulp/gin/middleware"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type ProfileHandler struct {
	db *bun.DB
}

func NewProfileHandler(db *bun.DB) *ProfileHandler {
	return &ProfileHandler{db: db}
}

func (h *ProfileHandler) Create(c *pulpgin.Context) {
	var req CreateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}

	accountID, _ := c.Get("account_id")
	ctx := c.Ctx()

	var existing Profile
	err := h.db.NewSelect().Model(&existing).Where("account_id = ?", accountID).Scan(ctx)
	if err == nil {
		c.JSON(http.StatusConflict, middleware.ErrorResponse{Error: "profile_exists", Message: "Profile already exists for this account"})
		return
	}

	now := time.Now().UTC()
	profile := Profile{
		AccountID:   uuid.MustParse(accountID.(string)),
		DisplayName: req.DisplayName,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if _, err := h.db.NewInsert().Model(&profile).Exec(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "creation_failed"})
		return
	}
	c.JSON(http.StatusCreated, profile)
}

func (h *ProfileHandler) Get(c *pulpgin.Context) {
	id := c.Param("id")
	ctx := c.Ctx()

	var profile Profile
	err := h.db.NewSelect().Model(&profile).Where("account_id = ?", id).Scan(ctx)
	if err != nil {
		c.JSON(http.StatusNotFound, middleware.ErrorResponse{Error: "not_found", Message: "Profile not found"})
		return
	}
	c.JSON(http.StatusOK, profile)
}

func (h *ProfileHandler) Update(c *pulpgin.Context) {
	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}

	accountID, _ := c.Get("account_id")
	ctx := c.Ctx()

	var profile Profile
	err := h.db.NewSelect().Model(&profile).Where("account_id = ?", accountID).Scan(ctx)
	if err != nil {
		c.JSON(http.StatusNotFound, middleware.ErrorResponse{Error: "not_found", Message: "Profile not found"})
		return
	}

	if req.DisplayName != "" {
		profile.DisplayName = req.DisplayName
	}
	profile.UpdatedAt = time.Now().UTC()

	if _, err := h.db.NewUpdate().Model(&profile).WherePK().Exec(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "update_failed"})
		return
	}
	c.JSON(http.StatusOK, profile)
}
