package handlers

import (
	"net/http"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type ProfileHandler struct {
	db *bun.DB
}

func NewProfileHandler(db *bun.DB) *ProfileHandler {
	return &ProfileHandler{db: db}
}

func (h *ProfileHandler) Create(c *gin.Context) {
	var req models.CreateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

	accountID, _ := c.Get("account_id")
	ctx := c.Request.Context()

	var existing models.Profile
	err := h.db.NewSelect().Model(&existing).Where("account_id = ?", accountID).Scan(ctx)
	if err == nil {
		c.JSON(http.StatusConflict, models.ErrorResponse{
			Error:   "profile_exists",
			Message: "Profile already exists for this account",
		})
		return
	}

	now := time.Now().UTC()
	profile := models.Profile{
		AccountID:   uuid.MustParse(accountID.(string)),
		DisplayName: req.DisplayName,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if _, err := h.db.NewInsert().Model(&profile).Exec(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "creation_failed"})
		return
	}

	c.JSON(http.StatusCreated, profile)
}

func (h *ProfileHandler) Get(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	var profile models.Profile
	err := h.db.NewSelect().Model(&profile).Where("account_id = ?", id).Scan(ctx)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:   "not_found",
			Message: "Profile not found",
		})
		return
	}

	c.JSON(http.StatusOK, profile)
}

func (h *ProfileHandler) Update(c *gin.Context) {
	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

	accountID, _ := c.Get("account_id")
	ctx := c.Request.Context()

	var profile models.Profile
	err := h.db.NewSelect().Model(&profile).Where("account_id = ?", accountID).Scan(ctx)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:   "not_found",
			Message: "Profile not found",
		})
		return
	}

	if req.DisplayName != "" {
		profile.DisplayName = req.DisplayName
	}
	profile.UpdatedAt = time.Now().UTC()

	if _, err := h.db.NewUpdate().Model(&profile).WherePK().Exec(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "update_failed"})
		return
	}

	c.JSON(http.StatusOK, profile)
}
