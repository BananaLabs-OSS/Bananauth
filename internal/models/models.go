package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Account is the identity — "you exist"
type Account struct {
	bun.BaseModel `bun:"table:auth_accounts,alias:a"`

	ID        uuid.UUID `bun:"id,pk,type:uuid" json:"id"`
	CreatedAt time.Time `bun:"created_at,nullzero,notnull" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,nullzero,notnull" json:"updated_at"`

	Native     *NativeAccount `bun:"rel:has-one,join:id=account_id" json:"native,omitempty"`
	OAuthLinks []*OAuthLink   `bun:"rel:has-many,join:id=account_id" json:"oauth_links,omitempty"`
}

// NativeAccount is email/password authentication
type NativeAccount struct {
	bun.BaseModel `bun:"table:auth_native,alias:n"`

	ID           uuid.UUID `bun:"id,pk,type:uuid" json:"id"`
	AccountID    uuid.UUID `bun:"account_id,notnull,type:uuid" json:"account_id"`
	Email        string    `bun:"email,notnull,unique" json:"email"`
	Username     string    `bun:"username,notnull,unique" json:"username"`
	PasswordHash string    `bun:"password_hash,notnull" json:"-"`
	CreatedAt    time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`

	Account *Account `bun:"rel:belongs-to,join:account_id=id" json:"-"`
}

// OAuthLink is a provider login linked to an account
type OAuthLink struct {
	bun.BaseModel `bun:"table:auth_oauth,alias:o"`

	ID            uuid.UUID `bun:"id,pk,type:uuid" json:"id"`
	AccountID     uuid.UUID `bun:"account_id,notnull,type:uuid" json:"account_id"`
	Provider      string    `bun:"provider,notnull" json:"provider"`
	ProviderID    string    `bun:"provider_id,notnull" json:"provider_id"`
	ProviderEmail string    `bun:"provider_email" json:"provider_email,omitempty"`
	CreatedAt     time.Time `bun:"created_at,notnull" json:"created_at"`

	Account *Account `bun:"rel:belongs-to,join:account_id=id" json:"-"`
}

type OTPCode struct {
	bun.BaseModel `bun:"table:auth_otp_codes,alias:otp"`

	ID        uuid.UUID `bun:"id,pk,type:uuid" json:"id"`
	Email     string    `bun:"email,notnull" json:"email"`
	Code      string    `bun:"code,notnull" json:"code"`
	Type      string    `bun:"type,notnull" json:"type"`
	ExpiresAt time.Time `bun:"expires_at,notnull" json:"expires_at"`
	CreatedAt time.Time `bun:"created_at,notnull" json:"created_at"`
	Metadata  string    `bun:"metadata" json:"metadata,omitempty"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type DeleteAccountRequest struct {
	Password string `json:"password" binding:"required"`
}

type Profile struct {
	bun.BaseModel `bun:"table:profiles,alias:p"`

	AccountID   uuid.UUID `bun:"account_id,pk,type:uuid" json:"account_id"`
	DisplayName string    `bun:"display_name,notnull" json:"display_name"`
	CreatedAt   time.Time `bun:"created_at,notnull" json:"created_at"`
	UpdatedAt   time.Time `bun:"updated_at,notnull" json:"updated_at"`
}

type CreateProfileRequest struct {
	DisplayName string `json:"display_name" binding:"required,min=2,max=32"`
}

type UpdateProfileRequest struct {
	DisplayName string `json:"display_name" binding:"omitempty,min=2,max=32"`
}

// --- Request / Response types ---

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Username string `json:"username" binding:"required,min=3,max=32"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	AccountID   string `json:"account_id"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}
