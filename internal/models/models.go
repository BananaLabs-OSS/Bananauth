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

	Native *NativeAccount `bun:"rel:has-one,join:id=account_id" json:"native,omitempty"`
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

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	AccountID   string `json:"account_id"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}
