package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Account is the identity — "you exist"
type Account struct {
	bun.BaseModel `bun:"table:auth_accounts,alias:a"`

	ID        uuid.UUID `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`

	Native *NativeAccount `bun:"rel:has-one,join:id=account_id" json:"native,omitempty"`
}

// NativeAccount is email/password authentication
type NativeAccount struct {
	bun.BaseModel `bun:"table:auth_native,alias:n"`

	ID           uuid.UUID `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	AccountID    uuid.UUID `bun:"account_id,notnull,type:uuid" json:"account_id"`
	Email        string    `bun:"email,notnull,unique" json:"email"`
	Username     string    `bun:"username,notnull,unique" json:"username"`
	PasswordHash string    `bun:"password_hash,notnull" json:"-"`
	CreatedAt    time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`

	Account *Account `bun:"rel:belongs-to,join:account_id=id" json:"-"`
}
