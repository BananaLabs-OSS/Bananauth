package main

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

// AttachNativeCredentialRequest is accepted only from an authenticated
// Bananauth session. It converts an OAuth-only account into a dual-mode
// account without issuing a new account identity.
type AttachNativeCredentialRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Username string `json:"username" binding:"required,min=3,max=32"`
	Password string `json:"password" binding:"required,min=8"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// EmailVerificationIssueRequest is the public, passwordless email-code
// request. It is served only when Bananauth's composed identity owner is
// active; the HTTP shell generates no durable verification state itself.
type EmailVerificationIssueRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// EmailVerificationConsumeRequest proves a code issued by the composed
// identity owner. It deliberately carries no account/session claim; the
// consuming application owns its own presentation session.
type EmailVerificationConsumeRequest struct {
	Email string `json:"email" binding:"required,email"`
	Code  string `json:"code" binding:"required"`
}

// EmailVerificationSessionRequest is a host-to-host passwordless login
// completion. RequestID and IssuedAt are generated once by the storefront BFF
// and retained in its server-side session. They are deliberately not accepted
// from browser identity claims: the OTP remains the human proof, while the
// stable request makes owner receipts replayable after a lost response.
type EmailVerificationSessionRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Code      string `json:"code" binding:"required"`
	RequestID string `json:"request_id" binding:"required"`
}

type DeleteAccountRequest struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

type CreateProfileRequest struct {
	DisplayName string `json:"display_name" binding:"required,min=2,max=32"`
}

type UpdateProfileRequest struct {
	DisplayName string `json:"display_name" binding:"omitempty,min=2,max=32"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	AccountID   string `json:"account_id"`
}

type StorefrontSessionResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	AccountID   string `json:"account_id"`
	SessionID   string `json:"session_id"`
	ExpiresAt   int64  `json:"expires_at"`
}
