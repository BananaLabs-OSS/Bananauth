package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/uptrace/bun"
	"github.com/vmihailenco/msgpack/v5"
)

// These migration-only DTOs mirror auth-identity.v1.legacy.import. Password
// hashes remain inside the application boundary and are never returned by an
// owner projection.
type legacyIdentityAccount struct {
	AccountID string `msgpack:"account_id"`
	Email     string `msgpack:"email,omitempty"`
	Username  string `msgpack:"username,omitempty"`
	CreatedAt int64  `msgpack:"created_at"`
}

type legacyIdentityNative struct {
	ID           string `msgpack:"id"`
	AccountID    string `msgpack:"account_id"`
	Email        string `msgpack:"email"`
	Username     string `msgpack:"username"`
	PasswordHash string `msgpack:"password_hash"`
	CreatedAt    int64  `msgpack:"created_at"`
}

type legacyIdentityOAuthLink struct {
	ID            string `msgpack:"id"`
	AccountID     string `msgpack:"account_id"`
	Provider      string `msgpack:"provider"`
	ProviderID    string `msgpack:"provider_id"`
	ProviderEmail string `msgpack:"provider_email"`
	CreatedAt     int64  `msgpack:"created_at"`
}

type legacyIdentityOTP struct {
	ID        string `msgpack:"id"`
	Email     string `msgpack:"email"`
	Code      string `msgpack:"code"`
	Type      string `msgpack:"type"`
	ExpiresAt int64  `msgpack:"expires_at"`
	AccountID string `msgpack:"account_id"`
}

type legacyIdentityProfile struct {
	AccountID   string `msgpack:"account_id"`
	DisplayName string `msgpack:"display_name"`
	CreatedAt   int64  `msgpack:"created_at"`
	UpdatedAt   int64  `msgpack:"updated_at"`
}

type legacyIdentityImportRequest struct {
	RequestID  string                    `msgpack:"request_id"`
	Accounts   []legacyIdentityAccount   `msgpack:"accounts"`
	Native     []legacyIdentityNative    `msgpack:"native"`
	OAuthLinks []legacyIdentityOAuthLink `msgpack:"oauth_links"`
	OTPs       []legacyIdentityOTP       `msgpack:"otps"`
	Profiles   []legacyIdentityProfile   `msgpack:"profiles"`
}

type legacyIdentityImportResult struct {
	Accounts   int `msgpack:"accounts"`
	Native     int `msgpack:"native"`
	OAuthLinks int `msgpack:"oauth_links"`
	OTPs       int `msgpack:"otps"`
	Profiles   int `msgpack:"profiles"`
}

func importLegacyIdentity(ctx context.Context, database *bun.DB, dispatch sessionDispatcher) error {
	if database == nil {
		return fmt.Errorf("legacy identity import database is nil")
	}
	if dispatch == nil {
		return fmt.Errorf("legacy identity import dispatcher is nil")
	}

	var accounts []Account
	var native []NativeAccount
	var oauthLinks []OAuthLink
	var otps []OTPCode
	var profiles []Profile
	for _, query := range []struct {
		name  string
		model any
	}{
		{name: "accounts", model: &accounts},
		{name: "native credentials", model: &native},
		{name: "OAuth links", model: &oauthLinks},
		{name: "OTP codes", model: &otps},
		{name: "profiles", model: &profiles},
	} {
		if err := database.NewSelect().Model(query.model).Scan(ctx); err != nil {
			return fmt.Errorf("load legacy identity %s: %w", query.name, err)
		}
	}
	// A fresh composed deployment has no compatibility records to migrate.
	// Do not manufacture an empty owner command/receipt: migration is only a
	// boundary operation when there is actual legacy state to carry forward.
	if !hasLegacyIdentityRows(accounts, native, oauthLinks, otps, profiles) {
		return nil
	}

	request, err := buildLegacyIdentityImport(accounts, native, oauthLinks, otps, profiles)
	if err != nil {
		return err
	}
	result, err := callIdentity[legacyIdentityImportResult](dispatch, identityLegacyImportEvent, request)
	if err != nil {
		return fmt.Errorf("dispatch legacy identity import: %w", err)
	}
	if !result.OK {
		if result.Error == nil {
			return fmt.Errorf("legacy identity import rejected without an error")
		}
		return fmt.Errorf("legacy identity import rejected: %s: %s", result.Error.Code, result.Error.Message)
	}
	return nil
}

func hasLegacyIdentityRows(accounts []Account, native []NativeAccount, oauthLinks []OAuthLink, otps []OTPCode, profiles []Profile) bool {
	return len(accounts) != 0 || len(native) != 0 || len(oauthLinks) != 0 || len(otps) != 0 || len(profiles) != 0
}

func buildLegacyIdentityImport(
	accounts []Account,
	native []NativeAccount,
	oauthLinks []OAuthLink,
	otps []OTPCode,
	profiles []Profile,
) (legacyIdentityImportRequest, error) {
	request := legacyIdentityImportRequest{
		Accounts:   make([]legacyIdentityAccount, 0, len(accounts)),
		Native:     make([]legacyIdentityNative, 0, len(native)),
		OAuthLinks: make([]legacyIdentityOAuthLink, 0, len(oauthLinks)),
		OTPs:       make([]legacyIdentityOTP, 0, len(otps)),
		Profiles:   make([]legacyIdentityProfile, 0, len(profiles)),
	}
	for _, row := range accounts {
		request.Accounts = append(request.Accounts, legacyIdentityAccount{
			AccountID: row.ID.String(),
			CreatedAt: row.CreatedAt.UTC().UnixMilli(),
		})
	}
	for _, row := range native {
		request.Native = append(request.Native, legacyIdentityNative{
			ID:           row.ID.String(),
			AccountID:    row.AccountID.String(),
			Email:        row.Email,
			Username:     row.Username,
			PasswordHash: row.PasswordHash,
			CreatedAt:    row.CreatedAt.UTC().UnixMilli(),
		})
	}
	for _, row := range oauthLinks {
		request.OAuthLinks = append(request.OAuthLinks, legacyIdentityOAuthLink{
			ID:            row.ID.String(),
			AccountID:     row.AccountID.String(),
			Provider:      row.Provider,
			ProviderID:    row.ProviderID,
			ProviderEmail: row.ProviderEmail,
			CreatedAt:     row.CreatedAt.UTC().UnixMilli(),
		})
	}
	for _, row := range otps {
		request.OTPs = append(request.OTPs, legacyIdentityOTP{
			ID:        row.ID.String(),
			Email:     row.Email,
			Code:      row.Code,
			Type:      row.Type,
			ExpiresAt: row.ExpiresAt.UTC().UnixMilli(),
			AccountID: row.Metadata,
		})
	}
	for _, row := range profiles {
		request.Profiles = append(request.Profiles, legacyIdentityProfile{
			AccountID:   row.AccountID.String(),
			DisplayName: row.DisplayName,
			CreatedAt:   row.CreatedAt.UTC().UnixMilli(),
			UpdatedAt:   row.UpdatedAt.UTC().UnixMilli(),
		})
	}

	sort.Slice(request.Accounts, func(i, j int) bool { return request.Accounts[i].AccountID < request.Accounts[j].AccountID })
	sort.Slice(request.Native, func(i, j int) bool { return request.Native[i].ID < request.Native[j].ID })
	sort.Slice(request.OAuthLinks, func(i, j int) bool { return request.OAuthLinks[i].ID < request.OAuthLinks[j].ID })
	sort.Slice(request.OTPs, func(i, j int) bool { return request.OTPs[i].ID < request.OTPs[j].ID })
	sort.Slice(request.Profiles, func(i, j int) bool { return request.Profiles[i].AccountID < request.Profiles[j].AccountID })

	wire, err := msgpack.Marshal(request)
	if err != nil {
		return legacyIdentityImportRequest{}, fmt.Errorf("encode legacy identity import: %w", err)
	}
	digest := sha256.Sum256(wire)
	request.RequestID = "legacy-import:" + hex.EncodeToString(digest[:])
	return request, nil
}
