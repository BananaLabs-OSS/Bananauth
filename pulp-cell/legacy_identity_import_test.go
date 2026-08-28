package main

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBuildLegacyIdentityImportIsOrderIndependentAndBoundToContent(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	accountA := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	accountB := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	credentialA := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	credentialB := uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")

	accounts := []Account{
		{ID: accountB, CreatedAt: now.Add(time.Second)},
		{ID: accountA, CreatedAt: now},
	}
	native := []NativeAccount{
		{ID: credentialB, AccountID: accountB, Email: "b@example.test", Username: "b", PasswordHash: "hash-b", CreatedAt: now.Add(time.Second)},
		{ID: credentialA, AccountID: accountA, Email: "a@example.test", Username: "a", PasswordHash: "hash-a", CreatedAt: now},
	}

	first, err := buildLegacyIdentityImport(accounts, native, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildLegacyIdentityImport(
		[]Account{accounts[1], accounts[0]},
		[]NativeAccount{native[1], native[0]},
		nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID != second.RequestID {
		t.Fatalf("order changed request id: %q != %q", first.RequestID, second.RequestID)
	}
	if first.Accounts[0].AccountID > first.Accounts[1].AccountID || first.Native[0].ID > first.Native[1].ID {
		t.Fatal("legacy import rows are not in canonical order")
	}

	native[0].PasswordHash = "changed-hash"
	changed, err := buildLegacyIdentityImport(accounts, native, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if changed.RequestID == first.RequestID {
		t.Fatal("request id did not bind changed credential content")
	}
}

func TestHasLegacyIdentityRows(t *testing.T) {
	if hasLegacyIdentityRows(nil, nil, nil, nil, nil) {
		t.Fatal("empty legacy source must not create a migration command")
	}
	if !hasLegacyIdentityRows([]Account{{}}, nil, nil, nil, nil) {
		t.Fatal("nonempty legacy source must remain eligible for import")
	}
}
