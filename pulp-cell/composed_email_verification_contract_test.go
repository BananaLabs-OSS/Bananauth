package main

import (
	"os"
	"strings"
	"testing"
)

func TestComposedEmailVerificationRoutesAreOwnerBackedAndLegacyGated(t *testing.T) {
	composition, err := os.ReadFile("identity_composition.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`identityEmailVerificationIssueEvent   = "bananauth.identity.email-verification.issue.v1"`,
		`identityEmailVerificationConsumeEvent = "bananauth.identity.email-verification.consume.v1"`,
	} {
		if !strings.Contains(string(composition), required) {
			t.Fatalf("identity composition is missing %q", required)
		}
	}

	router, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"if cfg.ComposedIdentity {",
		`auth.POST("/email-verification", authH.IssueEmailVerification)`,
		`auth.POST("/email-verification/consume", authH.ConsumeEmailVerification)`,
	} {
		if !strings.Contains(string(router), required) {
			t.Fatalf("router is missing composed-only declaration %q", required)
		}
	}

	handler, err := os.ReadFile("auth_composed.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"identityEmailVerificationIssueEvent",
		"identityEmailVerificationConsumeEvent",
		`"verification_id": uuid.NewString()`,
		`"effect_id": uuid.NewString()`,
		"authcrypto.GenerateOTP()",
	} {
		if !strings.Contains(string(handler), required) {
			t.Fatalf("composed handler is missing owner-backed behavior %q", required)
		}
	}
}
