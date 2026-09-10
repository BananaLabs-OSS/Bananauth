package main

import (
	"os"
	"strings"
	"testing"
)

func TestOutboundDeliveryConfigFailsClosed(t *testing.T) {
	for _, value := range []string{"", "false", "1", "yes", "enabled", " true-ish "} {
		if outboundDeliveryEnabled(value) {
			t.Fatalf("delivery enabled by %q", value)
		}
	}
	for _, value := range []string{"true", "TRUE", " true "} {
		if !outboundDeliveryEnabled(value) {
			t.Fatalf("delivery rejected %q", value)
		}
	}
}

func TestLegacyOutboundDeliveryNeverFallsBackToPlaintextOTPLogging(t *testing.T) {
	if err := validateLegacyOutboundDelivery("true", ""); err == nil {
		t.Fatal("delivery without a credential did not fail closed")
	}
	if err := validateLegacyOutboundDelivery("false", "configured"); err == nil {
		t.Fatal("delivery without explicit activation did not fail closed")
	}
	if err := validateLegacyOutboundDelivery("true", "configured"); err != nil {
		t.Fatalf("fully configured delivery rejected: %v", err)
	}
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"Password reset OTP for", "log.Printf", "fmt.Printf"} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("legacy HTTP cell retains plaintext OTP logging path %q", forbidden)
		}
	}
}
