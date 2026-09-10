package main

import (
	"os"
	"strings"
	"testing"
)

func TestIdentityOwnerDeclaresStorageOnlyCapability(t *testing.T) {
	wire, err := os.ReadFile("pulp.cell.toml")
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(wire)
	if !strings.Contains(manifest, `capabilities = ["storage.sqlite"]`) {
		t.Fatalf("identity owner capability boundary widened: %s", manifest)
	}
	for _, forbidden := range []string{"workers", "transport.http", "notification", "email", "payment", "spawn."} {
		if strings.Contains(manifest[strings.Index(manifest, "capabilities ="):], forbidden) {
			t.Fatalf("identity state owner gained forbidden capability %q", forbidden)
		}
	}
}
