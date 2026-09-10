package main

import (
	"os"
	"strings"
	"testing"
)

func TestBrowserSessionBoundaryHasExactAuthority(t *testing.T) {
	wire, err := os.ReadFile("pulp.cell.toml")
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(wire)
	for _, required := range []string{
		`provides = ["auth.browser-session.v1.resolve"]`,
		`consumes = ["auth.session.v1.get"]`,
		`depends_on = ["auth-session"]`,
		`capabilities = ["identity.jwt.hs256"]`,
	} {
		if !strings.Contains(manifest, required) {
			t.Fatalf("missing exact boundary %q in:\n%s", required, manifest)
		}
	}
	for _, forbidden := range []string{"storage.", "transport.", "notification", "email", "oauth", "workers", "spawn.", "entropy"} {
		if strings.Contains(manifest[strings.Index(manifest, "capabilities ="):], forbidden) {
			t.Fatalf("credential boundary gained forbidden capability %q", forbidden)
		}
	}
}
