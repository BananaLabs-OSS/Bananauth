package sessionsidentityshadow

import (
	"bytes"
	"testing"

	identitycore "github.com/SirNiklas9/pulp-engines/identity-core"
	"github.com/vmihailenco/msgpack/v5"
)

func genericSnapshot() Snapshot {
	return Snapshot{
		Principals:    []Principal{{SubjectID: "subject-1", Email: "User@Example.COM"}},
		Claims:        []ClaimMetadata{ProjectClaim(identitycore.Claim{ID: "claim-1", UserID: "subject-1", Email: "User@Example.COM", Token: "never-serialized-token", Purpose: "sign-in", CreatedAt: 10, ExpiresAt: 20})},
		Attestations:  []identitycore.SubjectAttestationRecord{{ID: "att-1", SubjectID: "subject-1", Value: identitycore.SubjectAttestation{Kind: "terms", Revision: "v1", Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", AcceptedAt: 10}}},
		Verifications: []VerificationMetadata{ProjectVerification(identitycore.Verification{ID: "verify-1", Email: "User@Example.COM", Code: "never-serialized-code", CreatedAt: 10, ExpiresAt: 20, AttemptCount: 1})},
		Bans:          []identitycore.Ban{{ID: "ban-1", Email: "User@Example.COM", Reason: "abuse", BannedBy: "moderator", CreatedAt: 10}},
		Suppressions:  []identitycore.Suppression{{Email: "User@Example.COM", Reason: "opt-out", SuppressedAt: 10}},
		Sessions:      []SessionMetadata{{ID: "session-1", PrincipalID: "subject-1", CreatedAt: 10, ExpiresAt: 20}},
	}
}

func TestPrepareShadowParityIsOrderIndependentAndSecretFree(t *testing.T) {
	left, err := PrepareShadowImport(genericSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	rightInput := genericSnapshot()
	rightInput.Principals = append(rightInput.Principals, Principal{SubjectID: "subject-0", Email: "a@example.com"})
	rightInput.Principals = []Principal{rightInput.Principals[1], rightInput.Principals[0]}
	// Add the same principal to left in opposite ordering to prove canonical sort.
	leftInput := genericSnapshot()
	leftInput.Principals = append(leftInput.Principals, Principal{SubjectID: "subject-0", Email: "a@example.com"})
	left, err = Prepare(leftInput)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Prepare(rightInput)
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(left, right) {
		t.Fatalf("equivalent projections differ: %#v %#v", left, right)
	}
	wire, err := msgpack.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte("never-serialized-token")) || bytes.Contains(wire, []byte("never-serialized-code")) {
		t.Fatal("shadow projection serialized secret material")
	}
}
func TestPrepareRejectsInvalidGenericMetadata(t *testing.T) {
	value := genericSnapshot()
	value.Claims[0].ExpiresAt = value.Claims[0].CreatedAt
	if _, err := Prepare(value); err == nil {
		t.Fatal("invalid claim metadata accepted")
	}
}
func TestExcludedProductSurfaceCannotEnterSnapshotWire(t *testing.T) {
	// This compile-time shape check keeps checkout, gifts, route principals, and
	// reporting out of the non-production shadow ABI.
	value := genericSnapshot()
	wire, err := msgpack.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"checkout", "gift", "route", "report", "tos", "eula"} {
		if bytes.Contains(bytes.ToLower(wire), []byte(forbidden)) {
			t.Fatalf("forbidden product surface %q entered wire", forbidden)
		}
	}
}
