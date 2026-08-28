// Package sessionsidentityshadow proves a non-production-only projection from
// the generic Sessions identity surface into Bananauth. It has no storage,
// host, HTTP, credential, JWT, or live-provider dependency: callers may use
// it to compare representations, never to move or activate user records.
package sessionsidentityshadow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	identitycore "github.com/SirNiklas9/pulp-engines/identity-core"
	"github.com/vmihailenco/msgpack/v5"
)

const ContractVersion = "bananauth.sessions-identity-shadow.v1"

// Principal is generic identity metadata. It intentionally is not a route
// principal: it carries neither bearer material nor route authorization.
type Principal struct {
	SubjectID string `msgpack:"subject_id"`
	Email     string `msgpack:"email"`
}

// ClaimMetadata retains only the durable comparison facts. Token and IP
// address are deliberately omitted: a shadow parity proof never transports
// credential or network material.
type ClaimMetadata struct {
	ID        string `msgpack:"id"`
	SubjectID string `msgpack:"subject_id,omitempty"`
	Email     string `msgpack:"email"`
	Purpose   string `msgpack:"purpose"`
	Claimed   bool   `msgpack:"claimed"`
	ExpiresAt int64  `msgpack:"expires_at"`
	CreatedAt int64  `msgpack:"created_at"`
}

// VerificationMetadata excludes the one-time verification code.
type VerificationMetadata struct {
	ID            string `msgpack:"id"`
	Email         string `msgpack:"email"`
	Verified      bool   `msgpack:"verified"`
	ExpiresAt     int64  `msgpack:"expires_at"`
	CreatedAt     int64  `msgpack:"created_at"`
	AttemptCount  int    `msgpack:"attempt_count"`
	LastAttemptAt int64  `msgpack:"last_attempt_at,omitempty"`
}

// SessionMetadata is lifecycle metadata only. Session/JWT/cookie values are
// not represented, and this package does not invoke Bananauth's session owner.
type SessionMetadata struct {
	ID          string `msgpack:"id"`
	PrincipalID string `msgpack:"principal_id"`
	CreatedAt   int64  `msgpack:"created_at"`
	ExpiresAt   int64  `msgpack:"expires_at"`
	RevokedAt   int64  `msgpack:"revoked_at,omitempty"`
}

// Snapshot is the complete generic parity surface. Checkout, gifts, route
// principals, consent/TOS/EULA, deletion, reports, legacy-import DTOs, and
// notification/effect records are deliberately not representable here.
type Snapshot struct {
	Version       string                                  `msgpack:"version"`
	Principals    []Principal                             `msgpack:"principals"`
	Claims        []ClaimMetadata                         `msgpack:"claims"`
	Attestations  []identitycore.SubjectAttestationRecord `msgpack:"attestations"`
	Verifications []VerificationMetadata                  `msgpack:"verifications"`
	Bans          []identitycore.Ban                      `msgpack:"bans"`
	Suppressions  []identitycore.Suppression              `msgpack:"suppressions"`
	Sessions      []SessionMetadata                       `msgpack:"sessions"`
}

// Projection is a deterministic, non-secret comparison result. Digest is of
// canonical MessagePack metadata only; it is not a database import receipt.
type Projection struct {
	Version  string   `msgpack:"version"`
	Digest   string   `msgpack:"digest"`
	Snapshot Snapshot `msgpack:"snapshot"`
}

func ProjectClaim(value identitycore.Claim) ClaimMetadata {
	return ClaimMetadata{ID: value.ID, SubjectID: value.UserID, Email: value.Email, Purpose: value.Purpose, Claimed: value.Claimed, ExpiresAt: value.ExpiresAt, CreatedAt: value.CreatedAt}
}
func ProjectVerification(value identitycore.Verification) VerificationMetadata {
	return VerificationMetadata{ID: value.ID, Email: value.Email, Verified: value.Verified, ExpiresAt: value.ExpiresAt, CreatedAt: value.CreatedAt, AttemptCount: value.AttemptCount, LastAttemptAt: value.LastAttemptAt}
}

// Prepare validates and canonicalizes an in-memory shadow representation. It
// performs no I/O and callers must not treat its result as migration authority.
func Prepare(snapshot Snapshot) (Projection, error) {
	if err := validateSnapshot(&snapshot); err != nil {
		return Projection{}, err
	}
	wire, err := msgpack.Marshal(snapshot)
	if err != nil {
		return Projection{}, fmt.Errorf("encode shadow snapshot: %w", err)
	}
	sum := sha256.Sum256(wire)
	return Projection{Version: ContractVersion, Digest: hex.EncodeToString(sum[:]), Snapshot: snapshot}, nil
}

// PrepareShadowImport is the explicit migration rehearsal entry point. Despite
// its name it only prepares an in-memory, secret-free comparison projection;
// it has no durable import side effect.
func PrepareShadowImport(snapshot Snapshot) (Projection, error) { return Prepare(snapshot) }

// Equal proves whether two independently prepared metadata projections are
// equivalent. It does not cause a write or authorize a live auth transition.
func Equal(left, right Projection) bool {
	return left.Version == ContractVersion && right.Version == ContractVersion && left.Digest == right.Digest && bytes.Equal(mustWire(left.Snapshot), mustWire(right.Snapshot))
}
func mustWire(value Snapshot) []byte { wire, _ := msgpack.Marshal(value); return wire }

func validateSnapshot(snapshot *Snapshot) error {
	if snapshot.Version == "" {
		snapshot.Version = ContractVersion
	}
	if snapshot.Version != ContractVersion {
		return fmt.Errorf("shadow snapshot version must be %q", ContractVersion)
	}
	for i := range snapshot.Principals {
		value := &snapshot.Principals[i]
		email, err := identitycore.CanonicalizeEmail(value.Email)
		if err != nil || blank(value.SubjectID) {
			return fmt.Errorf("principal %d is invalid", i)
		}
		value.Email = email
	}
	for i := range snapshot.Claims {
		value := &snapshot.Claims[i]
		email, err := identitycore.CanonicalizeEmail(value.Email)
		if err != nil || blank(value.ID) || blank(value.Purpose) || value.CreatedAt <= 0 || value.ExpiresAt <= value.CreatedAt {
			return fmt.Errorf("claim metadata %d is invalid", i)
		}
		value.Email = email
	}
	for i := range snapshot.Attestations {
		if err := identitycore.ValidateSubjectAttestationRecord(snapshot.Attestations[i]); err != nil {
			return fmt.Errorf("attestation %d: %w", i, err)
		}
	}
	for i := range snapshot.Verifications {
		value := &snapshot.Verifications[i]
		email, err := identitycore.CanonicalizeEmail(value.Email)
		if err != nil || blank(value.ID) || value.CreatedAt <= 0 || value.ExpiresAt <= value.CreatedAt || value.AttemptCount < 0 {
			return fmt.Errorf("verification metadata %d is invalid", i)
		}
		value.Email = email
	}
	for i := range snapshot.Bans {
		value := &snapshot.Bans[i]
		email, err := identitycore.CanonicalizeEmail(value.Email)
		if err != nil {
			return fmt.Errorf("ban %d is invalid", i)
		}
		value.Email = email
		if err := identitycore.ValidateBan(*value); err != nil {
			return fmt.Errorf("ban %d: %w", i, err)
		}
	}
	for i := range snapshot.Suppressions {
		value := &snapshot.Suppressions[i]
		email, err := identitycore.CanonicalizeEmail(value.Email)
		if err != nil {
			return fmt.Errorf("suppression %d is invalid", i)
		}
		value.Email = email
		if err := identitycore.ValidateSuppression(*value); err != nil {
			return fmt.Errorf("suppression %d: %w", i, err)
		}
	}
	for i := range snapshot.Sessions {
		value := snapshot.Sessions[i]
		if blank(value.ID) || blank(value.PrincipalID) || value.CreatedAt <= 0 || value.ExpiresAt <= value.CreatedAt || value.RevokedAt < 0 {
			return fmt.Errorf("session metadata %d is invalid", i)
		}
	}
	sort.Slice(snapshot.Principals, func(i, j int) bool { return snapshot.Principals[i].SubjectID < snapshot.Principals[j].SubjectID })
	sort.Slice(snapshot.Claims, func(i, j int) bool { return snapshot.Claims[i].ID < snapshot.Claims[j].ID })
	sort.Slice(snapshot.Attestations, func(i, j int) bool { return snapshot.Attestations[i].ID < snapshot.Attestations[j].ID })
	sort.Slice(snapshot.Verifications, func(i, j int) bool { return snapshot.Verifications[i].ID < snapshot.Verifications[j].ID })
	sort.Slice(snapshot.Bans, func(i, j int) bool { return snapshot.Bans[i].ID < snapshot.Bans[j].ID })
	sort.Slice(snapshot.Suppressions, func(i, j int) bool { return snapshot.Suppressions[i].Email < snapshot.Suppressions[j].Email })
	sort.Slice(snapshot.Sessions, func(i, j int) bool { return snapshot.Sessions[i].ID < snapshot.Sessions[j].ID })
	return nil
}
func blank(value string) bool { return strings.TrimSpace(value) == "" }
