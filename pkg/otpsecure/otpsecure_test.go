package otpsecure

import (
	"bytes"
	"encoding/json"
	"testing"
)

const (
	currentKey  = "current-test-key-material-that-is-at-least-32-bytes"
	previousKey = "previous-test-key-material-that-is-at-least-32-bytes"
)

func mustKeys(t *testing.T, current, previous string) Keyring {
	t.Helper()
	keys, err := Parse(current, previous)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestCodeMACRequiresCorrectKeyAndSupportsRotation(t *testing.T) {
	old := mustKeys(t, previousKey, "")
	mac := old.CodeMAC("otp", "Player@Example.Test", "123456", "verify")
	rotated := mustKeys(t, currentKey, previousKey)
	if !rotated.VerifyCode(mac, "otp", "player@example.test", "123456", "verify") {
		t.Fatal("previous rotation key did not verify live OTP")
	}
	wrong := mustKeys(t, "wrong-test-key-material-that-is-at-least-32-bytes", "")
	if wrong.VerifyCode(mac, "otp", "player@example.test", "123456", "verify") {
		t.Fatal("wrong key verified OTP")
	}
}

func TestDeliveryEnvelopeIsDeterministicAuthenticatedAndRotatable(t *testing.T) {
	old := mustKeys(t, previousKey, "")
	plain := []byte("single-recipient secret code 123456")
	one, err := old.Seal("effect-1", "player@example.test", 1234, plain)
	if err != nil {
		t.Fatal(err)
	}
	two, err := old.Seal("effect-1", "player@example.test", 1234, plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one, two) {
		t.Fatal("idempotent effect produced a different envelope")
	}
	other, err := old.Seal("effect-2", "player@example.test", 1234, plain)
	if err != nil {
		t.Fatal(err)
	}
	var firstEnvelope, otherEnvelope Envelope
	if err := json.Unmarshal(one, &firstEnvelope); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(other, &otherEnvelope); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstEnvelope.Nonce, otherEnvelope.Nonce) {
		t.Fatal("distinct effect IDs reused an encryption nonce")
	}
	if bytes.Contains(one, []byte("123456")) || bytes.Contains(one, []byte(previousKey)) {
		t.Fatal("envelope persisted plaintext or key material")
	}
	rotated := mustKeys(t, currentKey, previousKey)
	opened, envelope, err := rotated.Open("effect-1", one)
	if err != nil || !bytes.Equal(opened, plain) || envelope.Recipient != "player@example.test" {
		t.Fatalf("rotation open = %q %#v %v", opened, envelope, err)
	}
	tampered := append([]byte(nil), one...)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := rotated.Open("effect-1", tampered); err == nil {
		t.Fatal("tampered envelope opened")
	}
	if _, _, err := mustKeys(t, currentKey, "").Open("effect-1", one); err == nil {
		t.Fatal("wrong key opened envelope")
	}
	if _, _, err := rotated.Open("different-effect", one); err == nil {
		t.Fatal("wrong effect identity opened envelope")
	}
}

func TestParseFailsClosedWithoutProductionStrengthCurrentKey(t *testing.T) {
	for _, key := range []string{"", "short"} {
		if _, err := Parse(key, ""); err == nil {
			t.Fatalf("accepted weak current key %q", key)
		}
	}
}
