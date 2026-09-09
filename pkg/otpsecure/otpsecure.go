package otpsecure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const EnvelopeVersion = "bananauth.otp-delivery.v1"

type Keyring struct {
	Current  []byte
	Previous []byte
}

type Envelope struct {
	Version    string `msgpack:"version"`
	KeyID      string `msgpack:"key_id"`
	Recipient  string `msgpack:"recipient"`
	ExpiresAt  int64  `msgpack:"expires_at"`
	Nonce      []byte `msgpack:"nonce"`
	Ciphertext []byte `msgpack:"ciphertext"`
}

func Parse(current, previous string) (Keyring, error) {
	if len(current) < 32 {
		return Keyring{}, errors.New("current OTP key must contain at least 32 bytes")
	}
	ring := Keyring{Current: []byte(current)}
	if previous != "" {
		if len(previous) < 32 || previous == current {
			return Keyring{}, errors.New("previous OTP key must be distinct and contain at least 32 bytes")
		}
		ring.Previous = []byte(previous)
	}
	return ring, nil
}

func keyID(key []byte) string {
	sum := sha256.Sum256(append([]byte("bananauth:otp-key-id:v1\x00"), key...))
	return hex.EncodeToString(sum[:8])
}

func normalizedCode(code string) string { return strings.ToUpper(strings.TrimSpace(code)) }

func (r Keyring) CodeMAC(id, recipient, code, kind string) string {
	mac := hmac.New(sha256.New, r.Current)
	fmt.Fprintf(mac, "bananauth:otp:v2\x00%s\x00%s\x00%s\x00%s", kind, id, strings.ToLower(strings.TrimSpace(recipient)), normalizedCode(code))
	return hex.EncodeToString(mac.Sum(nil))
}

func (r Keyring) VerifyCode(want, id, recipient, code, kind string) bool {
	for _, key := range [][]byte{r.Current, r.Previous} {
		if len(key) == 0 {
			continue
		}
		candidate := r
		candidate.Current = key
		if hmac.Equal([]byte(want), []byte(candidate.CodeMAC(id, recipient, code, kind))) {
			return true
		}
	}
	return false
}

func deriveAEAD(key []byte) (cipher.AEAD, error) {
	sum := sha256.Sum256(append([]byte("bananauth:otp-encryption:v1\x00"), key...))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func aad(effectID, recipient string, expiresAt int64) []byte {
	return []byte(fmt.Sprintf("bananauth:otp-delivery-aad:v1\x00%s\x00%s\x00%d", effectID, strings.ToLower(strings.TrimSpace(recipient)), expiresAt))
}

func (r Keyring) Seal(effectID, recipient string, expiresAt int64, plaintext []byte) ([]byte, error) {
	if len(r.Current) == 0 || effectID == "" || recipient == "" || expiresAt <= 0 {
		return nil, errors.New("complete OTP delivery identity is required")
	}
	aead, err := deriveAEAD(r.Current)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, r.Current)
	mac.Write([]byte("bananauth:otp-nonce:v1\x00" + effectID))
	nonce := append([]byte(nil), mac.Sum(nil)[:aead.NonceSize()]...)
	envelope := Envelope{Version: EnvelopeVersion, KeyID: keyID(r.Current), Recipient: strings.ToLower(strings.TrimSpace(recipient)), ExpiresAt: expiresAt, Nonce: nonce}
	envelope.Ciphertext = aead.Seal(nil, nonce, plaintext, aad(effectID, envelope.Recipient, expiresAt))
	return json.Marshal(envelope)
}

func (r Keyring) Open(effectID string, raw []byte) ([]byte, Envelope, error) {
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, envelope, err
	}
	if envelope.Version != EnvelopeVersion {
		return nil, envelope, errors.New("unsupported OTP delivery envelope")
	}
	for _, key := range [][]byte{r.Current, r.Previous} {
		if len(key) == 0 || keyID(key) != envelope.KeyID {
			continue
		}
		aead, err := deriveAEAD(key)
		if err != nil {
			return nil, envelope, err
		}
		plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, aad(effectID, envelope.Recipient, envelope.ExpiresAt))
		if err != nil {
			return nil, envelope, errors.New("OTP delivery authentication failed")
		}
		return plaintext, envelope, nil
	}
	return nil, envelope, errors.New("OTP delivery key is unavailable")
}
