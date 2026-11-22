package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"

	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/vmihailenco/msgpack/v5"
)

type archivedMessage struct {
	digest     [sha256.Size]byte
	ciphertext []byte
}

type notificationArchive struct {
	key      otpsecure.Keyring
	messages map[string]archivedMessage
}

func newNotificationArchive(key string) (*notificationArchive, error) {
	ring, err := otpsecure.Parse(key, "")
	if err != nil {
		return nil, err
	}
	return &notificationArchive{key: ring, messages: make(map[string]archivedMessage)}, nil
}

func (a *notificationArchive) seal(id string, value any) ([]byte, error) {
	payload, err := object(value)
	if err != nil || len(payload) != 3 {
		return nil, errors.New("unsupported historical plaintext notification")
	}
	to, toOK := payload["to"].(string)
	_, subjectOK := payload["subject"].(string)
	_, textOK := payload["text"].(string)
	if id == "" || !toOK || to == "" || !subjectOK || !textOK {
		return nil, errors.New("invalid historical plaintext notification")
	}
	raw, err := encoded(payload)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	if previous, ok := a.messages[id]; ok {
		if previous.digest != digest {
			return nil, errors.New("conflicting historical plaintext payloads for one notification")
		}
		return previous.ciphertext, nil
	}
	// A past expiry and a separate key keep archived content outside delivery.
	const archivedExpiryMillis = 1
	ciphertext, err := a.key.Seal(id, to, archivedExpiryMillis, raw)
	if err != nil {
		return nil, err
	}
	a.messages[id] = archivedMessage{digest: digest, ciphertext: ciphertext}
	return ciphertext, nil
}

func (a *notificationArchive) checkHead(ctx context.Context, source *sql.Tx) error {
	var raw []byte
	if err := source.QueryRowContext(ctx, `SELECT snapshot FROM auth_identity_commands ORDER BY revision DESC LIMIT 1`).Scan(&raw); err != nil {
		return err
	}
	var snapshot map[string]any
	if err := msgpack.Unmarshal(raw, &snapshot); err != nil {
		return errors.New("invalid current identity snapshot")
	}
	effects, err := object(snapshot["effects"])
	if err != nil {
		return err
	}
	for id, value := range effects {
		row, err := object(value)
		if err != nil {
			return err
		}
		intent, err := object(row["intent"])
		if err != nil {
			return err
		}
		intentID, _ := intent["id"].(string)
		_, byID := a.messages[id]
		_, byIntentID := a.messages[intentID]
		if byID || byIntentID {
			return errors.New("plaintext notification still exists in current state; archive conversion refused")
		}
	}
	return nil
}
