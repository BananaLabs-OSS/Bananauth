package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func TestExternalServiceCredentialAdapterDTOsSerializeOnlyNonSecretMetadata(t *testing.T) {
	metadata := ExternalServiceCredentialMetadata{
		Version: ExternalServiceCredentialContractVersion,
		Reference: ExternalServiceCredentialReference{
			ID: "service-credential-opaque-1", Provider: "example-protocol",
		},
		SubjectID: "profile-123", Status: ExternalServiceCredentialActive,
		Revision: 4, CreatedAt: 100, UpdatedAt: 200, ExpiresAt: 300, LastVerifiedAt: 190,
	}
	value := ExternalServiceCredentialObserveResult{Metadata: metadata, Changed: true}

	jsonWire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	msgpackWire, err := msgpack.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{string(jsonWire), string(msgpackWire)} {
		for _, forbidden := range []string{"refresh_token", "access_token", "secret", "password", "credential_payload"} {
			if strings.Contains(strings.ToLower(wire), forbidden) {
				t.Fatalf("sealed credential DTO leaked forbidden material field %q in %q", forbidden, wire)
			}
		}
	}

	var decoded ExternalServiceCredentialObserveResult
	if err := msgpack.Unmarshal(msgpackWire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Metadata != metadata || !decoded.Changed {
		t.Fatalf("round trip = %#v", decoded)
	}
}

func TestExternalServiceCredentialContractHasNoSecretBearingFields(t *testing.T) {
	for _, value := range []any{
		ExternalServiceCredentialReference{},
		ExternalServiceCredentialMetadata{},
		ExternalServiceCredentialDescribeRequest{},
		ExternalServiceCredentialDescribeResult{},
		ExternalServiceCredentialObserveRequest{},
		ExternalServiceCredentialObserveResult{},
	} {
		assertNoSecretFields(t, reflect.TypeOf(value), map[reflect.Type]bool{})
	}
}

func assertNoSecretFields(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[typ] {
		return
	}
	seen[typ] = true
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		name := strings.ToLower(field.Name + " " + field.Tag.Get("msgpack") + " " + field.Tag.Get("json"))
		for _, forbidden := range []string{"secret", "token", "password", "payload"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("%s exposes forbidden field %q", typ.Name(), field.Name)
			}
		}
		fieldType := field.Type
		if fieldType.Kind() == reflect.Struct {
			assertNoSecretFields(t, fieldType, seen)
		}
	}
}
