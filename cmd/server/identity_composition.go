package main

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	identityNativeRegisterEvent           = "bananauth.identity.native.register.v1"
	identityNativeAuthenticateEvent       = "bananauth.identity.native.authenticate.v1"
	identityPasswordChangeEvent           = "bananauth.identity.native.password.change.v1"
	identityNativeAttachEvent             = "bananauth.identity.native.attach.v1"
	identityPasswordResetIssueEvent       = "bananauth.identity.password-reset.issue.v1"
	identityPasswordResetConsumeEvent     = "bananauth.identity.password-reset.consume.v1"
	identityEmailVerificationIssueEvent   = "bananauth.identity.email-verification.issue.v1"
	identityEmailVerificationConsumeEvent = "bananauth.identity.email-verification.consume.v1"
	identityAccountGetEvent               = "bananauth.identity.account.get.v1"
	identityAccountDeleteEvent            = "bananauth.identity.account.delete.v1"
	identityOAuthStateIssueEvent          = "bananauth.identity.oauth-state.issue.v1"
	identityOAuthStateConsumeEvent        = "bananauth.identity.oauth-state.consume.v1"
	identityOAuthResolveEvent             = "bananauth.identity.oauth.resolve.v1"
	identityOAuthUpsertEvent              = "bananauth.identity.oauth.upsert.v1"
	identityProfileCreateEvent            = "bananauth.identity.profile.create.v1"
	identityProfileGetEvent               = "bananauth.identity.profile.get.v1"
	identityProfileUpdateEvent            = "bananauth.identity.profile.update.v1"
	identityRateCheckEvent                = "bananauth.identity.rate.check.v1"
	identityRateClearEvent                = "bananauth.identity.rate.clear.v1"
	identityLegacyImportEvent             = "bananauth.identity.legacy.import.v1"
)

type identityResult[T any] struct {
	Version string         `msgpack:"version"`
	OK      bool           `msgpack:"ok"`
	Value   T              `msgpack:"value"`
	Error   *identityError `msgpack:"error,omitempty"`
}

type identityError struct {
	Code    string `msgpack:"code"`
	Message string `msgpack:"message"`
}

func callIdentity[T any](dispatch sessionDispatcher, event string, request any) (identityResult[T], error) {
	var response identityResult[T]
	if dispatch == nil {
		return response, fmt.Errorf("identity workflow dispatcher is nil")
	}
	requestWire, err := msgpack.Marshal(request)
	if err != nil {
		return response, err
	}
	responseWire, err := dispatch(event, requestWire)
	if err != nil {
		return response, err
	}
	if err := msgpack.Unmarshal(responseWire, &response); err != nil {
		return response, err
	}
	if response.Version != "auth-identity.v1" {
		return response, fmt.Errorf("identity workflow returned contract %q", response.Version)
	}
	return response, nil
}

func identityRequestID(prefix string) string {
	return prefix + ":" + mustRandomID()
}

var randomID = func() string {
	return uuid.NewString()
}

func mustRandomID() string { return randomID() }

func dispatchIdentity(identities map[string]func([]byte) ([]byte, error)) sessionDispatcher {
	return func(event string, wire []byte) ([]byte, error) {
		operation, version, ok := strings.Cut(strings.TrimPrefix(event, "bananauth.identity."), ".v")
		if !ok || operation == "" || (version != "1" && version != "2") {
			return nil, fmt.Errorf("unknown identity operation %q", event)
		}
		name := "auth.identity.v" + version + "." + operation
		execute := identities[name]
		if execute == nil {
			return nil, fmt.Errorf("unknown identity operation %q", event)
		}
		return execute(wire)
	}
}
