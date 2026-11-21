package main

import (
	identitysvc "github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/google/uuid"
)

type identityError = identitysvc.Error
type identityResult[T any] = identitysvc.Result[T]

func identityRequestID(prefix string) string {
	return prefix + ":" + mustRandomID()
}

var randomID = func() string {
	return uuid.NewString()
}

func mustRandomID() string { return randomID() }
