package browser

import (
	"errors"
	"time"

	hostjwt "github.com/bananalabs-oss/bananauth/internal/token"
	"github.com/vmihailenco/msgpack/v5"
)

type command = func([]byte) ([]byte, error)

func query[Q, R any](execute command) func(Q) (R, error) {
	return func(request Q) (R, error) {
		var result R
		wire, err := msgpack.Marshal(request)
		if err != nil {
			return result, err
		}
		response, err := execute(wire)
		if err == nil {
			err = msgpack.Unmarshal(response, &result)
		}
		return result, err
	}
}

// Commands wires browser session flows to the two in-process state owners.
func Commands(identity, session map[string]command, key hostjwt.Key) (map[string]command, error) {
	for _, name := range []string{"auth.identity.v1.account.get", identityConsumeProvider,
		"auth.identity.v2.email-login.consume", "auth.identity.v2.email-signup.consume"} {
		if identity[name] == nil {
			return nil, errors.New("missing identity command: " + name)
		}
	}
	for _, name := range []string{"auth.session.v1.get", sessionCreateProvider, sessionRevokeOwnedProvider} {
		if session[name] == nil {
			return nil, errors.New("missing session command: " + name)
		}
	}
	boundary := resolver{
		verify: func(proof string) (jwtClaims, error) {
			claims, err := key.Verify(proof)
			return jwtClaims{AccountID: claims.AccountID, SessionID: claims.SessionID}, err
		},
		get:     query[sessionGetRequest, sessionGetResult](session["auth.session.v1.get"]),
		account: query[accountGetRequest, accountGetResult](identity["auth.identity.v1.account.get"]),
		now:     time.Now,
	}
	completion := emailSessionCompleter{
		consumeLoginV2:  identity["auth.identity.v2.email-login.consume"],
		consumeSignupV2: identity["auth.identity.v2.email-signup.consume"],
		consume:         identity[identityConsumeProvider],
		create:          session[sessionCreateProvider],
		sign:            key.Sign,
		now:             time.Now,
	}
	revoker := sessionRevoker{resolver: boundary, revoke: session[sessionRevokeOwnedProvider]}
	return map[string]command{
		ProviderLogout:                      revoker.logout,
		ProviderResolve:                     boundary.resolve,
		ProviderCompleteEmailVerification:   completion.complete,
		ProviderCompleteEmailVerificationV2: completion.completeV2,
	}, nil
}
