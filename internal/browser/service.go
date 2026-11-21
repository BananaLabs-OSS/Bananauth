package browser

import (
	"errors"
	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/session"
	hostjwt "github.com/bananalabs-oss/bananauth/internal/token"
	"time"
)

type Service struct {
	resolver   resolver
	completion emailSessionCompleter
	revoker    sessionRevoker
}

func New(identities *identity.Service, sessions *session.Service, key hostjwt.Key) (*Service, error) {
	if identities == nil || sessions == nil || len(key) < 32 {
		return nil, errors.New("identity, session service and signing key are required")
	}
	boundary := resolver{verify: func(proof string) (jwtClaims, error) {
		claims, err := key.Verify(proof)
		return jwtClaims{AccountID: claims.AccountID, SessionID: claims.SessionID}, err
	}, get: sessions.Get, account: identities.AccountGet, now: time.Now}
	completion := emailSessionCompleter{consumeLoginV2: identities.EmailLoginConsumeV2, consumeSignupV2: identities.EmailSignupConsumeV2, create: sessions.CreateEmailVerifiedOwned, sign: key.Sign, now: time.Now}
	return &Service{resolver: boundary, completion: completion, revoker: sessionRevoker{resolver: boundary, revoke: sessions.RevokeOwned}}, nil
}
func (s *Service) Resolve(request ResolveRequest) ResolveResult {
	return s.resolver.resolveRequest(request)
}
func (s *Service) CompleteEmailVerification(request CompleteEmailVerificationRequestV2) CompleteEmailVerificationResult {
	return s.completion.completeIntent(request)
}
func (s *Service) Logout(request ResolveRequest) LogoutResult {
	return s.revoker.logoutRequest(request)
}
