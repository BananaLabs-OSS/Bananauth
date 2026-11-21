package browser

import "github.com/bananalabs-oss/bananauth/internal/session"

type LogoutResult struct {
	Version string `msgpack:"version" json:"version"`
	OK      bool   `msgpack:"ok" json:"ok"`
	Error   string `msgpack:"error,omitempty" json:"error,omitempty"`
}
type sessionRevoker struct {
	resolver resolver
	revoke   func(session.RevokeOwnedRequest) (session.Result[session.Session], error)
}

func (r sessionRevoker) logoutRequest(request ResolveRequest) LogoutResult {
	result := LogoutResult{Version: ContractVersion}
	principal := r.resolver.resolveRequest(request)
	if !principal.OK {
		result.Error = principal.Error
		return result
	}
	result.Error = "unavailable"
	if r.revoke != nil {
		receipt, err := r.revoke(session.RevokeOwnedRequest{RequestID: "browser-logout:" + principal.SessionID, SessionID: principal.SessionID})
		if err == nil && receipt.Version == sessionContractVersion && receipt.OK && receipt.Value.SessionID == principal.SessionID && receipt.Value.AccountID == principal.AccountID && !receipt.Value.Active && receipt.Value.RevokedAt > 0 {
			result.OK = true
			result.Error = ""
		}
	}
	return result
}
