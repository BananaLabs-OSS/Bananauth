package browser

import "github.com/vmihailenco/msgpack/v5"

const ProviderLogout = "auth.browser-session.v1.logout"
const sessionRevokeOwnedProvider = "auth.session.v1.revoke-owned"

type logoutResult struct {
	Version string `msgpack:"version"`
	OK      bool   `msgpack:"ok"`
	Error   string `msgpack:"error,omitempty"`
}

type sessionRevoker struct {
	resolver resolver
	revoke   func([]byte) ([]byte, error)
}

func (r sessionRevoker) logout(raw []byte) ([]byte, error) {
	result := logoutResult{Version: ContractVersion}
	identity := r.resolver.resolveValue(raw)
	if !identity.OK {
		result.Error = identity.Error
		return msgpack.Marshal(result)
	}
	result.Error = "unavailable"
	if r.revoke != nil {
		request, _ := msgpack.Marshal(map[string]any{"request_id": "browser-logout:" + identity.SessionID, "session_id": identity.SessionID})
		response, err := r.revoke(request)
		var receipt sessionGetResult
		if err == nil && msgpack.Unmarshal(response, &receipt) == nil && receipt.Version == sessionContractVersion && receipt.OK &&
			receipt.Value.SessionID == identity.SessionID && receipt.Value.AccountID == identity.AccountID && !receipt.Value.Active && receipt.Value.RevokedAt > 0 {
			result.OK, result.Error = true, ""
		}
	}
	return msgpack.Marshal(result)
}
