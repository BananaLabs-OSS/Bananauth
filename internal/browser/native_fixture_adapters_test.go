package browser

import (
	"github.com/vmihailenco/msgpack/v5"
	"unicode/utf8"
)

func typedFixture[Q, R any](fn func([]byte) ([]byte, error)) func(Q) (R, error) {
	return func(q Q) (R, error) {
		var r R
		b, e := msgpack.Marshal(q)
		if e != nil {
			return r, e
		}
		v, e := fn(b)
		if e == nil {
			e = msgpack.Unmarshal(v, &r)
		}
		return r, e
	}
}
func (r resolver) resolveValue(raw []byte) ResolveResult {
	q, ok := decodeExactRequest(raw)
	if !ok {
		return denied("invalid_request")
	}
	return r.resolveRequest(q)
}
func (r resolver) resolve(raw []byte) ([]byte, error) { return msgpack.Marshal(r.resolveValue(raw)) }
func (c emailSessionCompleter) completeValue(raw []byte) CompleteEmailVerificationResult {
	var q CompleteEmailVerificationRequest
	if msgpack.Unmarshal(raw, &q) != nil {
		return CompleteEmailVerificationResult{Version: ContractVersion, Error: "invalid_request"}
	}
	return c.completeIntent(CompleteEmailVerificationRequestV2{Version: q.Version, RequestID: q.RequestID, Email: q.Email, Code: q.Code, Intent: "login"})
}
func (c emailSessionCompleter) complete(raw []byte) ([]byte, error) {
	return msgpack.Marshal(c.completeValue(raw))
}
func (c emailSessionCompleter) completeV2(raw []byte) ([]byte, error) {
	var q CompleteEmailVerificationRequestV2
	if msgpack.Unmarshal(raw, &q) != nil {
		return msgpack.Marshal(CompleteEmailVerificationResult{Version: ContractVersion, Error: "invalid_request"})
	}
	return msgpack.Marshal(c.completeIntent(q))
}
func (r sessionRevoker) logout(raw []byte) ([]byte, error) {
	q, ok := decodeExactRequest(raw)
	if !ok {
		return msgpack.Marshal(LogoutResult{Version: ContractVersion, Error: "invalid_request"})
	}
	return msgpack.Marshal(r.logoutRequest(q))
}

type logoutResult = LogoutResult

func decodeExactRequest(raw []byte) (ResolveRequest, bool) {
	if len(raw) == 0 || len(raw) > maxCredentialBytes+256 {
		return ResolveRequest{}, false
	}
	var fields map[string]any
	if err := msgpack.Unmarshal(raw, &fields); err != nil || len(fields) != 3 {
		return ResolveRequest{}, false
	}
	for _, key := range []string{"version", "audience", "credential"} {
		if _, exists := fields[key]; !exists {
			return ResolveRequest{}, false
		}
	}
	for key := range fields {
		if key != "version" && key != "audience" && key != "credential" {
			return ResolveRequest{}, false
		}
	}
	request := ResolveRequest{}
	var valid bool
	request.Version, valid = fields["version"].(string)
	if !valid || request.Version != ContractVersion {
		return ResolveRequest{}, false
	}
	request.Audience, valid = fields["audience"].(string)
	if !valid || request.Audience != AccountAudience {
		return ResolveRequest{}, false
	}
	request.Credential, valid = fields["credential"].(string)
	if !valid || len(request.Credential) == 0 || len(request.Credential) > maxCredentialBytes || !utf8.ValidString(request.Credential) {
		return ResolveRequest{}, false
	}
	return request, true
}
