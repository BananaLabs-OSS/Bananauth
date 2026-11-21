package session

import (
	"fmt"
	"github.com/vmihailenco/msgpack/v5"
)

type owner = Service

func decode(raw []byte, v any) error {
	if len(raw) == 0 {
		return fmt.Errorf("empty request")
	}
	return msgpack.Unmarshal(raw, v)
}
func encode(v any) ([]byte, error) { return msgpack.Marshal(v) }
func (o *Service) revokeOwned(raw []byte) ([]byte, error) {
	var q RevokeOwnedRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.RevokeOwned(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) createOwned(raw []byte) ([]byte, error) {
	var q CreateOwnedRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.CreateOwned(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) create(raw []byte) ([]byte, error) {
	var q CreateRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.Create(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) get(raw []byte) ([]byte, error) {
	var q GetRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.Get(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) revoke(raw []byte) ([]byte, error) {
	var q RevokeRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.Revoke(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
func (o *Service) createEmailVerifiedOwned(raw []byte) ([]byte, error) {
	var q CreateEmailVerifiedOwnedRequest
	if e := decode(raw, &q); e != nil {
		return nil, e
	}
	v, e := o.CreateEmailVerifiedOwned(q)
	if e != nil {
		return nil, e
	}
	return msgpack.Marshal(v)
}
