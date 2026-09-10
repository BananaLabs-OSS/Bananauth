//go:build wasip1

package main

import (
	"time"

	"github.com/BananaLabs-OSS/Fiber/pulp"
	hostjwt "github.com/BananaLabs-OSS/Fiber/pulp/jwt"
	"github.com/vmihailenco/msgpack/v5"
)

func init() {
	pulp.OnInit(func([]byte) error {
		boundary := resolver{
			verify: func(token string) (jwtClaims, error) {
				claims, err := hostjwt.Verify(token)
				return jwtClaims{AccountID: claims.AccountID, SessionID: claims.SessionID}, err
			},
			get: func(request sessionGetRequest) (sessionGetResult, error) {
				wire, err := msgpack.Marshal(request)
				if err != nil {
					return sessionGetResult{}, err
				}
				response, err := pulp.Call("auth-session", "auth.session.v1.get", wire)
				if err != nil {
					return sessionGetResult{}, err
				}
				var result sessionGetResult
				err = msgpack.Unmarshal(response, &result)
				return result, err
			},
			now: time.Now,
		}
		pulp.Provide(ProviderResolve, boundary.resolve)
		return nil
	})
}

func main() {}
