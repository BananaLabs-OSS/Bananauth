package main

import (
	"strings"

	pulpgin "github.com/BananaLabs-OSS/Fiber/pulp/gin"
)

// sessionAuth validates the JWT and then checks that the session has
// not been revoked. Other services (Hand, Bunch, etc.) use Fiber's
// stock middleware.JWTAuth — they do not own session lifecycle.
func sessionAuth(sm *SessionManager) pulpgin.HandlerFunc {
	return func(c *pulpgin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(401, pulpgin.H{"error": "missing authorization header"})
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(401, pulpgin.H{"error": "invalid authorization format, expected: Bearer <token>"})
			return
		}

		accountID, sessionID, err := sm.Verify(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(401, pulpgin.H{"error": "invalid or expired token"})
			return
		}

		if !sm.Exists(sessionID) {
			c.AbortWithStatusJSON(401, pulpgin.H{"error": "session revoked"})
			return
		}

		c.Set("account_id", accountID)
		c.Set("session_id", sessionID)
		c.Next()
	}
}
