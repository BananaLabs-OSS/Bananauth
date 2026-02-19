package middleware

import (
	"net/http"
	"strings"

	"github.com/bananalabs-oss/bananauth/internal/sessions"
	potassium "github.com/bananalabs-oss/potassium/middleware"
	"github.com/gin-gonic/gin"
)

// Auth returns BananAuth-specific middleware that validates JWTs
// AND checks session revocation. Other services use Potassium's
// JWTAuth directly since they don't own sessions.
func Auth(sm *sessions.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization header",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization format, expected: Bearer <token>",
			})
			return
		}

		// Step 1: Validate JWT signature and claims (Potassium)
		claims, err := potassium.ParseToken(parts[1], sm.Secret())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			return
		}

		// Step 2: Check session not revoked (BananAuth-specific)
		if !sm.Exists(claims.SessionID) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "session revoked",
			})
			return
		}

		c.Set("account_id", claims.AccountID)
		c.Set("session_id", claims.SessionID)
		c.Next()
	}
}
