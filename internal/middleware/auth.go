package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oregpt/agentplatform-auth-service/internal/auth"
)

// AuthRequired middleware to validate Firebase tokens
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Check if the header has the Bearer prefix
		idToken := strings.TrimPrefix(authHeader, "Bearer ")
		if idToken == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header must be in the format 'Bearer {token}'"})
			c.Abort()
			return
		}

		// Verify the Firebase token
		token, err := auth.VerifyFirebaseToken(c, idToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Invalid token: %v", err)})
			c.Abort()
			return
		}

		// Extract organization ID from claims
		orgID, ok := token.Claims["org_id"].(string)
		if !ok || orgID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token missing organization ID"})
			c.Abort()
			return
		}

		// Set user and organization info in context
		c.Set("user_id", token.UID)
		c.Set("org_id", orgID)
		c.Set("user_email", token.Claims["email"])
		c.Set("user_roles", token.Claims["roles"])

		c.Next()
	}
}
