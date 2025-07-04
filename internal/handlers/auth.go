package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/oregpt/agentplatform-auth-service/internal/auth"
	"github.com/oregpt/agentplatform-auth-service/internal/config"
	"github.com/oregpt/agentplatform-auth-service/internal/models"
)

// Request and response structures
type VerifyTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

type GenerateJWTRequest struct {
	FirebaseToken string   `json:"firebase_token" binding:"required"`
	OrganizationID string  `json:"organization_id" binding:"required"`
	Permissions   []string `json:"permissions"`
}

type TokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"` // in seconds
}

// VerifyToken validates a Firebase ID token
func VerifyToken(c *gin.Context) {
	var req VerifyTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify the token
	token, err := auth.VerifyFirebaseToken(c, req.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Return the token claims
	c.JSON(http.StatusOK, gin.H{
		"uid":   token.UID,
		"email": token.Claims["email"],
		"claims": token.Claims,
	})
}

// GenerateJWT creates a JWT token from a Firebase token
func GenerateJWT(c *gin.Context) {
	var req GenerateJWTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify the Firebase token
	firebaseToken, err := auth.VerifyFirebaseToken(c, req.FirebaseToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Firebase token: " + err.Error()})
		return
	}

	// Get user information
	firebaseUser, err := auth.GetUserByUID(c, firebaseToken.UID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user: " + err.Error()})
		return
	}

	// Create user model
	user := models.User{
		UID:           firebaseUser.UID,
		Email:         firebaseUser.Email,
		DisplayName:   firebaseUser.DisplayName,
		EmailVerified: firebaseUser.EmailVerified,
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load configuration: " + err.Error()})
		return
	}

	// Generate JWT
	token, err := auth.GenerateJWT(user, req.OrganizationID, req.Permissions, cfg.JWTSecret, cfg.JWTExpiration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT: " + err.Error()})
		return
	}

	// Return the JWT
	c.JSON(http.StatusOK, TokenResponse{
		Token:     token,
		ExpiresIn: cfg.JWTExpiration * 3600, // convert hours to seconds
	})
}

// GetPermissions returns the permissions for the authenticated user
func GetPermissions(c *gin.Context) {
	// Get user and organization from context (set by AuthRequired middleware)
	userID, _ := c.Get("user_id")
	orgID, _ := c.Get("org_id")
	roles, _ := c.Get("user_roles")

	// In a real implementation, you would fetch the actual permissions from a database
	// This is a placeholder implementation
	permissions := []string{
		"read:agents",
		"create:agents",
		"update:agents",
		"delete:agents",
		"read:files",
		"upload:files",
		"delete:files",
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":       userID,
		"organization_id": orgID,
		"roles":         roles,
		"permissions":   permissions,
	})
}
