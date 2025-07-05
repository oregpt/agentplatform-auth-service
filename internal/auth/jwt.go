package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oregpt/agentplatform-auth-service/internal/models"
)

// GenerateJWT creates a new JWT token for a user with organization-scoped permissions
func GenerateJWT(user models.User, orgID string, permissions []string, secret string, expirationHours int) (string, error) {
	// Set expiration time
	expirationTime := time.Now().Add(time.Duration(expirationHours) * time.Hour)
	
	// Create claims
	claims := jwt.MapClaims{
		"uid":         user.UID,
		"email":       user.Email,
		"permissions": permissions,
		"exp":         expirationTime.Unix(),
		"iat":         time.Now().Unix(),
	}
	
	// Only add org_id to claims if it's not empty
	if orgID != "" {
		claims["org_id"] = orgID
	} else {
		// For empty org_id, explicitly set to empty string to indicate 'all organizations' access
		claims["org_id"] = ""
	}
	
	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	
	// Sign the token with the secret key
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("error signing token: %v", err)
	}
	
	return tokenString, nil
}

// VerifyJWT validates a JWT token and returns its claims
func VerifyJWT(tokenString string, secret string) (jwt.MapClaims, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		
		// Return the secret key
		return []byte(secret), nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %v", err)
	}
	
	// Check if the token is valid
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	
	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	
	return claims, nil
}
