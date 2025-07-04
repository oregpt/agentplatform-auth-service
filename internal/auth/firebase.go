package auth

import (
	"context"
	"fmt"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

var firebaseAuth *auth.Client

// Token represents a Firebase ID token with claims
type Token struct {
	UID    string                 `json:"uid"`
	Claims map[string]interface{} `json:"claims"`
}

// InitFirebase initializes the Firebase Auth client
func InitFirebase(ctx context.Context, projectID string) error {
	// Firebase app configuration
	config := &firebase.Config{
		ProjectID: projectID,
	}

	// Initialize the Firebase app
	app, err := firebase.NewApp(ctx, config, option.WithoutAuthentication())
	if err != nil {
		return fmt.Errorf("error initializing Firebase app: %v", err)
	}

	// Initialize the Firebase Auth client
	firebaseAuth, err = app.Auth(ctx)
	if err != nil {
		return fmt.Errorf("error initializing Firebase Auth client: %v", err)
	}

	return nil
}

// VerifyFirebaseToken validates a Firebase ID token
func VerifyFirebaseToken(ctx context.Context, idToken string) (*Token, error) {
	if firebaseAuth == nil {
		return nil, fmt.Errorf("Firebase Auth client not initialized")
	}

	// Verify the ID token
	fbToken, err := firebaseAuth.VerifyIDToken(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("error verifying ID token: %v", err)
	}

	// Convert to our Token type
	token := &Token{
		UID:    fbToken.UID,
		Claims: fbToken.Claims,
	}

	return token, nil
}

// GetUserByUID retrieves a user by their Firebase UID
func GetUserByUID(ctx context.Context, uid string) (*auth.UserRecord, error) {
	if firebaseAuth == nil {
		return nil, fmt.Errorf("Firebase Auth client not initialized")
	}

	user, err := firebaseAuth.GetUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("error getting user: %v", err)
	}

	return user, nil
}
