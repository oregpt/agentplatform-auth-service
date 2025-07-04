package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all configuration for the service
type Config struct {
	Port            string
	FirebaseProject string
	JWTSecret       string
	JWTExpiration   int // in hours
}

// Load reads the configuration from environment variables
func Load() (*Config, error) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port
	}

	firebaseProject := os.Getenv("FIREBASE_PROJECT_ID")
	if firebaseProject == "" {
		return nil, fmt.Errorf("FIREBASE_PROJECT_ID environment variable is required")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET environment variable is required")
	}

	jwtExpirationStr := os.Getenv("JWT_EXPIRATION_HOURS")
	jwtExpiration := 24 // Default to 24 hours
	if jwtExpirationStr != "" {
		var err error
		jwtExpiration, err = strconv.Atoi(jwtExpirationStr)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT_EXPIRATION_HOURS: %v", err)
		}
	}

	return &Config{
		Port:            port,
		FirebaseProject: firebaseProject,
		JWTSecret:       jwtSecret,
		JWTExpiration:   jwtExpiration,
	}, nil
}
