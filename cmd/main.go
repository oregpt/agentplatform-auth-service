// Simple server for local testing without signal handling
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/oregpt/agentplatform-auth-service/internal/auth"
	"github.com/oregpt/agentplatform-auth-service/internal/config"
	"github.com/oregpt/agentplatform-auth-service/internal/handlers"
	"github.com/oregpt/agentplatform-auth-service/internal/middleware"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	// Initialize Firebase
	if err := auth.InitFirebase(context.Background(), cfg.FirebaseProject); err != nil {
		log.Fatalf("Failed to initialize Firebase: %v", err)
	}

	// Set up Gin router
	router := gin.Default()
	
	// Add CORS middleware
	router.Use(middleware.CORS())

	// Set up routes
	v1 := router.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/verify", handlers.VerifyToken)
			auth.POST("/generate-jwt", handlers.GenerateJWT)
		}

		// Protected routes
		protected := v1.Group("/")
		protected.Use(middleware.AuthRequired())
		{
			protected.GET("/permissions", handlers.GetPermissions)
		}
	}

	// Start server directly (no goroutine)
	log.Printf("Starting Auth Service on port %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, router); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
