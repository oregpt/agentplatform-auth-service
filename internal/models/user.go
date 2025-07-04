package models

// User represents a user in the system
type User struct {
	UID           string   `json:"uid"`
	Email         string   `json:"email"`
	DisplayName   string   `json:"display_name"`
	EmailVerified bool     `json:"email_verified"`
	Organizations []string `json:"organizations"`
}

// Permission represents a permission in the system
type Permission struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Role represents a role in the system with associated permissions
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// Organization represents an organization in the system
type Organization struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   int64  `json:"created_at"`
}

// UserRole associates a user with a role in an organization
type UserRole struct {
	UserID         string `json:"user_id"`
	OrganizationID string `json:"organization_id"`
	RoleID         string `json:"role_id"`
}
