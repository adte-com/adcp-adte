package auth

import (
	"context"
	"errors"
)

// Permission represents an access level
type Permission string

const (
	PermissionRead    Permission = "read"
	PermissionWrite   Permission = "write"
	PermissionDelete  Permission = "delete"
	PermissionApprove Permission = "approve"
)

// Principal represents an authenticated entity with permissions
type Principal struct {
	PrincipalID string                        `json:"principal_id"`
	Permissions map[string][]Permission       `json:"permissions"`
	APIKey      string                        `json:"-"` // Don't expose in JSON
	Metadata    map[string]interface{}        `json:"metadata,omitempty"`
}

// HasPermission checks if a principal has a specific permission for a resource
func (p *Principal) HasPermission(resource string, permission Permission) bool {
	if p == nil || p.Permissions == nil {
		return false
	}
	
	perms, ok := p.Permissions[resource]
	if !ok {
		return false
	}
	
	for _, perm := range perms {
		if perm == permission {
			return true
		}
	}
	
	return false
}

// RequiredPermissions defines what permissions are needed for each operation
var RequiredPermissions = map[string]map[string]Permission{
	"get_products": {
		"products": PermissionRead,
	},
	"create_media_buy": {
		"media_buys": PermissionWrite,
	},
	"update_media_buy": {
		"media_buys": PermissionWrite,
	},
	"list_creatives": {
		"creatives": PermissionRead,
	},
	"sync_creatives": {
		"creatives": PermissionWrite,
	},
	"get_media_buy_delivery": {
		"reports": PermissionRead,
	},
	"provide_performance_feedback": {
		"reports": PermissionWrite,
	},
}

// CheckOperationPermissions verifies if a principal has all required permissions for an operation
func CheckOperationPermissions(principal *Principal, operation string) error {
	requiredPerms, ok := RequiredPermissions[operation]
	if !ok {
		// If no permissions defined, allow access (for public operations)
		return nil
	}
	
	if principal == nil {
		return errors.New("authentication required")
	}
	
	for resource, requiredPerm := range requiredPerms {
		if !principal.HasPermission(resource, requiredPerm) {
			return &InsufficientPermissionsError{
				Resource:   resource,
				Permission: requiredPerm,
				Operation:  operation,
			}
		}
	}
	
	return nil
}

// InsufficientPermissionsError represents a permission denied error
type InsufficientPermissionsError struct {
	Resource   string
	Permission Permission
	Operation  string
}

func (e *InsufficientPermissionsError) Error() string {
	return "insufficient permissions for operation"
}

// Context keys
type contextKey string

const (
	ContextKeyPrincipal contextKey = "principal"
	ContextKeyDryRun    contextKey = "dry_run"
)

// GetPrincipalFromContext retrieves the principal from context
func GetPrincipalFromContext(ctx context.Context) (*Principal, bool) {
	principal, ok := ctx.Value(ContextKeyPrincipal).(*Principal)
	return principal, ok
}

// IsDryRun checks if the request is in dry-run mode
func IsDryRun(ctx context.Context) bool {
	dryRun, ok := ctx.Value(ContextKeyDryRun).(bool)
	return ok && dryRun
}
