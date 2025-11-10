// tools/generate_jwt_token.go
// This is a utility to generate JWT tokens for testing the authentication middleware
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims matches the AdCP-compliant claims structure used in the middleware
type JWTClaims struct {
	jwt.RegisteredClaims
	// AdCP standard permissions model
	Permissions struct {
		Products  []string `json:"products,omitempty"`
		MediaBuys []string `json:"media_buys,omitempty"`
		Creatives []string `json:"creatives,omitempty"`
		Reports   []string `json:"reports,omitempty"`
	} `json:"permissions,omitempty"`
}

func main() {
	// Get secret key from environment
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		fmt.Println("Error: JWT_SECRET_KEY environment variable not set")
		fmt.Println("Usage: JWT_SECRET_KEY=your-secret go run generate_jwt_token.go")
		os.Exit(1)
	}

	// Create claims with AdCP permissions model
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // 24 hour expiration
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "adte-sales-agent",
			Subject:   "principal_test",
		},
	}

	// Set default permissions if not specified via command line
	permissionsArg := os.Args
	if len(permissionsArg) > 1 && permissionsArg[1] == "readonly" {
		// Read-only permissions
		claims.Permissions.Products = []string{"read"}
		claims.Permissions.MediaBuys = []string{"read"}
		claims.Permissions.Creatives = []string{"read"}
		claims.Permissions.Reports = []string{"read"}
		fmt.Println("Generating token with READ-ONLY permissions")
	} else {
		// Full permissions (default)
		claims.Permissions.Products = []string{"read"}
		claims.Permissions.MediaBuys = []string{"read", "write"}
		claims.Permissions.Creatives = []string{"read", "write"}
		claims.Permissions.Reports = []string{"read", "write"}
		fmt.Println("Generating token with FULL permissions")
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret key
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		fmt.Printf("Error signing token: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nGenerated JWT Token:")
	fmt.Println("====================")
	fmt.Println(tokenString)
	fmt.Println()
	fmt.Println("Token Details:")
	fmt.Println("- Algorithm: HS256")
	fmt.Println("- Subject:  ", claims.Subject)
	fmt.Println("- Expires:  ", claims.ExpiresAt.Time.Format(time.RFC3339))
	fmt.Println("- Permissions:")
	fmt.Println("  - Products:  ", claims.Permissions.Products)
	fmt.Println("  - MediaBuys: ", claims.Permissions.MediaBuys)
	fmt.Println("  - Creatives: ", claims.Permissions.Creatives)
	fmt.Println("  - Reports:   ", claims.Permissions.Reports)
	fmt.Println()
	fmt.Println("Test commands:")
	fmt.Println("1. Test with JWT (Bearer token):")
	fmt.Printf("   curl -H \"Authorization: Bearer %s\" http://localhost:8081/get_products\n", tokenString)
	fmt.Println()
	fmt.Println("2. Test with API Key:")
	fmt.Println("   curl -H \"X-API-Key: test_api_key_full_access\" http://localhost:8081/get_products")
	fmt.Println()
	fmt.Println("3. Test dry-run mode:")
	fmt.Printf("   curl -H \"Authorization: Bearer %s\" -H \"X-Dry-Run: true\" http://localhost:8081/create_media_buy\n", tokenString)
}
