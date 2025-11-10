package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"adte.com/adte/sales-agent/internal/auth"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

type RateLimiterStore struct {
	mu      sync.Mutex
	clients map[string]*clientLimiter
	limit   rate.Limit
	burst   int
	ttl     time.Duration
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewRateLimiterStore(limit rate.Limit, burst int, ttl time.Duration) *RateLimiterStore {
	return &RateLimiterStore{
		clients: make(map[string]*clientLimiter),
		limit:   limit,
		burst:   burst,
		ttl:     ttl,
	}
}

func (s *RateLimiterStore) getLimiter(key string) *rate.Limiter {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.clients[key]; ok {
		entry.lastSeen = now
		return entry.limiter
	}

	limiter := rate.NewLimiter(s.limit, s.burst)
	s.clients[key] = &clientLimiter{limiter: limiter, lastSeen: now}

	// Clean up old entries
	for k, v := range s.clients {
		if now.Sub(v.lastSeen) > s.ttl {
			delete(s.clients, k)
		}
	}
	return limiter
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}

func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(lrw, r)
			logger.Info("request completed",
				"method", r.Method,
				"path", r.URL.Path,
				"status", lrw.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// CORS middleware to allow the AdCP Testing Framework (or any origin) to access our API.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow all origins and necessary headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Vary", "Origin")

		if r.Method == http.MethodOptions {
			// Respond to preflight requests quickly
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// For actual requests, ensure content is JSON
		// w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// RateLimit middleware implements per-IP rate limiting
func RateLimitMiddleware(store *RateLimiterStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := clientIPFromRequest(r)
			limiter := store.getLimiter(clientIP)
			if !limiter.Allow() {
				slog.Default().Warn("rate limit exceeded", "client_ip", clientIP, "path", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"Rate limit exceeded","code":"RATE_LIMIT_EXCEEDED"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Add request body size limit middleware
func LimitBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// JWTClaims represents the claims in our JWT tokens (AdCP compliant)
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

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	ContextKeyClaims contextKey = "jwt_claims"
)

// JWTAuthMiddleware creates a middleware that validates JWT tokens
func JWTAuthMiddleware(jwtSecretKey string, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				sendUnauthorizedResponse(w, "Missing authorization header", logger)
				return
			}

			// Check Bearer scheme
			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
				sendUnauthorizedResponse(w, "Invalid authorization header format", logger)
				return
			}

			tokenString := tokenParts[1]

			// Parse and validate the token
			claims := &JWTClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				// Verify the signing method
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(jwtSecretKey), nil
			})

			if err != nil {
				logger.Debug("JWT validation failed", "error", err, "path", r.URL.Path)
				sendUnauthorizedResponse(w, "Invalid or expired token", logger)
				return
			}

			if !token.Valid {
				sendUnauthorizedResponse(w, "Invalid token", logger)
				return
			}

			// Add claims to request context
			ctx := context.WithValue(r.Context(), ContextKeyClaims, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaimsFromContext retrieves JWT claims from the request context
func GetClaimsFromContext(ctx context.Context) (*JWTClaims, bool) {
	claims, ok := ctx.Value(ContextKeyClaims).(*JWTClaims)
	return claims, ok
}

// sendUnauthorizedResponse sends a 401 Unauthorized response
func sendUnauthorizedResponse(w http.ResponseWriter, message string, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	response := map[string]string{
		"error": message,
		"code":  "UNAUTHORIZED",
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Error("failed to encode error response", "error", err)
	}
}

// sendAuthErrorResponse sends an authentication error response with AdCP-compliant error codes
func sendAuthErrorResponse(w http.ResponseWriter, code string, message string, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	statusCode := http.StatusUnauthorized
	if code == "INSUFFICIENT_PERMISSIONS" {
		statusCode = http.StatusForbidden
	}
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Error("failed to encode error response", "error", err)
	}
}

// ExcludePathsMiddleware wraps a middleware to exclude certain paths
func ExcludePathsMiddleware(middleware func(http.Handler) http.Handler, excludedPaths []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the current path should be excluded
			for _, path := range excludedPaths {
				if r.URL.Path == path {
					// Skip the middleware for excluded paths
					next.ServeHTTP(w, r)
					return
				}
			}
			// Apply the middleware for non-excluded paths
			middleware(next).ServeHTTP(w, r)
		})
	}
}

// OptionalAuthMiddleware allows public paths to be accessed without authentication
// but still extracts authentication context if credentials are provided
func OptionalAuthMiddleware(authMiddleware func(http.Handler) http.Handler, publicPaths []string, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the current path is public
			isPublic := false
			for _, path := range publicPaths {
				if r.URL.Path == path {
					isPublic = true
					break
				}
			}

			if isPublic {
				// For public paths, try to extract auth but don't require it
				// We need to capture the authenticated request context
				var authenticatedRequest *http.Request
				
				// Create a custom handler that captures the authenticated request
				captureHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					// Capture the request with auth context
					authenticatedRequest = req
					// Don't call next here - we'll do it after checking auth status
				})

				// Create a response writer that captures status codes
				captureWriter := &authCaptureWriter{ResponseWriter: w, isPublic: true}
				
				// Try to authenticate
				authMiddleware(captureHandler).ServeHTTP(captureWriter, r)
				
				// If auth failed (401/403), still continue for public endpoints
				if captureWriter.authFailed {
					logger.Debug("Optional auth failed for public endpoint, continuing without auth", 
						"path", r.URL.Path,
						"hasAuthHeader", r.Header.Get("Authorization") != "",
						"hasAPIKey", r.Header.Get("X-API-Key") != "")
					// Continue without auth context
					next.ServeHTTP(w, r)
				} else if authenticatedRequest != nil {
					// Auth succeeded - use the request with auth context
					logger.Debug("Optional auth succeeded for public endpoint", 
						"path", r.URL.Path,
						"hasContext", authenticatedRequest.Context() != r.Context())
					next.ServeHTTP(w, authenticatedRequest)
				} else {
					// No auth attempted (no credentials provided)
					next.ServeHTTP(w, r)
				}
			} else {
				// For protected paths, require authentication
				authMiddleware(next).ServeHTTP(w, r)
			}
		})
	}
}

// authCaptureWriter captures authentication failures for public endpoints
type authCaptureWriter struct {
	http.ResponseWriter
	authFailed bool
	isPublic   bool
	written    bool
}

func (w *authCaptureWriter) WriteHeader(code int) {
	if w.isPublic && (code == http.StatusUnauthorized || code == http.StatusForbidden) {
		w.authFailed = true
		// Don't actually write the error for public endpoints
		return
	}
	w.written = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *authCaptureWriter) Write(b []byte) (int, error) {
	if w.isPublic && w.authFailed {
		// Don't write auth errors for public endpoints
		return len(b), nil
	}
	w.written = true
	return w.ResponseWriter.Write(b)
}

// UnifiedAuthMiddleware creates a middleware that validates both JWT tokens and API keys
// This implements the AdCP authentication specification
func UnifiedAuthMiddleware(jwtSecretKey string, apiKeyStore *auth.APIKeyStore, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for dry-run mode
			if dryRun := r.Header.Get("X-Dry-Run"); strings.ToLower(dryRun) == "true" {
				ctx := context.WithValue(r.Context(), auth.ContextKeyDryRun, true)
				r = r.WithContext(ctx)
			}

			// Try API Key authentication first
			if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
				principal, ok := apiKeyStore.GetPrincipal(apiKey)
				if !ok {
					sendAuthErrorResponse(w, "AUTH_INVALID", "Invalid or expired credentials", logger)
					return
				}
				// Add principal to context
				ctx := context.WithValue(r.Context(), auth.ContextKeyPrincipal, principal)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Try JWT Bearer token authentication
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				sendAuthErrorResponse(w, "AUTH_REQUIRED", "Authentication required for this operation", logger)
				return
			}

			// Check Bearer scheme
			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
				sendAuthErrorResponse(w, "AUTH_INVALID", "Invalid authorization header format", logger)
				return
			}

			tokenString := tokenParts[1]

			// Parse and validate the token
			claims := &JWTClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				// Verify the signing method
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(jwtSecretKey), nil
			})

			if err != nil {
				logger.Debug("JWT validation failed", "error", err, "path", r.URL.Path)
				sendAuthErrorResponse(w, "AUTH_INVALID", "Invalid or expired credentials", logger)
				return
			}

			if !token.Valid {
				sendAuthErrorResponse(w, "AUTH_INVALID", "Invalid token", logger)
				return
			}

			// Convert JWT claims to Principal
			principal := &auth.Principal{
				PrincipalID: claims.Subject,
				Permissions: make(map[string][]auth.Permission),
			}

			// Convert string permissions to Permission type
			if len(claims.Permissions.Products) > 0 {
				principal.Permissions["products"] = stringSliceToPermissions(claims.Permissions.Products)
			}
			if len(claims.Permissions.MediaBuys) > 0 {
				principal.Permissions["media_buys"] = stringSliceToPermissions(claims.Permissions.MediaBuys)
			}
			if len(claims.Permissions.Creatives) > 0 {
				principal.Permissions["creatives"] = stringSliceToPermissions(claims.Permissions.Creatives)
			}
			if len(claims.Permissions.Reports) > 0 {
				principal.Permissions["reports"] = stringSliceToPermissions(claims.Permissions.Reports)
			}

			// Add principal to context
			ctx := context.WithValue(r.Context(), auth.ContextKeyPrincipal, principal)
			
			// Keep backward compatibility by also adding claims
			ctx = context.WithValue(ctx, ContextKeyClaims, claims)
			
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// stringSliceToPermissions converts string permissions to Permission types
func stringSliceToPermissions(perms []string) []auth.Permission {
	result := make([]auth.Permission, 0, len(perms))
	for _, p := range perms {
		result = append(result, auth.Permission(p))
	}
	return result
}
