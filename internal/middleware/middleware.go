package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

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
