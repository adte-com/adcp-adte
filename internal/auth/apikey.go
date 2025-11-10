package auth

import (
	"sync"
)

// APIKeyStore manages API keys and their associated principals
type APIKeyStore struct {
	mu    sync.RWMutex
	keys  map[string]*Principal
}

// NewAPIKeyStore creates a new API key store
func NewAPIKeyStore() *APIKeyStore {
	return &APIKeyStore{
		keys: make(map[string]*Principal),
	}
}

// AddKey adds an API key with its associated principal
func (s *APIKeyStore) AddKey(apiKey string, principal *Principal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[apiKey] = principal
}

// GetPrincipal retrieves a principal by API key
func (s *APIKeyStore) GetPrincipal(apiKey string) (*Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	principal, ok := s.keys[apiKey]
	return principal, ok
}

// RemoveKey removes an API key
func (s *APIKeyStore) RemoveKey(apiKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, apiKey)
}

// InitializeDefaultAPIKeys sets up default API keys for testing
// In production, these would come from a database or configuration
func InitializeDefaultAPIKeys() *APIKeyStore {
	store := NewAPIKeyStore()
	
	// Add a test API key with full permissions
	store.AddKey("test_api_key_full_access", &Principal{
		PrincipalID: "principal_test_full",
		Permissions: map[string][]Permission{
			"products":  {PermissionRead},
			"media_buys": {PermissionRead, PermissionWrite},
			"creatives": {PermissionRead, PermissionWrite},
			"reports":   {PermissionRead, PermissionWrite},
		},
	})
	
	// Add a read-only API key
	store.AddKey("test_api_key_readonly", &Principal{
		PrincipalID: "principal_test_readonly",
		Permissions: map[string][]Permission{
			"products":  {PermissionRead},
			"media_buys": {PermissionRead},
			"creatives": {PermissionRead},
			"reports":   {PermissionRead},
		},
	})
	
	return store
}
