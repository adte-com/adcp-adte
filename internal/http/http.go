package http

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"adte.com/adte/sales-agent/internal/api"
	"adte.com/adte/sales-agent/internal/server"
)

// HTTPHandler wraps the server and provides HTTP handlers
type HTTPHandler struct {
	srv *server.Server
}

// NewHTTPHandler creates a new HTTP handler
func NewHTTPHandler(srv *server.Server) *HTTPHandler {
	return &HTTPHandler{srv: srv}
}

// Returns properties that this sales agent is authorized to sell.
func (h *HTTPHandler) ListAuthorizedPropertiesHandler(w http.ResponseWriter, r *http.Request) {
	// Simply return the pre-defined authorized properties (pointing to publisher domain and property IDs)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(h.srv.AuthProperties); err != nil {
		h.srv.Logger.Error("encode authorized properties failed", "error", err)
	}
}

// Returns the list of available advertising products (inventory offerings).
func (h *HTTPHandler) GetProductsHandler(w http.ResponseWriter, r *http.Request) {
	// Wrap the product catalog in a JSON object
	w.Header().Set("Content-Type", "application/json")
	resp := struct {
		Products []api.Product `json:"products"`
	}{Products: h.srv.Products}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.srv.Logger.Error("encode products failed", "error", err)
	}
}

// Returns supported creative formats (here we reference the standard Creative agent).
func (h *HTTPHandler) ListCreativeFormatsHandler(w http.ResponseWriter, r *http.Request) {
	// No custom formats defined; we advertise support for all standard formats via the reference Creative agent.
	w.Header().Set("Content-Type", "application/json")
	resp := api.CreativeFormatsResponse{
		Formats:        []api.CreativeFormat{},                             // no custom formats
		CreativeAgents: []string{"https://creative.adcontextprotocol.org"}, // reference agent for standard formats
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.srv.Logger.Error("encode creative formats failed", "error", err)
	}
}

// Processes a new media buy request (campaign creation).
func (h *HTTPHandler) CreateMediaBuyHandler(w http.ResponseWriter, r *http.Request) {
	var req api.CreateMediaBuyRequest

	// Parse request JSON into struct
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		h.sendDetailedErrorResponse(w, "Invalid JSON format", "INVALID_JSON", err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Use shared business logic
	resp, err := h.srv.CreateMediaBuy(ctx, server.CreateMediaBuyParams{
		Request: &req,
	})
	if err != nil {
		// Handle validation errors
		if valErr, ok := err.(server.ValidationError); ok {
			h.sendErrorResponse(w, valErr.Message, valErr.Code, http.StatusBadRequest)
			return
		}
		h.srv.Logger.Error("create media buy failed", "error", err)
		h.sendErrorResponse(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.srv.Logger.Error("encode response failed", "error", err)
	}
}

// Updates an existing media buy
func (h *HTTPHandler) UpdateMediaBuyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		h.sendErrorResponse(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}

	mediaBuyID := r.URL.Query().Get("media_buy_id")
	if mediaBuyID == "" {
		h.sendErrorResponse(w, "media_buy_id required", "MISSING_REQUIRED_FIELD", http.StatusBadRequest)
		return
	}

	var updates struct {
		Status  *string `json:"status,omitempty"`
		EndTime *string `json:"end_time,omitempty"`
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&updates); err != nil {
		h.sendDetailedErrorResponse(w, "Invalid JSON format", "INVALID_JSON", err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Use shared business logic
	resp, err := h.srv.UpdateMediaBuy(ctx, server.UpdateMediaBuyParams{
		MediaBuyID: mediaBuyID,
		Status:     updates.Status,
		EndTime:    updates.EndTime,
	})
	if err != nil {
		// Handle validation errors
		if valErr, ok := err.(server.ValidationError); ok {
			status := http.StatusBadRequest
			if valErr.Code == "NOT_FOUND" {
				status = http.StatusNotFound
			}
			h.sendErrorResponse(w, valErr.Message, valErr.Code, status)
			return
		}
		h.srv.Logger.Error("update media buy failed", "error", err)
		h.sendErrorResponse(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.srv.Logger.Error("encode response failed", "error", err)
	}
}

func (h *HTTPHandler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()

	if err := h.srv.DB.PingContext(ctx); err != nil {
		h.sendErrorResponse(w, "database unavailable", "DATABASE_UNAVAILABLE", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"agent":  "ADTE Sales Agent",
	}); err != nil {
		h.srv.Logger.Error("encode health response failed", "error", err)
	}
}

// Sends a structured error response
func (h *HTTPHandler) sendErrorResponse(w http.ResponseWriter, message string, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(api.ErrorResponse{
		Error: message,
		Code:  code,
	}); err != nil {
		h.srv.Logger.Error("encode error response failed", "code", code, "error", err)
	}
}

// Sends an error with additional details
func (h *HTTPHandler) sendDetailedErrorResponse(w http.ResponseWriter, message string, code string, details string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(api.ErrorResponse{
		Error:   message,
		Code:    code,
		Details: details,
	}); err != nil {
		h.srv.Logger.Error("encode detailed error response failed", "code", code, "error", err)
	}
}
