package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"adte.com/adte/sales-agent/internal/api"
	"adte.com/adte/sales-agent/internal/auth"
	"adte.com/adte/sales-agent/internal/config"
	"adte.com/adte/sales-agent/internal/server"
)

// HTTPHandler wraps the server and provides HTTP handlers
type HTTPHandler struct {
	srv         *server.Server
	config      *config.Config
	apiKeyStore *auth.APIKeyStore
}

// NewHTTPHandler creates a new HTTP handler
func NewHTTPHandler(srv *server.Server, config *config.Config, apiKeyStore *auth.APIKeyStore) *HTTPHandler {
	return &HTTPHandler{srv: srv, config: config, apiKeyStore: apiKeyStore}
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
//
//	func (h *HTTPHandler) GetProductsHandler(w http.ResponseWriter, r *http.Request) {
//		// Wrap the product catalog in a JSON object
//		w.Header().Set("Content-Type", "application/json")
//		resp := struct {
//			Products []api.Product `json:"products"`
//		}{Products: h.srv.Products}
//		if err := json.NewEncoder(w).Encode(resp); err != nil {
//			h.srv.Logger.Error("encode products failed", "error", err)
//		}
//	}
func (h *HTTPHandler) GetProductsHandler(w http.ResponseWriter, r *http.Request) {
	// Check if request is authenticated
	principal, isAuthenticated := auth.GetPrincipalFromContext(r.Context())
	
	// Log authentication status
	h.srv.Logger.Debug("get_products request", 
		"isAuthenticated", isAuthenticated,
		"principalID", func() string {
			if principal != nil {
				return principal.PrincipalID
			}
			return "none"
		}(),
		"hasAuthHeader", r.Header.Get("Authorization") != "",
		"hasAPIKey", r.Header.Get("X-API-Key") != "")

	// Parse optional request body for filters
	var req struct {
		Brief   string `json:"brief,omitempty"`
		Filters struct {
			DeliveryType        string   `json:"delivery_type,omitempty"`
			IsFixedPrice        *bool    `json:"is_fixed_price,omitempty"`
			FormatTypes         []string `json:"format_types,omitempty"`
			StandardFormatsOnly bool     `json:"standard_formats_only,omitempty"`
			MinExposures        int      `json:"min_exposures,omitempty"`
		} `json:"filters,omitempty"`
		BrandManifest interface{} `json:"brand_manifest,omitempty"`
	}

	// Try to parse request body if present
	if r.Body != nil && r.ContentLength > 0 {
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			// If decode fails, just proceed with no filters
			h.srv.Logger.Debug("failed to parse product request filters", "error", err)
		}
	}

	// Convert internal products to match AdCP spec exactly
	// For unauthenticated requests, limit to run-of-network products only
	productsToShow := h.srv.Products
	if !isAuthenticated {
		// Filter to only basic products for unauthenticated users
		// In this implementation, we'll show products but without pricing
		h.srv.Logger.Debug("Limiting products for unauthenticated request")
	}
	
	adcpProducts := make([]map[string]interface{}, 0, len(productsToShow))

	for _, product := range productsToShow {
		// Convert properties to AdCP format
		properties := []map[string]interface{}{}
		for _, prop := range product.Properties {
			properties = append(properties, map[string]interface{}{
				"property_type": "website", // All our properties are websites for now
				"name":          "FOMO TV",
				"identifiers": []map[string]interface{}{
					{
						"type":  "domain",
						"value": "adte.com",
					},
				},
				"tags":             []string{"premium_content", "video_content"},
				"publisher_domain": prop.PublisherDomain,
			})
		}

		// Convert format IDs to proper structure
		formatIDs := []map[string]interface{}{}
		for _, sf := range product.SupportedFormats {
			formatIDs = append(formatIDs, map[string]interface{}{
				"agent_url": sf.FormatID.AgentURL,
				"id":        sf.FormatID.ID,
			})
		}

		// Build the product object matching AdCP spec
		adcpProduct := map[string]interface{}{
			"product_id":     product.ProductID,
			"name":           product.Name,
			"description":    getProductDescription(product),
			"properties":     properties,
			"format_ids":     formatIDs,
			"delivery_type":  product.DeliveryType,
			"is_fixed_price": true, // All our products are fixed price
			"currency":       "USD",
			"min_spend":      1000.0, // Minimum spend in USD
		}

		// Add pricing information only for authenticated requests
		if isAuthenticated && len(product.PricingOptions) > 0 {
			// Use the first pricing option's rate as CPM
			adcpProduct["cpm"] = product.PricingOptions[0].Rate

			// Also include pricing_options array for create_media_buy
			pricingOptions := []map[string]interface{}{}
			for _, po := range product.PricingOptions {
				pricingOptions = append(pricingOptions, map[string]interface{}{
					"pricing_option_id": po.PricingOptionID,
					"model":             po.Model,
					"currency":          po.Currency,
					"is_fixed":          po.IsFixed,
					"rate":              po.Rate,
				})
			}
			adcpProduct["pricing_options"] = pricingOptions
		} else if !isAuthenticated {
			// For unauthenticated requests, remove pricing-related fields
			delete(adcpProduct, "currency")
			delete(adcpProduct, "min_spend")
		}

		// Add measurement capabilities
		if len(product.AvailableMetrics) > 0 {
			adcpProduct["available_metrics"] = product.AvailableMetrics
		}

		// Add brief relevance if a brief was provided
		if req.Brief != "" {
			adcpProduct["is_custom"] = false
			adcpProduct["brief_relevance"] = getBriefRelevance(product, req.Brief)
		}

		adcpProducts = append(adcpProducts, adcpProduct)
	}

	// Build response
	resp := map[string]interface{}{
		"products": adcpProducts,
	}

	// Add authentication status information for unauthenticated requests
	if !isAuthenticated {
		resp["limited_results"] = true
		resp["auth_required_for"] = []string{"pricing", "custom_products", "full_catalog"}
		resp["message"] = fmt.Sprintf("Found %d products (limited catalog - authenticate for full access including pricing)", len(adcpProducts))
	} else if req.Brief != "" {
		resp["message"] = fmt.Sprintf("Found %d products matching your requirements for %s",
			len(adcpProducts), req.Brief)
	} else {
		resp["message"] = fmt.Sprintf("Found %d products available for purchase", len(adcpProducts))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.srv.Logger.Error("encode products failed", "error", err)
	}
}

// Helper function to generate product descriptions
func getProductDescription(product api.Product) string {
	switch product.ProductID {
	case "ctv_premium_preroll_30s":
		return "Premium 30-second pre-roll video ads on FOMO TV's CTV platform, reaching engaged viewers on connected TV devices"
	case "ctv_premium_preroll_15s":
		return "Premium 15-second pre-roll video ads on FOMO TV's CTV platform, optimized for shorter attention spans"
	case "web_premium_preroll_30s_companion":
		return "Premium 30-second pre-roll video with companion display ad on FOMO TV's web platform for maximum engagement"
	default:
		return product.Name
	}
}

// Helper function to generate brief relevance
func getBriefRelevance(product api.Product, brief string) string {
	briefLower := strings.ToLower(brief)

	if strings.Contains(briefLower, "video") || strings.Contains(briefLower, "ctv") {
		if strings.Contains(product.ProductID, "ctv") {
			return "Premium CTV inventory perfectly suited for video campaigns"
		}
		if strings.Contains(product.ProductID, "web") {
			return "Web video inventory with companion display for broader reach"
		}
	}

	if strings.Contains(briefLower, "premium") {
		return "Premium inventory on FOMO TV's high-quality content"
	}

	return "Quality inventory matching campaign requirements"
}

// Returns supported creative formats (here we reference the standard Creative agent).
func (h *HTTPHandler) ListCreativeFormatsHandler(w http.ResponseWriter, r *http.Request) {
	// Parse optional filters from request
	var req struct {
		FormatIDs    []api.FormatID `json:"format_ids,omitempty"`
		Type         string         `json:"type,omitempty"`
		AssetTypes   []string       `json:"asset_types,omitempty"`
		MaxWidth     *int           `json:"max_width,omitempty"`
		MaxHeight    *int           `json:"max_height,omitempty"`
		MinWidth     *int           `json:"min_width,omitempty"`
		MinHeight    *int           `json:"min_height,omitempty"`
		IsResponsive *bool          `json:"is_responsive,omitempty"`
		NameSearch   string         `json:"name_search,omitempty"`
	}

	// Try to parse request body if present
	if r.Body != nil && r.ContentLength > 0 {
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			h.srv.Logger.Debug("Failed to parse format filters", "error", err)
		}
	}

	// Define the formats we support based on our products
	creativeAgentURL := "https://creative.adcontextprotocol.org"

	allFormats := []map[string]interface{}{
		{
			"format_id": map[string]interface{}{
				"agent_url": creativeAgentURL,
				"id":        "video_30s_hosted",
			},
			"name": "30-Second Hosted Video",
			"type": "video",
			"requirements": map[string]interface{}{
				"duration":         "30s",
				"aspect_ratio":     "16:9",
				"file_types":       []string{"mp4", "webm"},
				"max_file_size_mb": 50,
				"resolution":       []string{"1920x1080", "1280x720"},
			},
			"assets_required": []map[string]interface{}{
				{
					"asset_id":   "video_file",
					"asset_type": "video",
					"asset_role": "hero_video",
					"required":   true,
					"width":      1920,
					"height":     1080,
					"requirements": map[string]interface{}{
						"duration":         "30s",
						"format":           "MP4 H.264",
						"resolution":       []string{"1920x1080", "1280x720"},
						"max_file_size_mb": 50,
					},
				},
			},
		},
		{
			"format_id": map[string]interface{}{
				"agent_url": creativeAgentURL,
				"id":        "video_15s_hosted",
			},
			"name": "15-Second Hosted Video",
			"type": "video",
			"requirements": map[string]interface{}{
				"duration":         "15s",
				"aspect_ratio":     "16:9",
				"file_types":       []string{"mp4", "webm"},
				"max_file_size_mb": 30,
				"resolution":       []string{"1920x1080", "1280x720"},
			},
			"assets_required": []map[string]interface{}{
				{
					"asset_id":   "video_file",
					"asset_type": "video",
					"asset_role": "hero_video",
					"required":   true,
					"width":      1920,
					"height":     1080,
					"requirements": map[string]interface{}{
						"duration":         "15s",
						"format":           "MP4 H.264",
						"resolution":       []string{"1920x1080", "1280x720"},
						"max_file_size_mb": 30,
					},
				},
			},
		},
		{
			"format_id": map[string]interface{}{
				"agent_url": creativeAgentURL,
				"id":        "display_300x250",
			},
			"name":       "Medium Rectangle Banner",
			"type":       "display",
			"dimensions": "300x250",
			"requirements": map[string]interface{}{
				"width":            300,
				"height":           250,
				"file_types":       []string{"jpg", "png", "gif"},
				"max_file_size_kb": 200,
			},
			"assets_required": []map[string]interface{}{
				{
					"asset_id":           "banner_image",
					"asset_type":         "image",
					"asset_role":         "hero_image",
					"required":           true,
					"width":              300,
					"height":             250,
					"acceptable_formats": []string{"jpg", "png", "gif"},
					"max_file_size_kb":   200,
				},
			},
		},
	}

	// Apply filters
	filteredFormats := []map[string]interface{}{}

	for _, format := range allFormats {
		// Check if specific format IDs were requested
		if len(req.FormatIDs) > 0 {
			formatID := format["format_id"].(map[string]interface{})
			matches := false
			for _, requestedID := range req.FormatIDs {
				if formatID["id"] == requestedID.ID {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}
		}

		// Filter by type
		if req.Type != "" && format["type"] != req.Type {
			continue
		}

		// Filter by asset types
		if len(req.AssetTypes) > 0 {
			hasAssetType := false
			if assetsRequired, ok := format["assets_required"].([]map[string]interface{}); ok {
				for _, asset := range assetsRequired {
					for _, requestedType := range req.AssetTypes {
						if asset["asset_type"] == requestedType {
							hasAssetType = true
							break
						}
					}
					if hasAssetType {
						break
					}
				}
			}
			if !hasAssetType {
				continue
			}
		}

		// Filter by dimensions
		if req.MaxWidth != nil || req.MaxHeight != nil || req.MinWidth != nil || req.MinHeight != nil {
			width := 0
			height := 0

			// Try to get dimensions from requirements
			if requirements, ok := format["requirements"].(map[string]interface{}); ok {
				if w, ok := requirements["width"].(int); ok {
					width = w
				}
				if h, ok := requirements["height"].(int); ok {
					height = h
				}
			}

			// Check dimension constraints
			if req.MaxWidth != nil && width > *req.MaxWidth {
				continue
			}
			if req.MaxHeight != nil && height > *req.MaxHeight {
				continue
			}
			if req.MinWidth != nil && width < *req.MinWidth {
				continue
			}
			if req.MinHeight != nil && height < *req.MinHeight {
				continue
			}
		}

		// Filter by name search
		if req.NameSearch != "" {
			name := format["name"].(string)
			if !strings.Contains(strings.ToLower(name), strings.ToLower(req.NameSearch)) {
				continue
			}
		}

		filteredFormats = append(filteredFormats, format)
	}

	// Build response
	resp := map[string]interface{}{
		"formats": filteredFormats,
		"creative_agents": []map[string]interface{}{
			{
				"agent_url":    creativeAgentURL,
				"agent_name":   "AdCP Reference Creative Agent",
				"capabilities": []string{"validation", "assembly", "preview"},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.srv.Logger.Error("encode creative formats failed", "error", err)
	}
}

// Processes a new media buy request (campaign creation).
func (h *HTTPHandler) CreateMediaBuyHandler(w http.ResponseWriter, r *http.Request) {
	var req api.CreateMediaBuyRequest

	// Authentication is already enforced by middleware for this endpoint
	// Get the authenticated principal from context
	principal, hasPrincipal := auth.GetPrincipalFromContext(r.Context())
	if hasPrincipal {
		h.srv.Logger.Debug("create_media_buy request", "principalID", principal.PrincipalID)
	}

	// Parse request JSON into struct
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		h.sendDetailedErrorResponse(w, "Invalid JSON format", "INVALID_JSON", err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Check if this is a dry-run request
	isDryRun := auth.IsDryRun(ctx)
	
	if isDryRun {
		// In dry-run mode, validate but don't save
		// First validate the request
		if err := h.srv.ValidateMediaBuyRequest(&req); err != nil {
			if valErr, ok := err.(server.ValidationError); ok {
				h.sendErrorResponse(w, valErr.Message, valErr.Code, http.StatusBadRequest)
				return
			}
			h.sendErrorResponse(w, err.Error(), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		
		// Return success response without actually creating
		dryRunResp := &api.CreateMediaBuyResponse{
			MediaBuyID: "mb_dryrun_123",
			PackageIDs: []string{"pkg_dryrun_1", "pkg_dryrun_2"},
			Message:    "Media buy validated successfully (dry-run mode)",
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Dry-Run", "true")
		w.WriteHeader(http.StatusOK) // Use 200 for dry-run instead of 201
		if err := json.NewEncoder(w).Encode(dryRunResp); err != nil {
			h.srv.Logger.Error("encode dry-run response failed", "error", err)
		}
		return
	}

	// Use shared business logic for actual creation
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

// sendAuthErrorResponse sends an authentication/authorization error response following AdCP spec
func (h *HTTPHandler) sendAuthErrorResponse(w http.ResponseWriter, code string, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	response := map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.srv.Logger.Error("encode auth error response failed", "code", code, "error", err)
	}
}

// MCPHandler handles MCP protocol requests over HTTP
func (h *HTTPHandler) MCPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-MCP-Version", "1.0")

	h.srv.Logger.Debug("MCPHandler called", "method", r.Method, "path", r.URL.Path)

	// Handle MCP discovery via GET
	if r.Method == http.MethodGet {
		discovery := map[string]interface{}{
			"mcp_version": "1.0",
			"server": map[string]interface{}{
				"name":    "Adte Sales Agent",
				"version": "0.1.0",
			},
			"tools": []map[string]interface{}{
				{
					"name":        "adcp.list_authorized_properties",
					"description": "List properties authorized for this sales agent",
				},
				{
					"name":        "adcp.get_products",
					"description": "Get available advertising products",
				},
				{
					"name":        "adcp.list_creative_formats",
					"description": "List supported creative formats",
				},
				{
					"name":        "adcp.create_media_buy",
					"description": "Create a new media buy",
				},
				{
					"name":        "adcp.update_media_buy",
					"description": "Update an existing media buy",
				},
				{
					"name":        "adcp.list_creatives",
					"description": "List creatives",
				},
			},
			"capabilities": map[string]bool{
				"tools": true,
			},
		}
		if err := json.NewEncoder(w).Encode(discovery); err != nil {
			h.srv.Logger.Error("encode MCP discovery failed", "error", err)
		}
		return
	}

	// Handle MCP tool calls via POST
	if r.Method == http.MethodPost {
		// Read the body first to see what we're getting
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		h.srv.Logger.Debug("MCP POST request body", "body", string(bodyBytes))

		// Try to decode as JSON-RPC request
		var jsonRPCReq struct {
			JSONRPC string          `json:"jsonrpc"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
			ID      json.RawMessage `json:"id"`
		}

		if err := json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&jsonRPCReq); err != nil {
			h.srv.Logger.Error("Failed to decode JSON-RPC request", "error", err)
			jsonRPCError := map[string]interface{}{
				"jsonrpc": "2.0",
				"error": map[string]interface{}{
					"code":    -32700,
					"message": "Parse error",
				},
				"id": nil,
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(jsonRPCError)
			return
		}

		// Handle JSON-RPC methods
		if jsonRPCReq.JSONRPC == "2.0" {
			switch jsonRPCReq.Method {
			case "initialize":
				// Handle MCP initialization
				response := map[string]interface{}{
					"jsonrpc": "2.0",
					"result": map[string]interface{}{
						"protocolVersion": "2025-06-18",
						"capabilities": map[string]interface{}{
							"tools": map[string]interface{}{},
						},
						"serverInfo": map[string]interface{}{
							"name":    "Adte Sales Agent",
							"version": "0.1.0",
						},
					},
					"id": jsonRPCReq.ID,
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
				return

			case "tools/list":
				// List available tools
				response := map[string]interface{}{
					"jsonrpc": "2.0",
					"result": map[string]interface{}{
						"tools": []map[string]interface{}{
							{
								"name":        "list_authorized_properties",
								"description": "List properties authorized for this sales agent",
								"inputSchema": map[string]interface{}{
									"type":       "object",
									"properties": map[string]interface{}{},
								},
							},
							{
								"name":        "get_products",
								"description": "Get available advertising products",
								"inputSchema": map[string]interface{}{
									"type":       "object",
									"properties": map[string]interface{}{},
								},
							},
							{
								"name":        "list_creative_formats",
								"description": "List supported creative formats",
								"inputSchema": map[string]interface{}{
									"type":       "object",
									"properties": map[string]interface{}{},
								},
							},
							{
								"name":        "list_creatives",
								"description": "List creatives (not managed by this sales agent)",
								"inputSchema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"filters": map[string]interface{}{
											"type": "object",
											"properties": map[string]interface{}{
												"status": map[string]interface{}{
													"type": "string",
												},
												"formats": map[string]interface{}{
													"type": "array",
													"items": map[string]interface{}{
														"type": "string",
													},
												},
											},
										},
										"pagination": map[string]interface{}{
											"type": "object",
											"properties": map[string]interface{}{
												"limit": map[string]interface{}{
													"type":    "integer",
													"minimum": 1,
													"maximum": 100,
												},
												"offset": map[string]interface{}{
													"type":    "integer",
													"minimum": 0,
												},
											},
										},
									},
								},
							},
							{
								"name":        "create_media_buy",
								"description": "Create a new media buy",
								"inputSchema": map[string]interface{}{
									"type":     "object",
									"required": []string{"brand_manifest", "packages"},
									"properties": map[string]interface{}{
										"brand_manifest": map[string]interface{}{
											"type":     "object",
											"required": []string{"url"},
											"properties": map[string]interface{}{
												"url": map[string]interface{}{
													"type":   "string",
													"format": "uri",
												},
												"name": map[string]interface{}{
													"type": "string",
												},
											},
										},
										"packages": map[string]interface{}{
											"type":     "array",
											"minItems": 1,
											"items": map[string]interface{}{
												"type": "object",
												"required": []string{
													"product_id",
													"pricing_option_id",
													"format_ids",
													"budget",
												},
												"properties": map[string]interface{}{
													"buyer_ref": map[string]interface{}{
														"type": "string",
													},
													"product_id": map[string]interface{}{
														"type": "string",
													},
													"pricing_option_id": map[string]interface{}{
														"type": "string",
													},
													"format_ids": map[string]interface{}{
														"type": "array",
														"items": map[string]interface{}{
															"type": "object",
															"properties": map[string]interface{}{
																"agent_url": map[string]interface{}{
																	"type": "string",
																},
																"id": map[string]interface{}{
																	"type": "string",
																},
															},
														},
													},
													"budget": map[string]interface{}{
														"type":    "number",
														"minimum": 0,
													},
													"pacing": map[string]interface{}{
														"type": "string",
														"enum": []string{"even", "asap", "frontloaded"},
													},
												},
											},
										},
										"start_time": map[string]interface{}{
											"type":   "string",
											"format": "date-time",
										},
										"end_time": map[string]interface{}{
											"type":   "string",
											"format": "date-time",
										},
									},
								},
							},
							{
								"name":        "update_media_buy",
								"description": "Update an existing media buy",
								"inputSchema": map[string]interface{}{
									"type":     "object",
									"required": []string{"media_buy_id"},
									"properties": map[string]interface{}{
										"media_buy_id": map[string]interface{}{
											"type":        "string",
											"description": "ID of the media buy to update",
										},
										"status": map[string]interface{}{
											"type":        "string",
											"enum":        []string{"active", "paused", "cancelled"},
											"description": "New status for the media buy",
										},
										"end_time": map[string]interface{}{
											"type":        "string",
											"format":      "date-time",
											"description": "New end time for the media buy",
										},
									},
								},
							},
						},
					},
					"id": jsonRPCReq.ID,
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
				return

			case "tools/call":
				// Handle tool calls
				var params struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				}
				if err := json.Unmarshal(jsonRPCReq.Params, &params); err != nil {
					jsonRPCError := map[string]interface{}{
						"jsonrpc": "2.0",
						"error": map[string]interface{}{
							"code":    -32602,
							"message": "Invalid params",
						},
						"id": jsonRPCReq.ID,
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(jsonRPCError)
					return
				}

				// Check if authentication is required for this tool
				if h.isAuthRequired(params.Name) {
					// Check for token in Authorization header (Bearer token)
					authHeader := r.Header.Get("Authorization")
					
					// Also check X-MCP-Token header as alternative
					mcpToken := r.Header.Get("X-MCP-Token")
					
					// Extract token from Bearer format
					var providedToken string
					if strings.HasPrefix(authHeader, "Bearer ") {
						providedToken = strings.TrimPrefix(authHeader, "Bearer ")
					} else if mcpToken != "" {
						providedToken = mcpToken
					}
					
					// Check if token is provided
					if providedToken == "" {
						h.srv.Logger.Debug("MCP authentication missing for protected operation", 
							"tool", params.Name)
						jsonRPCError := map[string]interface{}{
							"jsonrpc": "2.0",
							"error": map[string]interface{}{
								"code":    -32603,
								"message": "Authentication required for this operation",
								"data": map[string]interface{}{
									"code": "AUTH_REQUIRED",
								},
							},
							"id": jsonRPCReq.ID,
						}
						w.WriteHeader(http.StatusOK)
						json.NewEncoder(w).Encode(jsonRPCError)
						return
					}
					
					// Validate token if MCP_AUTH_TOKEN is configured
					if h.config.MCPAuthToken != "" && providedToken != h.config.MCPAuthToken {
						h.srv.Logger.Debug("MCP authentication failed - invalid token", 
							"tool", params.Name,
							"hasAuthHeader", authHeader != "",
							"hasMCPToken", mcpToken != "")
						jsonRPCError := map[string]interface{}{
							"jsonrpc": "2.0",
							"error": map[string]interface{}{
								"code":    -32603,
								"message": "Invalid or expired credentials",
								"data": map[string]interface{}{
									"code": "AUTH_INVALID",
								},
							},
							"id": jsonRPCReq.ID,
						}
						w.WriteHeader(http.StatusOK)
						json.NewEncoder(w).Encode(jsonRPCError)
						return
					}
					
					// If MCP_AUTH_TOKEN is not set, accept any non-empty token (for development)
					if h.config.MCPAuthToken == "" {
						h.srv.Logger.Warn("MCP_AUTH_TOKEN not configured - accepting any token for authenticated operations")
					}
				}

				// Log the tool being called
				h.srv.Logger.Debug("Processing MCP tool call", 
					"tool", params.Name, 
					"isAuthRequired", h.isAuthRequired(params.Name),
					"hasToken", h.config.MCPAuthToken != "")
				
				// Determine authentication status
				// For public tools, we still need to know if a valid token was provided
				// Extract token from headers
				authHeader := r.Header.Get("Authorization")
				mcpToken := r.Header.Get("X-MCP-Token")
				var providedTokenForContext string
				if strings.HasPrefix(authHeader, "Bearer ") {
					providedTokenForContext = strings.TrimPrefix(authHeader, "Bearer ")
				} else if mcpToken != "" {
					providedTokenForContext = mcpToken
				}
				
				// Add authentication status to context
				var toolCtx context.Context
				isAuthenticated := false
				
				// Check if token is an API key
				if providedTokenForContext != "" {
					// First try as API key
					if principal, ok := h.apiKeyStore.GetPrincipal(providedTokenForContext); ok {
						// Valid API key - add principal to context
						toolCtx = context.WithValue(r.Context(), auth.ContextKeyPrincipal, principal)
						toolCtx = context.WithValue(toolCtx, "mcp_authenticated", true)
						isAuthenticated = true
						h.srv.Logger.Debug("MCP request authenticated with API key", 
							"tool", params.Name,
							"principalID", principal.PrincipalID)
					} else if h.config.MCPAuthToken != "" && providedTokenForContext == h.config.MCPAuthToken {
						// Valid MCP token
						toolCtx = context.WithValue(r.Context(), "mcp_authenticated", true)
						isAuthenticated = true
					} else {
						// Invalid token
						toolCtx = context.WithValue(r.Context(), "mcp_authenticated", false)
					}
				} else {
					// No token provided
					toolCtx = context.WithValue(r.Context(), "mcp_authenticated", false)
				}
				
				// Log authentication result
				if isAuthenticated && !h.isAuthRequired(params.Name) {
					h.srv.Logger.Debug("MCP tool call authenticated for public endpoint", 
						"tool", params.Name,
						"authenticated", isAuthenticated)
				}
				
				// Process the tool call and get both message and data
				message, data, err := h.processToolCallWithMessage(toolCtx, params.Name, params.Arguments)
				if err != nil {
					jsonRPCError := map[string]interface{}{
						"jsonrpc": "2.0",
						"error": map[string]interface{}{
							"code":    -32603,
							"message": err.Error(),
						},
						"id": jsonRPCReq.ID,
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(jsonRPCError)
					return
				}

				// Parse the data JSON
				var parsedData interface{}
				if err := json.Unmarshal([]byte(data), &parsedData); err != nil {
					h.srv.Logger.Error("Failed to parse tool result", "error", err)
					parsedData = data
				}

				// Build response with message and data fields
				response := map[string]interface{}{
					"jsonrpc": "2.0",
					"result":  parsedData,
					"id":      jsonRPCReq.ID,
				}

				// If we have a message, add it to the result
				if message != "" {
					if resultMap, ok := parsedData.(map[string]interface{}); ok {
						resultMap["message"] = message
					}
				}

				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
				return

			default:
				// Method not found
				jsonRPCError := map[string]interface{}{
					"jsonrpc": "2.0",
					"error": map[string]interface{}{
						"code":    -32601,
						"message": "Method not found",
					},
					"id": jsonRPCReq.ID,
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(jsonRPCError)
				return
			}
		}

		// If not JSON-RPC, return an error
		h.sendErrorResponse(w, "Invalid request format", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	// For any other method, return method not allowed
	h.sendErrorResponse(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
}

// isAuthRequired checks if a tool requires authentication according to AdCP spec
func (h *HTTPHandler) isAuthRequired(toolName string) bool {
	// Public operations that don't require authentication
	publicTools := map[string]bool{
		"list_authorized_properties":      true,
		"adcp.list_authorized_properties": true,
		"list_creative_formats":           true,
		"adcp.list_creative_formats":      true,
		"get_products":                    true, // Limited results without auth
		"adcp.get_products":               true,
		"tools/list":                      true, // Allow listing tools
	}
	
	return !publicTools[toolName]
}

// processToolCall handles individual tool calls
func (h *HTTPHandler) processToolCallWithMessage(ctx context.Context, toolName string, arguments json.RawMessage) (string, string, error) {
	h.srv.Logger.Debug("Processing tool call", "tool", toolName, "arguments", string(arguments))

	// Handle both prefixed and unprefixed tool names for compatibility
	switch toolName {
	case "adcp.list_authorized_properties", "list_authorized_properties":
		// Parse optional filter parameters
		var params struct {
			PublisherDomains []string `json:"publisher_domains,omitempty"`
		}
		if len(arguments) > 0 && string(arguments) != "{}" {
			if err := json.Unmarshal(arguments, &params); err != nil {
				h.srv.Logger.Debug("Failed to parse filter params, proceeding without filter", "error", err)
			}
		}

		// Apply filter if provided
		response := h.srv.AuthProperties
		if len(params.PublisherDomains) > 0 {
			// Filter to only requested domains
			filteredDomains := []string{}
			for _, domain := range response.PublisherDomains {
				for _, filterDomain := range params.PublisherDomains {
					if domain == filterDomain {
						filteredDomains = append(filteredDomains, domain)
						break
					}
				}
			}
			response.PublisherDomains = filteredDomains
		}

		// Build message
		message := fmt.Sprintf("Authorized to represent %d publisher(s): %s",
			len(response.PublisherDomains),
			strings.Join(response.PublisherDomains, ", "))

		if len(params.PublisherDomains) > 0 {
			message += fmt.Sprintf(" (filtered from %d total)", len(h.srv.AuthProperties.PublisherDomains))
		}

		// Add message to response
		responseWithMessage := map[string]interface{}{
			"message":               message,
			"publisher_domains":     response.PublisherDomains,
			"primary_channels":      response.PrimaryChannels,
			"primary_countries":     response.PrimaryCountries,
			"portfolio_description": response.PortfolioDescription,
			"last_updated":          response.LastUpdated,
		}

		// Return the response with message
		result, err := json.Marshal(responseWithMessage)
		if err != nil {
			return "", "", err
		}
		h.srv.Logger.Debug("Returning authorized properties", "message", message, "domains", response.PublisherDomains)
		return message, string(result), nil

	case "adcp.get_products", "get_products":
		// Check if request is authenticated
		isAuthenticated := false
		if auth, ok := ctx.Value("mcp_authenticated").(bool); ok {
			isAuthenticated = auth
		}
		
		h.srv.Logger.Debug("get_products called", "isAuthenticated", isAuthenticated)
		
		// Parse optional filters
		var params struct {
			Brief   string `json:"brief,omitempty"`
			Filters struct {
				DeliveryType        string   `json:"delivery_type,omitempty"`
				IsFixedPrice        *bool    `json:"is_fixed_price,omitempty"`
				FormatTypes         []string `json:"format_types,omitempty"`
				StandardFormatsOnly bool     `json:"standard_formats_only,omitempty"`
				MinExposures        int      `json:"min_exposures,omitempty"`
			} `json:"filters,omitempty"`
			BrandManifest interface{} `json:"brand_manifest,omitempty"`
		}

		if len(arguments) > 0 && string(arguments) != "{}" && string(arguments) != "null" {
			if err := json.Unmarshal(arguments, &params); err != nil {
				h.srv.Logger.Debug("Failed to parse product filters, proceeding without filter", "error", err)
			}
		}

		// Convert products to AdCP format
		adcpProducts := make([]map[string]interface{}, 0, len(h.srv.Products))

		for _, product := range h.srv.Products {
			// Apply filters if provided
			if params.Filters.DeliveryType != "" && product.DeliveryType != params.Filters.DeliveryType {
				continue
			}

			// Convert properties to AdCP format
			properties := []map[string]interface{}{}
			for _, prop := range product.Properties {
				properties = append(properties, map[string]interface{}{
					"property_type": "website",
					"name":          "FOMO TV",
					"identifiers": []map[string]interface{}{
						{
							"type":  "domain",
							"value": "adte.com",
						},
					},
					"tags":             []string{"premium_content", "video_content"},
					"publisher_domain": prop.PublisherDomain,
				})
			}

			// Convert format IDs
			formatIDs := []map[string]interface{}{}
			for _, sf := range product.SupportedFormats {
				formatIDs = append(formatIDs, map[string]interface{}{
					"agent_url": sf.FormatID.AgentURL,
					"id":        sf.FormatID.ID,
				})
			}

			// Build product object
			adcpProduct := map[string]interface{}{
				"product_id":     product.ProductID,
				"name":           product.Name,
				"description":    getProductDescription(product),
				"properties":     properties,
				"format_ids":     formatIDs,
				"delivery_type":  product.DeliveryType,
				"is_fixed_price": true,
				"currency":       "USD",
				"min_spend":      1000.0,
			}

			// Add pricing only if authenticated (per AdCP spec)
			if isAuthenticated && len(product.PricingOptions) > 0 {
				adcpProduct["cpm"] = product.PricingOptions[0].Rate

				pricingOptions := []map[string]interface{}{}
				for _, po := range product.PricingOptions {
					pricingOptions = append(pricingOptions, map[string]interface{}{
						"pricing_option_id": po.PricingOptionID,
						"model":             po.Model,
						"currency":          po.Currency,
						"is_fixed":          po.IsFixed,
						"rate":              po.Rate,
					})
				}
				adcpProduct["pricing_options"] = pricingOptions
			} else if !isAuthenticated {
				// Remove pricing info for unauthenticated requests
				delete(adcpProduct, "min_spend")
				delete(adcpProduct, "currency")
			}

			if len(product.AvailableMetrics) > 0 {
				adcpProduct["available_metrics"] = product.AvailableMetrics
			}

			// Add brief relevance if provided
			if params.Brief != "" {
				adcpProduct["is_custom"] = false
				adcpProduct["brief_relevance"] = getBriefRelevance(product, params.Brief)
			}

			adcpProducts = append(adcpProducts, adcpProduct)
		}

		// Build response
		response := map[string]interface{}{
			"products": adcpProducts,
		}

		// Generate message
		message := ""
		if !isAuthenticated {
			message = fmt.Sprintf("Found %d products (limited catalog - authenticate for full access including pricing)", len(adcpProducts))
			response["limited_results"] = true
			response["auth_required_for"] = []string{"pricing", "custom_products", "full_catalog"}
		} else {
			message = fmt.Sprintf("Found %d products available for purchase", len(adcpProducts))
			if params.Brief != "" {
				message = fmt.Sprintf("Found %d products matching your requirements for %s",
					len(adcpProducts), params.Brief)
			}
		}

		result, err := json.Marshal(response)
		if err != nil {
			return "", "", err
		}

		h.srv.Logger.Debug("Returning products", "message", message, "count", len(adcpProducts))
		return message, string(result), nil

	case "adcp.list_creative_formats", "list_creative_formats":
		// Parse optional filters
		var params struct {
			FormatIDs    []api.FormatID `json:"format_ids,omitempty"`
			Type         string         `json:"type,omitempty"`
			AssetTypes   []string       `json:"asset_types,omitempty"`
			MaxWidth     *int           `json:"max_width,omitempty"`
			MaxHeight    *int           `json:"max_height,omitempty"`
			MinWidth     *int           `json:"min_width,omitempty"`
			MinHeight    *int           `json:"min_height,omitempty"`
			IsResponsive *bool          `json:"is_responsive,omitempty"`
			NameSearch   string         `json:"name_search,omitempty"`
		}

		if len(arguments) > 0 && string(arguments) != "{}" && string(arguments) != "null" {
			if err := json.Unmarshal(arguments, &params); err != nil {
				h.srv.Logger.Debug("Failed to parse format filters", "error", err)
			}
		}

		// Define the formats we support
		creativeAgentURL := "https://creative.adcontextprotocol.org"

		allFormats := []map[string]interface{}{
			{
				"format_id": map[string]interface{}{
					"agent_url": creativeAgentURL,
					"id":        "video_30s_hosted",
				},
				"name": "30-Second Hosted Video",
				"type": "video",
				"requirements": map[string]interface{}{
					"duration":         "30s",
					"aspect_ratio":     "16:9",
					"file_types":       []string{"mp4", "webm"},
					"max_file_size_mb": 50,
					"resolution":       []string{"1920x1080", "1280x720"},
				},
				"assets_required": []map[string]interface{}{
					{
						"asset_id":   "video_file",
						"asset_type": "video",
						"asset_role": "hero_video",
						"required":   true,
						"width":      1920,
						"height":     1080,
						"requirements": map[string]interface{}{
							"duration":         "30s",
							"format":           "MP4 H.264",
							"resolution":       []string{"1920x1080", "1280x720"},
							"max_file_size_mb": 50,
						},
					},
				},
			},
			{
				"format_id": map[string]interface{}{
					"agent_url": creativeAgentURL,
					"id":        "video_15s_hosted",
				},
				"name": "15-Second Hosted Video",
				"type": "video",
				"requirements": map[string]interface{}{
					"duration":         "15s",
					"aspect_ratio":     "16:9",
					"file_types":       []string{"mp4", "webm"},
					"max_file_size_mb": 30,
					"resolution":       []string{"1920x1080", "1280x720"},
				},
				"assets_required": []map[string]interface{}{
					{
						"asset_id":   "video_file",
						"asset_type": "video",
						"asset_role": "hero_video",
						"required":   true,
						"width":      1920,
						"height":     1080,
						"requirements": map[string]interface{}{
							"duration":         "15s",
							"format":           "MP4 H.264",
							"resolution":       []string{"1920x1080", "1280x720"},
							"max_file_size_mb": 30,
						},
					},
				},
			},
			{
				"format_id": map[string]interface{}{
					"agent_url": creativeAgentURL,
					"id":        "display_300x250",
				},
				"name":       "Medium Rectangle Banner",
				"type":       "display",
				"dimensions": "300x250",
				"requirements": map[string]interface{}{
					"width":            300,
					"height":           250,
					"file_types":       []string{"jpg", "png", "gif"},
					"max_file_size_kb": 200,
				},
				"assets_required": []map[string]interface{}{
					{
						"asset_id":           "banner_image",
						"asset_type":         "image",
						"asset_role":         "hero_image",
						"required":           true,
						"width":              300,
						"height":             250,
						"acceptable_formats": []string{"jpg", "png", "gif"},
						"max_file_size_kb":   200,
					},
				},
			},
		}

		// Apply filters (simplified version for MCP)
		filteredFormats := allFormats

		if params.Type != "" {
			filtered := []map[string]interface{}{}
			for _, format := range filteredFormats {
				if format["type"] == params.Type {
					filtered = append(filtered, format)
				}
			}
			filteredFormats = filtered
		}

		// Build response
		resp := map[string]interface{}{
			"formats": filteredFormats,
			"creative_agents": []map[string]interface{}{
				{
					"agent_url":    creativeAgentURL,
					"agent_name":   "AdCP Reference Creative Agent",
					"capabilities": []string{"validation", "assembly", "preview"},
				},
			},
		}

		result, err := json.Marshal(resp)
		if err != nil {
			return "", "", err
		}

		message := fmt.Sprintf("Found %d creative formats supported by this sales agent", len(filteredFormats))
		if params.Type != "" {
			message = fmt.Sprintf("Found %d %s formats", len(filteredFormats), params.Type)
		}

		h.srv.Logger.Debug("Returning creative formats", "message", message, "count", len(filteredFormats))
		return message, string(result), nil

	case "adcp.create_media_buy", "create_media_buy":
		var input api.CreateMediaBuyRequest
		if err := json.Unmarshal(arguments, &input); err != nil {
			return "", "", err
		}

		resp, err := h.srv.CreateMediaBuy(ctx, server.CreateMediaBuyParams{
			Request: &input,
		})
		if err != nil {
			return "", "", err
		}

		result, err := json.Marshal(resp)
		if err != nil {
			return "", "", err
		}
		h.srv.Logger.Debug("Created media buy", "result", string(result))
		return resp.Message, string(result), nil

	case "adcp.update_media_buy", "update_media_buy":
		var input struct {
			MediaBuyID string  `json:"media_buy_id"`
			Status     *string `json:"status,omitempty"`
			EndTime    *string `json:"end_time,omitempty"`
		}
		if err := json.Unmarshal(arguments, &input); err != nil {
			return "", "", err
		}

		resp, err := h.srv.UpdateMediaBuy(ctx, server.UpdateMediaBuyParams{
			MediaBuyID: input.MediaBuyID,
			Status:     input.Status,
			EndTime:    input.EndTime,
		})
		if err != nil {
			return "", "", err
		}

		result, err := json.Marshal(resp)
		if err != nil {
			return "", "", err
		}
		message := resp["message"]
		h.srv.Logger.Debug("Updated media buy", "message", message)
		return message, string(result), nil

	case "list_creatives", "adcp.list_creatives":
		var params struct {
			Filters struct {
				Status   string   `json:"status,omitempty"`
				Formats  []string `json:"formats,omitempty"`
				Statuses []string `json:"statuses,omitempty"`
			} `json:"filters,omitempty"`
			Pagination struct {
				Limit  int `json:"limit,omitempty"`
				Offset int `json:"offset,omitempty"`
			} `json:"pagination,omitempty"`
			Sort struct {
				Field     string `json:"field,omitempty"`
				Direction string `json:"direction,omitempty"`
			} `json:"sort,omitempty"`
			IncludeAssignments bool `json:"include_assignments,omitempty"`
			IncludePerformance bool `json:"include_performance,omitempty"`
		}

		if len(arguments) > 0 && string(arguments) != "{}" && string(arguments) != "null" {
			if err := json.Unmarshal(arguments, &params); err != nil {
				h.srv.Logger.Debug("Failed to parse creative filters", "error", err)
			}
		}

		// Default pagination
		limit := 50
		if params.Pagination.Limit > 0 && params.Pagination.Limit <= 100 {
			limit = params.Pagination.Limit
		}

		// Build response - empty creative library for sales agent
		response := map[string]interface{}{
			"message":    "No creatives found - this sales agent does not manage creatives. Please use a creative agent.",
			"context_id": fmt.Sprintf("ctx_list_%d", time.Now().Unix()),
			"query_summary": map[string]interface{}{
				"total_matching":  0,
				"returned":        0,
				"filters_applied": []string{},
			},
			"pagination": map[string]interface{}{
				"limit":        limit,
				"offset":       params.Pagination.Offset,
				"has_more":     false,
				"total_pages":  0,
				"current_page": 0,
			},
			"creatives":          []interface{}{},
			"format_summary":     map[string]int{},
			"status_summary":     map[string]int{},
			"creative_agent_url": "https://creative.adcontextprotocol.org",
		}

		result, err := json.Marshal(response)
		if err != nil {
			return "", "", err
		}

		message := "This sales agent does not manage creatives. For creative management, please use a creative agent at https://creative.adcontextprotocol.org"
		h.srv.Logger.Debug("Returning empty creative list", "message", message)
		return message, string(result), nil

	default:
		return "", "", fmt.Errorf("unknown tool: %s", toolName)
	}
}

// Keep the old processToolCall for backward compatibility
func (h *HTTPHandler) processToolCall(ctx context.Context, toolName string, arguments json.RawMessage) (string, error) {
	_, data, err := h.processToolCallWithMessage(ctx, toolName, arguments)
	return data, err
}

// Add root discovery handler
func (h *HTTPHandler) RootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-AdCP-Agent", "ADTE Sales Agent")
	w.Header().Set("X-MCP-Enabled", "true")

	discovery := map[string]interface{}{
		"agent": map[string]string{
			"name":    "ADTE Sales Agent",
			"version": "0.1.0",
			"type":    "sales",
		},
		"protocols": []string{"http", "mcp"},
		"mcp": map[string]string{
			"endpoint": "/mcp",
			"version":  "1.0",
		},
		"http_endpoints": map[string]string{
			"list_authorized_properties": "/list_authorized_properties",
			"get_products":               "/get_products",
			"list_creative_formats":      "/list_creative_formats",
			"create_media_buy":           "/create_media_buy",
			"update_media_buy":           "/update_media_buy",
		},
		"capabilities": []string{
			"media_buy_creation",
			"media_buy_update",
			"product_discovery",
			"property_discovery",
			"creative_format_discovery",
		},
		"adcp_version": "1.0",
	}

	if err := json.NewEncoder(w).Encode(discovery); err != nil {
		h.srv.Logger.Error("encode discovery failed", "error", err)
	}
}
