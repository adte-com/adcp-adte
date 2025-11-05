package mcp

import (
	"context"
	"encoding/json"
	"errors"

	"adte.com/adte/sales-agent/internal/api"
	"adte.com/adte/sales-agent/internal/server"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPHandler wraps the server and provides MCP tool handlers
type MCPHandler struct {
	srv *server.Server
}

// NewMCPHandler creates a new MCP handler
func NewMCPHandler(srv *server.Server) *MCPHandler {
	return &MCPHandler{srv: srv}
}

type productsResponse struct {
	Products []api.Product `json:"products"`
}

type updateMediaBuyInput struct {
	MediaBuyID string  `json:"media_buy_id"`
	Status     *string `json:"status,omitempty"`
	EndTime    *string `json:"end_time,omitempty"`
}

func (h *MCPHandler) errorResult(errResp api.ErrorResponse) (*sdk.CallToolResult, error) {
	data, err := json.Marshal(errResp)
	if err != nil {
		return nil, err
	}
	return &sdk.CallToolResult{
		IsError: true,
		Content: []sdk.Content{
			&sdk.TextContent{Text: string(data)},
		},
	}, nil
}

// HandleListAuthorizedProperties returns authorized properties
func (h *MCPHandler) HandleListAuthorizedProperties(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, api.AuthorizedPropertiesResponse, error) {
	return nil, h.srv.AuthProperties, nil
}

// HandleGetProducts returns available products
func (h *MCPHandler) HandleGetProducts(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, productsResponse, error) {
	return nil, productsResponse{Products: h.srv.Products}, nil
}

// HandleListCreativeFormats returns supported creative formats
func (h *MCPHandler) HandleListCreativeFormats(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, api.CreativeFormatsResponse, error) {
	resp := api.CreativeFormatsResponse{
		Formats:        []api.CreativeFormat{},
		CreativeAgents: []string{"https://creative.adcontextprotocol.org"},
	}
	return nil, resp, nil
}

// HandleCreateMediaBuy creates a new media buy using shared business logic
func (h *MCPHandler) HandleCreateMediaBuy(ctx context.Context, _ *sdk.CallToolRequest, input api.CreateMediaBuyRequest) (*sdk.CallToolResult, api.CreateMediaBuyResponse, error) {
	resp, err := h.srv.CreateMediaBuy(ctx, server.CreateMediaBuyParams{
		Request: &input,
	})
	if err != nil {
		if valErr, ok := err.(server.ValidationError); ok {
			result, buildErr := h.errorResult(api.ErrorResponse{
				Error: valErr.Message,
				Code:  valErr.Code,
			})
			if buildErr != nil {
				return nil, api.CreateMediaBuyResponse{}, buildErr
			}
			return result, api.CreateMediaBuyResponse{}, nil
		}
		return nil, api.CreateMediaBuyResponse{}, err
	}
	if resp == nil {
		return nil, api.CreateMediaBuyResponse{}, errors.New("create media buy returned nil response")
	}
	return nil, *resp, nil
}

// HandleUpdateMediaBuy updates an existing media buy using shared business logic
func (h *MCPHandler) HandleUpdateMediaBuy(ctx context.Context, _ *sdk.CallToolRequest, input updateMediaBuyInput) (*sdk.CallToolResult, map[string]string, error) {
	var empty map[string]string

	if input.MediaBuyID == "" {
		result, err := h.errorResult(api.ErrorResponse{
			Error: "media_buy_id is required",
			Code:  "MISSING_REQUIRED_FIELD",
		})
		if err != nil {
			return nil, empty, err
		}
		return result, empty, nil
	}

	resp, err := h.srv.UpdateMediaBuy(ctx, server.UpdateMediaBuyParams{
		MediaBuyID: input.MediaBuyID,
		Status:     input.Status,
		EndTime:    input.EndTime,
	})
	if err != nil {
		if valErr, ok := err.(server.ValidationError); ok {
			result, buildErr := h.errorResult(api.ErrorResponse{
				Error: valErr.Message,
				Code:  valErr.Code,
			})
			if buildErr != nil {
				return nil, empty, buildErr
			}
			return result, empty, nil
		}
		return nil, empty, err
	}

	return nil, resp, nil
}

// RegisterTools registers all MCP tools with the server
func (h *MCPHandler) RegisterTools(mcpServer *sdk.Server) {
	sdk.AddTool(mcpServer, &sdk.Tool{
		Name:        "adcp.list_authorized_properties",
		Description: "List properties authorized for this sales agent",
	}, h.HandleListAuthorizedProperties)

	sdk.AddTool(mcpServer, &sdk.Tool{
		Name:        "adcp.get_products",
		Description: "Get available advertising products",
	}, h.HandleGetProducts)

	sdk.AddTool(mcpServer, &sdk.Tool{
		Name:        "adcp.list_creative_formats",
		Description: "List supported creative formats",
	}, h.HandleListCreativeFormats)

	sdk.AddTool(mcpServer, &sdk.Tool{
		Name:        "adcp.create_media_buy",
		Description: "Create a new media buy",
	}, h.HandleCreateMediaBuy)

	sdk.AddTool(mcpServer, &sdk.Tool{
		Name:        "adcp.update_media_buy",
		Description: "Update an existing media buy",
	}, h.HandleUpdateMediaBuy)
}
