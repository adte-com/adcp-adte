package main

import (
	"context"
	"database/sql"
	"strings"

	"log/slog"
	"net/http"
	"os"
	"time"

	internalDB "adte.com/adte/sales-agent/internal/db"

	"adte.com/adte/sales-agent/internal/api"
	"adte.com/adte/sales-agent/internal/auth"
	"adte.com/adte/sales-agent/internal/config"
	"adte.com/adte/sales-agent/internal/gen/db"
	httpHandlers "adte.com/adte/sales-agent/internal/http"
	mcpHandlers "adte.com/adte/sales-agent/internal/mcp"
	"adte.com/adte/sales-agent/internal/middleware"
	"adte.com/adte/sales-agent/internal/server"
	mcpSdk "github.com/modelcontextprotocol/go-sdk/mcp"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	config, err := config.NewConfig()
	if err != nil {
		logs := slog.New(slog.NewTextHandler(os.Stdout, nil))
		logs.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
	// slog.SetDefault(logger)

	logLevel := slog.LevelInfo
	switch strings.ToLower(config.Log.Level) {
	case "trace":
		logLevel = slog.LevelDebug - 4
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     logLevel,
	}))
	slog.SetDefault(logger)

	// dsn := os.Getenv("DATABASE_DSN")
	// if dsn == "" {
	// 	dsn = "file:adte_sales_agent.db?_busy_timeout=5000&_foreign_keys=on"
	// }

	// Initialize an in-memory SQLite database
	dbConn, err := sql.Open("sqlite3", ":memory:") // sql.Open("sqlite3", dsn)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer dbConn.Close()

	dbConn.SetMaxOpenConns(1)
	dbConn.SetMaxIdleConns(1)
	dbConn.SetConnMaxLifetime(0)

	// Enable foreign key support in SQLite (for referential integrity)
	if _, err := dbConn.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		logger.Error("failed to enable foreign keys", "error", err)
		os.Exit(1)
	}

	// Create the necessary tables (media_buys and packages) if not already present
	if _, err := dbConn.Exec(internalDB.SchemaSQL); err != nil {
		logger.Error("failed to apply schema", "error", err)
		os.Exit(1)
	}

	// Initialize server with shared business logic
	srv := &server.Server{
		DB:      dbConn,
		Queries: db.New(dbConn),
		Logger:  logger,
		AuthProperties: api.AuthorizedPropertiesResponse{
			PublisherDomains:     []string{"adte.com"},
			PrimaryChannels:      []string{"ctv", "web"},
			PrimaryCountries:     []string{"US"},
			PortfolioDescription: "Premium CTV and web video inventory specialist representing ADTE properties including FOMO TV across connected TV, mobile, and web platforms.",
			LastUpdated:          time.Now().UTC().Format(time.RFC3339),
		},
		InternalProperties: []api.AuthorizedPropertyGroup{
			{
				PublisherDomain: "adte.com",
				PropertyIDs:     []string{"fomo_tv_ctv", "fomo_tv_mobile", "fomo_tv_web"},
			},
		},

		Products: initializeProducts(),
	}

	// Start MCP server in background
	if config.MCP.Enabled {
		startMCPServer(srv, logger, config.MCP.Transport)
	}

	// Start HTTP server
	startHTTPServer(srv, logger, config)
}

func initializeProducts() []api.Product {
	// Define the available products (inventory offerings) – e.g., 30s and 15s CTV pre-roll, and a web pre-roll with companion ad.
	creativeAgentURL := "https://creative.adcontextprotocol.org" // base URL of reference Creative agent for format IDs
	return []api.Product{
		{
			ProductID:    "ctv_premium_preroll_30s",
			Name:         "Premium CTV Pre-Roll (30s, US)",
			DeliveryType: "guaranteed",
			Properties: []api.ProductPropertyRef{
				{PublisherDomain: "adte.com", PropertyIDs: []string{"fomo_tv_ctv"}},
			},
			PricingOptions: []api.PricingOption{
				{PricingOptionID: "cpm_fixed_usd", Model: "cpm", Currency: "USD", IsFixed: true, Rate: 22.0},
			},
			SupportedFormats: []api.SupportedFormat{
				{FormatID: api.FormatID{AgentURL: creativeAgentURL, ID: "video_30s_hosted"}},
			},
			AvailableMetrics: []string{"impressions", "spend", "video_starts", "video_completions", "completion_rate"},
		},
		{
			ProductID:    "ctv_premium_preroll_15s",
			Name:         "Premium CTV Pre-Roll (15s, US)",
			DeliveryType: "guaranteed",
			Properties: []api.ProductPropertyRef{
				{PublisherDomain: "adte.com", PropertyIDs: []string{"fomo_tv_ctv"}},
			},
			PricingOptions: []api.PricingOption{
				{PricingOptionID: "cpm_fixed_usd", Model: "cpm", Currency: "USD", IsFixed: true, Rate: 18.0},
			},
			SupportedFormats: []api.SupportedFormat{
				{FormatID: api.FormatID{AgentURL: creativeAgentURL, ID: "video_15s_hosted"}},
			},
			AvailableMetrics: []string{"impressions", "spend", "video_starts", "video_completions", "completion_rate"},
		},
		{
			ProductID:    "web_premium_preroll_30s_companion",
			Name:         "Premium Web Pre-Roll + Companion (30s, US)",
			DeliveryType: "guaranteed",
			Properties: []api.ProductPropertyRef{
				{PublisherDomain: "adte.com", PropertyIDs: []string{"fomo_tv_web"}},
			},
			PricingOptions: []api.PricingOption{
				{PricingOptionID: "cpm_fixed_usd", Model: "cpm", Currency: "USD", IsFixed: true, Rate: 25.0},
			},
			SupportedFormats: []api.SupportedFormat{
				{FormatID: api.FormatID{AgentURL: creativeAgentURL, ID: "video_30s_hosted"}},
				{FormatID: api.FormatID{AgentURL: creativeAgentURL, ID: "display_300x250"}},
			},
			AvailableMetrics: []string{"impressions", "spend", "video_starts", "video_completions", "completion_rate"},
		},
	}
}

func startMCPServer(srv *server.Server, logger *slog.Logger, transport string) {
	// Create MCP server
	impl := &mcpSdk.Implementation{
		Name:    "Adte Sales Agent",
		Version: "0.1.0",
	}
	mcpServer := mcpSdk.NewServer(impl, nil)

	// Create and register MCP handlers
	mcpHandler := mcpHandlers.NewMCPHandler(srv)
	mcpHandler.RegisterTools(mcpServer)

	// Start MCP server in goroutine
	go func() {
		ctx := context.Background()
		logger.Info("Starting MCP server", "transport", transport)

		var mcpTransport mcpSdk.Transport
		switch transport {
		case "stdio":
			mcpTransport = &mcpSdk.StdioTransport{}
		default:
			logger.Error("unsupported MCP transport", "transport", transport)
			return
		}

		if err := mcpServer.Run(ctx, mcpTransport); err != nil {
			logger.Error("MCP server error", "error", err)
		}
	}()
}

func startHTTPServer(srv *server.Server, logger *slog.Logger, config *config.Config) {
	// Initialize API key store with test keys
	apiKeyStore := auth.InitializeDefaultAPIKeys()

	// Add configured API keys from environment if available
	if apiKey := os.Getenv("ADCP_API_KEY"); apiKey != "" {
		apiKeyStore.AddKey(apiKey, &auth.Principal{
			PrincipalID: "principal_env",
			Permissions: map[string][]auth.Permission{
				"products":   {auth.PermissionRead},
				"media_buys": {auth.PermissionRead, auth.PermissionWrite},
				"creatives":  {auth.PermissionRead, auth.PermissionWrite},
				"reports":    {auth.PermissionRead, auth.PermissionWrite},
			},
		})
	}

	// Create HTTP handlers
	httpHandler := httpHandlers.NewHTTPHandler(srv, config, apiKeyStore)

	// Setup routes
	// mux := http.NewServeMux()
	// mux.HandleFunc("/", httpHandler.RootHandler)    // Add root discovery
	// mux.HandleFunc("/mcp", httpHandler.MCPHandler)  // Add MCP endpoint
	// mux.HandleFunc("/mcp/", httpHandler.MCPHandler) // Handle with trailing slash too

	// mux.HandleFunc("/list_authorized_properties", httpHandler.ListAuthorizedPropertiesHandler)
	// mux.HandleFunc("/get_products", httpHandler.GetProductsHandler)
	// mux.HandleFunc("/list_creative_formats", httpHandler.ListCreativeFormatsHandler)
	// mux.HandleFunc("/create_media_buy", httpHandler.CreateMediaBuyHandler)
	// mux.HandleFunc("/update_media_buy", httpHandler.UpdateMediaBuyHandler)
	// mux.HandleFunc("/health", httpHandler.HealthHandler)

	// Create a debug wrapper to log all requests
	debugMux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("incoming request", "method", r.Method, "path", r.URL.Path)

		// Setup routes inline for debugging
		switch r.URL.Path {
		case "/":
			httpHandler.RootHandler(w, r)
		case "/mcp", "/mcp/":
			logger.Debug("routing to MCPHandler")
			httpHandler.MCPHandler(w, r)
		case "/list_authorized_properties":
			httpHandler.ListAuthorizedPropertiesHandler(w, r)
		case "/get_products":
			httpHandler.GetProductsHandler(w, r)
		case "/list_creative_formats":
			httpHandler.ListCreativeFormatsHandler(w, r)
		case "/create_media_buy":
			httpHandler.CreateMediaBuyHandler(w, r)
		case "/update_media_buy":
			httpHandler.UpdateMediaBuyHandler(w, r)
		case "/health":
			httpHandler.HealthHandler(w, r)
		default:
			logger.Debug("no route matched", "path", r.URL.Path)
			http.NotFound(w, r)
		}
	})

	// Setup middleware
	limiterStore := middleware.NewRateLimiterStore(10, 20, 10*time.Minute)

	// Define paths that don't require authentication (public operations per AdCP spec)
	// - list_authorized_properties: Browse available properties (public)
	// - list_creative_formats: Discover format support (public)
	// - get_products: Limited results without auth (handled in handler)
	publicPaths := []string{
		"/",
		"/health",
		"/mcp",
		"/list_authorized_properties",
		"/list_creative_formats",
		"/get_products", // Will return limited results without auth
	}

	// Create unified authentication middleware (supports JWT and API Key)
	// Public operations don't require auth, but still extract auth context if present
	authMiddleware := middleware.OptionalAuthMiddleware(
		middleware.UnifiedAuthMiddleware(config.JwtSecretKey, apiKeyStore, logger),
		publicPaths,
		logger,
	)

	handler := middleware.LoggingMiddleware(logger)(
		middleware.CORSMiddleware(
			authMiddleware(
				middleware.RateLimitMiddleware(limiterStore)(
					middleware.LimitBodySize(1 << 20)(debugMux),
				),
			),
		),
	)

	// Start the HTTP server
	logger.Info("Sales Agent service is running",
		"address", config.HttpAddress,
		"mcp_endpoint", "/mcp",
		"mcp_enabled", os.Getenv("MCP_ENABLED"))

	if err := http.ListenAndServe(config.HttpAddress, handler); err != nil {
		logger.Error("server shutdown", "error", err)
	}
}
