package main

import (
	"context"
	"database/sql"

	"log/slog"
	"net/http"
	"os"
	"time"

	internalDB "adte.com/adte/sales-agent/internal/db"

	"adte.com/adte/sales-agent/internal/api"
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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
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
			Properties: []api.AuthorizedPropertyGroup{
				{
					PublisherDomain: "adte.com",
					PropertyIDs:     []string{"fomo_tv_ctv", "fomo_tv_mobile", "fomo_tv_web"},
				},
			},
		},
		Products: initializeProducts(),
	}

	// Start MCP server in background
	if config.MCP.Enabled {
		startMCPServer(srv, logger, config.MCP.Transport)
	}

	// Start HTTP server
	startHTTPServer(srv, logger, config.HttpAddress)
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

func startHTTPServer(srv *server.Server, logger *slog.Logger, httpAddress string) {
	// Create HTTP handlers
	httpHandler := httpHandlers.NewHTTPHandler(srv)

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/list_authorized_properties", httpHandler.ListAuthorizedPropertiesHandler)
	mux.HandleFunc("/get_products", httpHandler.GetProductsHandler)
	mux.HandleFunc("/list_creative_formats", httpHandler.ListCreativeFormatsHandler)
	mux.HandleFunc("/create_media_buy", httpHandler.CreateMediaBuyHandler)
	mux.HandleFunc("/update_media_buy", httpHandler.UpdateMediaBuyHandler)
	mux.HandleFunc("/health", httpHandler.HealthHandler)

	// Setup middleware
	limiterStore := middleware.NewRateLimiterStore(10, 20, 10*time.Minute)
	handler := middleware.LoggingMiddleware(logger)(
		middleware.RateLimitMiddleware(limiterStore)(
			middleware.LimitBodySize(1 << 20)(
				middleware.CORSMiddleware(mux),
			),
		),
	)

	// Start the HTTP server
	logger.Info("Sales Agent service is running", "address", httpAddress)
	if err := http.ListenAndServe(httpAddress, handler); err != nil {
		logger.Error("server shutdown", "error", err)
	}
}
