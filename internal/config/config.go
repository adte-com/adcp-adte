package config

import (
	"fmt"
	"os"
	"strings"

	"adte.com/adte/sales-agent/internal/tool"
)

type Config struct {
	GrpcAddress       string
	GrpcApiKey        string
	GrpcApiReflection bool
	HttpAddress       string
	HttpApiKey        string
	OpenTelemetry     bool
	JwtSecretKey      string
	DB                *DbConfig
	Log               *LogConfig
	MCP               *MCPConfig
}

type DbConfig struct {
	Uri      string
	Password string
}

type LogConfig struct {
	Level string
	File  string
	Human bool
}

type MCPConfig struct {
	Transport string
	Enabled   bool
}

func NewConfig() (*Config, error) {

	// Server configuration
	grpcAddress := os.Getenv("GRPC_ADDRESS")
	if grpcAddress == "" {
		return nil, fmt.Errorf("missing environment variable: GRPC_ADDRESS")
	}

	grpcApiKey := os.Getenv("GRPC_API_KEY")
	_, grpcApiReflection := os.LookupEnv("GRPC_API_REFLECTION")

	httpAddress := os.Getenv("HTTP_ADDRESS")
	if httpAddress == "" {
		return nil, fmt.Errorf("missing environment variable: HTTP_ADDRESS")
	}
	httpApiKey := os.Getenv("HTTP_API_KEY")

	jwtSecretKey := os.Getenv("JWT_SECRET_KEY")
	if jwtSecretKey == "" {
		return nil, fmt.Errorf("missing environment variable: JWT_SECRET_KEY")
	}

	_, opentelemetry := os.LookupEnv("opentelemetry")

	// Database configuration
	dbUri := tool.GetFileValue("DB_URI")
	if dbUri == "" {
		return nil, fmt.Errorf("missing environment variable: DB_URI")
	}
	dbPassword := tool.GetFileValue("DB_PASSWORD")
	if dbPassword == "" {
		return nil, fmt.Errorf("missing environment variable: DB_PASSWORD")
	}

	// Logging configuration
	logLevel := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	_, human := os.LookupEnv("HUMAN_LOGGING")
	logFile := os.Getenv("LOG_FILE")

	// MCP configuration
	mcpTransport := os.Getenv("MCP_TRANSPORT")
	mcpEnabled := mcpTransport != ""

	return &Config{
		GrpcAddress:       grpcAddress,
		GrpcApiKey:        grpcApiKey,
		GrpcApiReflection: grpcApiReflection,
		HttpAddress:       httpAddress,
		HttpApiKey:        httpApiKey,
		JwtSecretKey:      jwtSecretKey,
		OpenTelemetry:     opentelemetry,
		Log: &LogConfig{
			Level: logLevel,
			File:  logFile,
			Human: human,
		},
		DB: &DbConfig{
			Uri:      dbUri,
			Password: dbPassword,
		},
		MCP: &MCPConfig{
			Transport: mcpTransport,
			Enabled:   mcpEnabled,
		},
	}, nil
}
