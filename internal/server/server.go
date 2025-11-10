package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"adte.com/adte/sales-agent/internal/api"
	"adte.com/adte/sales-agent/internal/gen/db"
)

// Server struct holds application dependencies (DB, queries, and cached data).
type Server struct {
	DB                 *sql.DB
	Queries            *db.Queries
	Products           []api.Product
	AuthProperties     api.AuthorizedPropertiesResponse
	InternalProperties []api.AuthorizedPropertyGroup // For internal product validation
	Logger             *slog.Logger
}

// CreateMediaBuyParams encapsulates parameters for creating a media buy
type CreateMediaBuyParams struct {
	Request *api.CreateMediaBuyRequest
}

// UpdateMediaBuyParams encapsulates parameters for updating a media buy
type UpdateMediaBuyParams struct {
	MediaBuyID string
	Status     *string
	EndTime    *string
}

// ValidationError represents a validation failure
type ValidationError struct {
	Message string
	Code    string
	Field   string
}

func (e ValidationError) Error() string {
	return e.Message
}

// CreateMediaBuy creates a new media buy with packages (shared business logic)
func (s *Server) CreateMediaBuy(ctx context.Context, params CreateMediaBuyParams) (*api.CreateMediaBuyResponse, error) {
	req := params.Request

	// Validate request
	if err := s.ValidateMediaBuyRequest(req); err != nil {
		return nil, err
	}

	// Parse dates if provided
	startValue, endValue, err := s.parseDates(req.StartTime, req.EndTime)
	if err != nil {
		return nil, err
	}

	// Begin transaction
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		s.Logger.Error("DB BeginTx error", "error", err)
		return nil, fmt.Errorf("database transaction error: %w", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			s.Logger.Error("transaction rollback failed", "error", rollbackErr)
		}
	}()

	qtx := db.New(tx)

	// Insert media buy record
	mbRes, err := qtx.CreateMediaBuy(ctx, db.CreateMediaBuyParams{
		BuyerRef:  sql.NullString{String: req.BuyerRef, Valid: req.BuyerRef != ""},
		BrandUrl:  sql.NullString{String: req.BrandManifest.URL, Valid: true},
		StartTime: sql.NullString{String: startValue, Valid: startValue != ""},
		EndTime:   sql.NullString{String: endValue, Valid: endValue != ""},
	})
	if err != nil {
		s.Logger.Error("insert media_buys error", "error", err)
		return nil, fmt.Errorf("failed to create media buy: %w", err)
	}

	mbIDNum, err := mbRes.LastInsertId()
	if err != nil {
		s.Logger.Error("media buy id fetch failed", "error", err)
		return nil, fmt.Errorf("failed to get media buy ID: %w", err)
	}
	mediaBuyID := fmt.Sprintf("mb_%d", mbIDNum)

	// Insert packages
	packageIDs := []string{}
	for _, pkg := range req.Packages {
		pkgID, err := s.createPackage(ctx, qtx, mbIDNum, &pkg)
		if err != nil {
			return nil, fmt.Errorf("failed to create package: %w", err)
		}
		packageIDs = append(packageIDs, pkgID)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		s.Logger.Error("transaction commit failed", "error", err)
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &api.CreateMediaBuyResponse{
		MediaBuyID: mediaBuyID,
		PackageIDs: packageIDs,
		Message:    "Media buy created successfully",
	}, nil
}

// UpdateMediaBuy updates an existing media buy (shared business logic)
func (s *Server) UpdateMediaBuy(ctx context.Context, params UpdateMediaBuyParams) (map[string]string, error) {
	// Extract numeric ID
	var mbIDNum int64
	if _, err := fmt.Sscanf(params.MediaBuyID, "mb_%d", &mbIDNum); err != nil {
		return nil, ValidationError{Message: "Invalid media_buy_id format", Code: "INVALID_ID_FORMAT"}
	}

	// Verify media buy exists
	mb, err := s.Queries.GetMediaBuy(ctx, mbIDNum)
	if err == sql.ErrNoRows {
		return nil, ValidationError{Message: "Media buy not found", Code: "NOT_FOUND"}
	} else if err != nil {
		s.Logger.Error("get media buy error", "error", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Build update query
	updateFields := []string{}
	args := []interface{}{}

	if params.Status != nil {
		if err := s.validateStatus(*params.Status); err != nil {
			return nil, err
		}
		updateFields = append(updateFields, "status = ?")
		args = append(args, *params.Status)
	}

	if params.EndTime != nil {
		endTime, err := time.Parse(time.RFC3339, *params.EndTime)
		if err != nil {
			return nil, ValidationError{Message: "Invalid end_time format", Code: "INVALID_DATE_FORMAT"}
		}
		if mb.StartTime.Valid {
			startTime, _ := time.Parse(time.RFC3339, mb.StartTime.String)
			if endTime.Before(startTime) {
				return nil, ValidationError{Message: "end_time must be after start_time", Code: "INVALID_DATE_RANGE"}
			}
		}
		updateFields = append(updateFields, "end_time = ?")
		args = append(args, endTime.Format(time.RFC3339))
	}

	if len(updateFields) == 0 {
		return nil, ValidationError{Message: "No valid fields to update", Code: "NO_UPDATES"}
	}

	// Execute update
	updateFields = append(updateFields, "updated_at = CURRENT_TIMESTAMP")
	args = append(args, mbIDNum)

	query := fmt.Sprintf("UPDATE media_buys SET %s WHERE id = ?", strings.Join(updateFields, ", "))
	if _, err := s.DB.ExecContext(ctx, query, args...); err != nil {
		s.Logger.Error("update media buy error", "error", err)
		return nil, fmt.Errorf("failed to update media buy: %w", err)
	}

	return map[string]string{
		"message":      "Media buy updated successfully",
		"media_buy_id": params.MediaBuyID,
	}, nil
}

// Helper methods

// ValidateMediaBuyRequest validates a media buy request without creating it (used for dry-run)
func (s *Server) ValidateMediaBuyRequest(req *api.CreateMediaBuyRequest) error {
	if req.BrandManifest.URL == "" {
		return ValidationError{Message: "brand_manifest.url is required", Code: "MISSING_REQUIRED_FIELD"}
	}
	if _, err := url.ParseRequestURI(req.BrandManifest.URL); err != nil {
		return ValidationError{Message: "brand_manifest.url must be a valid absolute URL", Code: "INVALID_URL"}
	}
	if len(req.Packages) == 0 {
		return ValidationError{Message: "At least one package is required", Code: "MISSING_PACKAGES"}
	}

	// Validate each package
	for _, pkg := range req.Packages {
		if err := s.validatePackage(&pkg); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) validatePackage(pkg *api.MediaBuyPackageReq) error {
	if pkg.Budget <= 0 {
		return ValidationError{Message: "Budget must be positive", Code: "INVALID_BUDGET"}
	}

	// Validate pacing
	validPacing := map[string]bool{"even": true, "asap": true, "frontloaded": true}
	if pkg.Pacing != "" && !validPacing[pkg.Pacing] {
		return ValidationError{Message: "Invalid pacing value: " + pkg.Pacing, Code: "INVALID_PACING"}
	}

	// Check product exists
	var prod *api.Product
	for i := range s.Products {
		if s.Products[i].ProductID == pkg.ProductID {
			prod = &s.Products[i]
			break
		}
	}
	if prod == nil {
		return ValidationError{Message: "invalid product_id: " + pkg.ProductID, Code: "INVALID_PRODUCT_ID"}
	}

	// Check pricing option
	validPrice := false
	for _, po := range prod.PricingOptions {
		if po.PricingOptionID == pkg.PricingOptionID {
			validPrice = true
			break
		}
	}
	if !validPrice {
		return ValidationError{Message: "invalid pricing_option_id: " + pkg.PricingOptionID, Code: "INVALID_PRICING_OPTION_ID"}
	}

	// Check format IDs
	allowedFormats := make(map[string]struct{})
	for _, sf := range prod.SupportedFormats {
		key := sf.FormatID.AgentURL + "|" + sf.FormatID.ID
		allowedFormats[key] = struct{}{}
	}
	for _, fid := range pkg.FormatIDs {
		key := fid.AgentURL + "|" + fid.ID
		if _, ok := allowedFormats[key]; !ok {
			return ValidationError{Message: "unsupported format_id: " + fid.ID, Code: "INVALID_FORMAT_ID"}
		}
	}

	return nil
}

func (s *Server) validateStatus(status string) error {
	validStatuses := map[string]bool{"active": true, "paused": true, "cancelled": true}
	if !validStatuses[status] {
		return ValidationError{Message: "Invalid status", Code: "INVALID_STATUS"}
	}
	return nil
}

func (s *Server) parseDates(startTime, endTime string) (string, string, error) {
	var (
		startValue string
		endValue   string
	)

	if startTime != "" {
		parsed, err := time.Parse(time.RFC3339, startTime)
		if err != nil {
			return "", "", ValidationError{Message: "Invalid start_time format (use RFC3339)", Code: "INVALID_DATE_FORMAT"}
		}
		if parsed.Before(time.Now().UTC().Add(-15 * time.Minute)) {
			return "", "", ValidationError{Message: "start_time cannot be in the past", Code: "INVALID_START_TIME"}
		}
		startValue = parsed.UTC().Format(time.RFC3339)
	}

	if endTime != "" {
		parsed, err := time.Parse(time.RFC3339, endTime)
		if err != nil {
			return "", "", ValidationError{Message: "Invalid end_time format (use RFC3339)", Code: "INVALID_DATE_FORMAT"}
		}
		endValue = parsed.UTC().Format(time.RFC3339)

		if startValue != "" {
			startParsed, _ := time.Parse(time.RFC3339, startValue)
			if parsed.Before(startParsed) {
				return "", "", ValidationError{Message: "end_time must be on or after start_time", Code: "INVALID_DATE_RANGE"}
			}
		}
	}

	return startValue, endValue, nil
}

func (s *Server) createPackage(ctx context.Context, qtx *db.Queries, mediaBuyID int64, pkg *api.MediaBuyPackageReq) (string, error) {
	formatIDsJSON, err := json.Marshal(pkg.FormatIDs)
	if err != nil {
		return "", fmt.Errorf("failed to marshal format IDs: %w", err)
	}

	pkgRes, err := qtx.CreatePackage(ctx, db.CreatePackageParams{
		MediaBuyID:      mediaBuyID,
		BuyerRef:        sql.NullString{String: pkg.BuyerRef, Valid: pkg.BuyerRef != ""},
		ProductID:       sql.NullString{String: pkg.ProductID, Valid: true},
		PricingOptionID: sql.NullString{String: pkg.PricingOptionID, Valid: true},
		FormatIdsJson:   sql.NullString{String: string(formatIDsJSON), Valid: true},
		Budget:          sql.NullFloat64{Float64: pkg.Budget, Valid: true},
		Pacing:          sql.NullString{String: pkg.Pacing, Valid: pkg.Pacing != ""},
	})
	if err != nil {
		return "", err
	}

	pkgIDNum, err := pkgRes.LastInsertId()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("pkg_%d", pkgIDNum), nil
}
