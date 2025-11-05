package api

type FormatID struct {
	AgentURL string `json:"agent_url"`
	ID       string `json:"id"`
}

type ProductPropertyRef struct {
	PublisherDomain string   `json:"publisher_domain,omitempty"`
	PropertyIDs     []string `json:"property_ids,omitempty"`
	PropertyTags    []string `json:"property_tags,omitempty"`
}

type PricingOption struct {
	PricingOptionID string  `json:"pricing_option_id"`
	Model           string  `json:"model"`
	Currency        string  `json:"currency"`
	IsFixed         bool    `json:"is_fixed"`
	Rate            float64 `json:"rate"`
}

type SupportedFormat struct {
	FormatID FormatID `json:"format_id"`
}

type Product struct {
	ProductID        string               `json:"product_id"`
	Name             string               `json:"name"`
	DeliveryType     string               `json:"delivery_type"`
	Properties       []ProductPropertyRef `json:"properties"`
	PricingOptions   []PricingOption      `json:"pricing_options"`
	SupportedFormats []SupportedFormat    `json:"supported_formats"`
	AvailableMetrics []string             `json:"available_metrics"`
}

type AuthorizedPropertyGroup struct {
	PublisherDomain string   `json:"publisher_domain"`
	PropertyIDs     []string `json:"property_ids"`
}

type AuthorizedPropertiesResponse struct {
	Properties []AuthorizedPropertyGroup `json:"properties"`
}

type CreativeFormatsResponse struct {
	Formats        []CreativeFormat `json:"formats"`
	CreativeAgents []string         `json:"creative_agents"`
}

type CreativeFormat struct {
	FormatID     FormatID `json:"format_id"`
	Name         string   `json:"name,omitempty"`
	Type         string   `json:"type,omitempty"`
	Description  string   `json:"description,omitempty"`
	PreviewImage string   `json:"preview_image,omitempty"`
	ExampleURL   string   `json:"example_url,omitempty"`
}

// Request body for create_media_buy
type CreateMediaBuyRequest struct {
	BuyerRef      string               `json:"buyer_ref"`
	BrandManifest BrandManifest        `json:"brand_manifest"`
	Packages      []MediaBuyPackageReq `json:"packages"`
	StartTime     string               `json:"start_time"`
	EndTime       string               `json:"end_time"`
}

type BrandManifest struct {
	URL  string `json:"url"`
	Name string `json:"name,omitempty"`
}

type MediaBuyPackageReq struct {
	BuyerRef        string     `json:"buyer_ref"`
	ProductID       string     `json:"product_id"`
	PricingOptionID string     `json:"pricing_option_id"`
	FormatIDs       []FormatID `json:"format_ids"`
	Budget          float64    `json:"budget"`
	Pacing          string     `json:"pacing"`
}

// Response body for create_media_buy
type CreateMediaBuyResponse struct {
	MediaBuyID string   `json:"media_buy_id"`
	PackageIDs []string `json:"package_ids"`
	Message    string   `json:"message"`
}

// ErrorResponse provides a consistent error format per AdCP spec
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}
