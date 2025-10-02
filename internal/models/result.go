package models

import (
	"time"
)

// Result contains comprehensive scan results for a domain
type Result struct {
	Domain         string        `json:"domain"`
	Active         bool          `json:"active"`
	FinalURL       string        `json:"final_url,omitempty"`
	StatusCode     int           `json:"status_code,omitempty"`
	RedirectTo     string        `json:"redirect_to,omitempty"`
	Error          error         `json:"error,omitempty"`
	ResponseTime   time.Duration `json:"response_time"`
	Title          string        `json:"title,omitempty"`
	ServerInfo     ServerInfo    `json:"server_info"`
	ScreenshotPath string        `json:"screenshot_path,omitempty"`
	SecurityInfo   SecurityInfo  `json:"security_info"`
	ContentInfo    ContentInfo   `json:"content_info"`
	IPAddresses    []string      `json:"ip_addresses,omitempty"`
	LastChecked    time.Time     `json:"last_checked"`
	Technologies   []string      `json:"technologies,omitempty"`
}

// ServerInfo contains HTTP server information
type ServerInfo struct {
	Server        string            `json:"server,omitempty"`
	PoweredBy     string            `json:"powered_by,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	ResponseSize  int64             `json:"response_size,omitempty"`
	LastModified  string            `json:"last_modified,omitempty"`
	SecurityFlags []string          `json:"security_flags,omitempty"`
}

// SecurityInfo contains security-related information
type SecurityInfo struct {
	HasHTTPS        bool              `json:"has_https"`
	ValidCert       bool              `json:"valid_cert"`
	CertIssuer      string            `json:"cert_issuer,omitempty"`
	CertExpiry      time.Time         `json:"cert_expiry,omitempty"`
	SecurityHeaders map[string]string `json:"security_headers,omitempty"`
	HTTPSRedirect   bool              `json:"https_redirect"`
	HSTPEnabled     bool              `json:"hstp_enabled"`
	TLSVersion      string            `json:"tls_version,omitempty"`
}

// ContentInfo contains website content analysis
type ContentInfo struct {
	WordCount      int      `json:"word_count,omitempty"`
	HasLoginForm   bool     `json:"has_login_form"`
	LinkCount      int      `json:"link_count,omitempty"`
	ExternalLinks  int      `json:"external_links,omitempty"`
	Favicon        string   `json:"favicon,omitempty"`
	PageLanguage   string   `json:"page_language,omitempty"`
	IsParked       bool     `json:"is_parked"`
	HasAnalytics   bool     `json:"has_analytics"`
	Description    string   `json:"description,omitempty"`
	Keywords       []string `json:"keywords,omitempty"`
	SocialProfiles []string `json:"social_profiles,omitempty"`
}
