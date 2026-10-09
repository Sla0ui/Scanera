package models

import (
	"encoding/json"
	"errors"
	"time"
)

// Result contains comprehensive scan results for a domain
type Result struct {
	Domain         string        `json:"domain"`
	Active         bool          `json:"active"`
	FinalURL       string        `json:"final_url,omitempty"`
	StatusCode     int           `json:"status_code,omitempty"`
	RedirectTo     string        `json:"redirect_to,omitempty"`
	Error          error         `json:"-"`
	ResponseTime   time.Duration `json:"response_time"`
	Title          string        `json:"title,omitempty"`
	ServerInfo     ServerInfo    `json:"server_info"`
	ScreenshotPath string        `json:"screenshot_path,omitempty"`
	SecurityInfo   SecurityInfo  `json:"security_info"`
	ContentInfo    ContentInfo   `json:"content_info"`
	IPAddresses    []string      `json:"ip_addresses,omitempty"`
	LastChecked    time.Time     `json:"last_checked"`
	Technologies   []string      `json:"technologies,omitempty"`

	// Extended asset and finding data (populated by the tier 1-2 modules).
	DNSRecords   *DNSRecords `json:"dns_records,omitempty"`
	TechDetails  []Tech      `json:"tech_details,omitempty"`
	OpenPorts    []Port      `json:"open_ports,omitempty"`
	Subdomains   []string    `json:"subdomains,omitempty"`
	Endpoints    []string    `json:"endpoints,omitempty"`
	Findings     []Finding   `json:"findings,omitempty"`
	DiscoveredBy string      `json:"discovered_by,omitempty"` // e.g. "seed", "crtsh", "bruteforce"

	// SkippedActive is set when active modules were requested but the host
	// was outside the authorized scope.
	SkippedActive bool `json:"skipped_active,omitempty"`
}

// AddFinding appends a finding with a normalized severity.
func (r *Result) AddFinding(f Finding) {
	f.Severity = f.Severity.Normalize()
	r.Findings = append(r.Findings, f)
}

// MarshalJSON renders Error as its string message. The bare error interface
// marshals to an empty object ({}), which silently dropped every failure
// reason from JSON reports; this emits a usable "error" string instead.
func (r Result) MarshalJSON() ([]byte, error) {
	type alias Result
	out := struct {
		alias
		ErrorMessage string `json:"error,omitempty"`
	}{alias: alias(r)}
	if r.Error != nil {
		out.ErrorMessage = r.Error.Error()
	}
	return json.Marshal(out)
}

// UnmarshalJSON restores Error from the "error" string MarshalJSON writes, so
// results read back from scan_results.json keep their failure reason.
func (r *Result) UnmarshalJSON(data []byte) error {
	type alias Result
	aux := struct {
		*alias
		ErrorMessage string `json:"error"`
	}{alias: (*alias)(r)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.ErrorMessage != "" {
		r.Error = errors.New(aux.ErrorMessage)
	}
	return nil
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
	CertSubject     string            `json:"cert_subject,omitempty"`
	CertDNSNames    []string          `json:"cert_dns_names,omitempty"`
	CertExpiry      time.Time         `json:"cert_expiry,omitempty"`
	CertError       string            `json:"cert_error,omitempty"`
	SecurityHeaders map[string]string `json:"security_headers,omitempty"`
	HTTPSRedirect   bool              `json:"https_redirect"`
	HSTSEnabled     bool              `json:"hsts_enabled"`
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
