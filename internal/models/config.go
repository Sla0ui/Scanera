package models

import (
	"fmt"
	"time"
)

// DefaultUserAgent identifies Scanera in requests unless overridden.
const DefaultUserAgent = "Mozilla/5.0 (compatible; Scanera/2.0; +https://github.com/Sla0ui/scanera)"

// Config holds all configuration options for scanera
type Config struct {
	SuccessStatusCodes  []int
	Timeout             time.Duration
	RetryCount          int
	MaxConcurrentChecks int
	VerifyTLS           bool
	UserAgent           string
	OutputDir           string
	LogVerbose          bool
	NoColor             bool
	Quiet               bool
	BrowserTimeout      time.Duration
	NoProgress          bool
	ForceHTTPS          bool
	SkipDNS             bool
	SkipBrowser         bool
	TakeScreenshots     bool
	ScreenshotDir       string
	DetectTech          bool
	CheckSecurity       bool
	OutputFormat        string
	AnalyzeContent      bool
	ExportPath          string
	MaxRedirects        int
	IncludeCertInfo     bool

	// Tier 1: attack-surface mapping
	EnableSubdomains  bool
	SubdomainWordlist string
	PassiveOnly       bool
	EnableDNSRecords  bool
	EnablePorts       bool
	PortSpec          string
	EnableProbes      bool
	EnableSecrets     bool
	EnableCrawl       bool
	CrawlDepth        int
	MaxPages          int
	EnableFuzz        bool
	EnableTakeover    bool
	Aggressive        bool

	// Tier 2: intelligence layer
	EnableTemplates bool
	TemplatesDir    string
	EnableVuln      bool
	SARIFPath       string

	// Tier 3: hardening and safety
	ProxyURL     string
	RateLimit    float64
	ScopeFile    string
	Authorize    bool
	AuditLogPath string
	ResumeFile   string
	Profile      string

	// Output and automation
	JSONL  bool     // stream each result to stdout as a JSON line
	FailOn Severity // exit non-zero when a finding at or above this severity exists
}

// Validate checks if the configuration is valid and returns an error if not
func (c *Config) Validate() error {
	if c.MaxConcurrentChecks < 1 {
		return fmt.Errorf("max concurrent checks must be at least 1, got %d", c.MaxConcurrentChecks)
	}
	if c.MaxConcurrentChecks > 100 {
		return fmt.Errorf("max concurrent checks cannot exceed 100, got %d", c.MaxConcurrentChecks)
	}
	if c.Timeout < 1*time.Second {
		return fmt.Errorf("timeout must be at least 1 second, got %v", c.Timeout)
	}
	if c.RetryCount < 0 {
		return fmt.Errorf("retry count cannot be negative, got %d", c.RetryCount)
	}
	if c.OutputDir == "" {
		return fmt.Errorf("output directory cannot be empty")
	}
	if len(c.SuccessStatusCodes) == 0 {
		return fmt.Errorf("must specify at least one success status code")
	}
	if c.MaxRedirects < 0 {
		return fmt.Errorf("max redirects cannot be negative, got %d", c.MaxRedirects)
	}
	if c.CrawlDepth < 0 {
		return fmt.Errorf("crawl depth cannot be negative, got %d", c.CrawlDepth)
	}
	if c.EnableCrawl && c.MaxPages < 1 {
		return fmt.Errorf("max pages must be at least 1 when crawling, got %d", c.MaxPages)
	}
	if c.RateLimit < 0 {
		return fmt.Errorf("rate limit cannot be negative, got %v", c.RateLimit)
	}
	if c.FailOn != "" && !c.FailOn.Valid() {
		return fmt.Errorf("unknown --fail-on severity %q (use info, low, medium, high or critical)", c.FailOn)
	}
	return nil
}

// Clone creates a deep copy of the config to avoid race conditions
func (c *Config) Clone() *Config {
	clone := *c
	clone.SuccessStatusCodes = make([]int, len(c.SuccessStatusCodes))
	copy(clone.SuccessStatusCodes, c.SuccessStatusCodes)
	return &clone
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		SuccessStatusCodes:  []int{200},
		Timeout:             10 * time.Second,
		RetryCount:          2,
		MaxConcurrentChecks: 5,
		VerifyTLS:           true, // Changed to true by default for security
		UserAgent:           DefaultUserAgent,
		OutputDir:           "results",
		LogVerbose:          false,
		NoColor:             false,
		Quiet:               false,
		BrowserTimeout:      20 * time.Second,
		NoProgress:          false,
		ForceHTTPS:          false,
		SkipDNS:             false,
		SkipBrowser:         false,
		TakeScreenshots:     false,
		ScreenshotDir:       "screenshots",
		DetectTech:          false,
		CheckSecurity:       false,
		OutputFormat:        "all",
		AnalyzeContent:      false,
		ExportPath:          "",
		MaxRedirects:        10,
		IncludeCertInfo:     false,

		EnableSubdomains:  false,
		SubdomainWordlist: "",
		PassiveOnly:       false,
		EnableDNSRecords:  false,
		EnablePorts:       false,
		PortSpec:          "top",
		EnableProbes:      false,
		EnableSecrets:     false,
		EnableCrawl:       false,
		CrawlDepth:        2,
		MaxPages:          50,
		EnableFuzz:        false,
		Aggressive:        false,

		EnableTemplates: false,
		TemplatesDir:    "",
		EnableVuln:      false,
		SARIFPath:       "",

		ProxyURL:     "",
		RateLimit:    0,
		ScopeFile:    "",
		Authorize:    false,
		AuditLogPath: "",
		ResumeFile:   "",
		Profile:      "",
	}
}

// ActiveScanRequested reports whether any feature that sends crafted requests
// to non-root paths or non-web ports is enabled. These require authorization.
func (c *Config) ActiveScanRequested() bool {
	return c.EnablePorts || c.EnableProbes || c.EnableTemplates || c.EnableFuzz
}
