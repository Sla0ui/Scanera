package models

import (
	"fmt"
	"time"
)

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
	Format              string
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
	BatchSize           int
	WebhookURL          string
	HistoricalCompare   bool
	ExportPath          string
	MaxRedirects        int
	IncludeCertInfo     bool
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
		UserAgent:           "Mozilla/5.0 (compatible; Scanera/1.0; +https://github.com/Sla0ui/scanera)",
		OutputDir:           "results",
		LogVerbose:          false,
		NoColor:             false,
		Format:              "text",
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
		BatchSize:           100,
		WebhookURL:          "",
		HistoricalCompare:   false,
		ExportPath:          "",
		MaxRedirects:        10,
		IncludeCertInfo:     false,
	}
}
