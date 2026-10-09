// Package profile applies a YAML profile of overrides onto a Config, so common
// scan modes can be saved and reused.
package profile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
	"gopkg.in/yaml.v3"
)

// Profile holds optional overrides; only keys present in the file take effect.
// Authorization (--scope / --authorize) is deliberately not settable here so
// active scanning always needs an explicit decision on the command line.
type Profile struct {
	StatusCodes       []int    `yaml:"status_codes"`
	Concurrency       *int     `yaml:"concurrency"`
	Timeout           *string  `yaml:"timeout"`
	Retries           *int     `yaml:"retries"`
	VerifyTLS         *bool    `yaml:"verify_tls"`
	UserAgent         *string  `yaml:"user_agent"`
	OutputDir         *string  `yaml:"output_dir"`
	MaxRedirects      *int     `yaml:"max_redirects"`
	SkipBrowser       *bool    `yaml:"skip_browser"`
	SkipDNS           *bool    `yaml:"skip_dns"`
	ForceHTTPS        *bool    `yaml:"force_https"`
	DetectTech        *bool    `yaml:"detect_tech"`
	SecurityCheck     *bool    `yaml:"security_check"`
	CertInfo          *bool    `yaml:"cert_info"`
	AnalyzeContent    *bool    `yaml:"analyze_content"`
	Screenshots       *bool    `yaml:"screenshots"`
	Subdomains        *bool    `yaml:"subdomains"`
	PassiveOnly       *bool    `yaml:"passive_only"`
	SubdomainWordlist *string  `yaml:"subdomain_wordlist"`
	DNS               *bool    `yaml:"dns"`
	Takeover          *bool    `yaml:"takeover"`
	Ports             *bool    `yaml:"ports"`
	PortSpec          *string  `yaml:"port_spec"`
	Probes            *bool    `yaml:"probes"`
	Secrets           *bool    `yaml:"secrets"`
	Crawl             *bool    `yaml:"crawl"`
	CrawlDepth        *int     `yaml:"crawl_depth"`
	MaxPages          *int     `yaml:"max_pages"`
	Fuzz              *bool    `yaml:"fuzz"`
	Templates         *bool    `yaml:"templates"`
	TemplatesDir      *string  `yaml:"templates_dir"`
	Vuln              *bool    `yaml:"vuln"`
	Aggressive        *bool    `yaml:"aggressive"`
	Rate              *float64 `yaml:"rate"`
	Proxy             *string  `yaml:"proxy"`
	FailOn            *string  `yaml:"fail_on"`
}

// Apply reads the profile at path and overlays its values onto cfg. Unknown
// keys are an error, so a typo doesn't silently drop a setting.
func Apply(path string, cfg *models.Config) error {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return fmt.Errorf("failed to read profile: %w", err)
	}
	var p Profile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("failed to parse profile %s: %w", path, err)
	}

	if len(p.StatusCodes) > 0 {
		cfg.SuccessStatusCodes = append([]int(nil), p.StatusCodes...)
	}
	if p.Timeout != nil {
		d, err := time.ParseDuration(*p.Timeout)
		if err != nil {
			return fmt.Errorf("invalid timeout in profile: %w", err)
		}
		cfg.Timeout = d
	}
	set(p.Concurrency, &cfg.MaxConcurrentChecks)
	set(p.Retries, &cfg.RetryCount)
	set(p.VerifyTLS, &cfg.VerifyTLS)
	set(p.UserAgent, &cfg.UserAgent)
	set(p.OutputDir, &cfg.OutputDir)
	set(p.MaxRedirects, &cfg.MaxRedirects)
	set(p.SkipBrowser, &cfg.SkipBrowser)
	set(p.SkipDNS, &cfg.SkipDNS)
	set(p.ForceHTTPS, &cfg.ForceHTTPS)
	set(p.DetectTech, &cfg.DetectTech)
	set(p.SecurityCheck, &cfg.CheckSecurity)
	set(p.CertInfo, &cfg.IncludeCertInfo)
	set(p.AnalyzeContent, &cfg.AnalyzeContent)
	set(p.Screenshots, &cfg.TakeScreenshots)
	set(p.Subdomains, &cfg.EnableSubdomains)
	set(p.PassiveOnly, &cfg.PassiveOnly)
	set(p.SubdomainWordlist, &cfg.SubdomainWordlist)
	set(p.DNS, &cfg.EnableDNSRecords)
	set(p.Takeover, &cfg.EnableTakeover)
	set(p.Ports, &cfg.EnablePorts)
	set(p.PortSpec, &cfg.PortSpec)
	set(p.Probes, &cfg.EnableProbes)
	set(p.Secrets, &cfg.EnableSecrets)
	set(p.Crawl, &cfg.EnableCrawl)
	set(p.CrawlDepth, &cfg.CrawlDepth)
	set(p.MaxPages, &cfg.MaxPages)
	set(p.Fuzz, &cfg.EnableFuzz)
	set(p.Templates, &cfg.EnableTemplates)
	set(p.TemplatesDir, &cfg.TemplatesDir)
	set(p.Vuln, &cfg.EnableVuln)
	set(p.Aggressive, &cfg.Aggressive)
	set(p.Rate, &cfg.RateLimit)
	set(p.Proxy, &cfg.ProxyURL)
	if p.FailOn != nil {
		cfg.FailOn = models.Severity(*p.FailOn)
	}
	return nil
}

func set[T any](src *T, dst *T) {
	if src != nil {
		*dst = *src
	}
}
