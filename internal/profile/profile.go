// Package profile applies a YAML profile of overrides onto a Config, so common
// scan modes can be saved and reused.
package profile

import (
	"fmt"
	"os"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
	"gopkg.in/yaml.v3"
)

// Profile holds optional overrides; only keys present in the file take effect.
type Profile struct {
	Concurrency    *int     `yaml:"concurrency"`
	Timeout        *string  `yaml:"timeout"`
	SkipBrowser    *bool    `yaml:"skip_browser"`
	SkipDNS        *bool    `yaml:"skip_dns"`
	ForceHTTPS     *bool    `yaml:"force_https"`
	DetectTech     *bool    `yaml:"detect_tech"`
	SecurityCheck  *bool    `yaml:"security_check"`
	AnalyzeContent *bool    `yaml:"analyze_content"`
	Screenshots    *bool    `yaml:"screenshots"`
	Subdomains     *bool    `yaml:"subdomains"`
	PassiveOnly    *bool    `yaml:"passive_only"`
	Ports          *bool    `yaml:"ports"`
	PortSpec       *string  `yaml:"port_spec"`
	Probes         *bool    `yaml:"probes"`
	Secrets        *bool    `yaml:"secrets"`
	Templates      *bool    `yaml:"templates"`
	Vuln           *bool    `yaml:"vuln"`
	Rate           *float64 `yaml:"rate"`
}

// Apply reads the profile at path and overlays its values onto cfg.
func Apply(path string, cfg *models.Config) error {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return fmt.Errorf("failed to read profile: %w", err)
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("failed to parse profile: %w", err)
	}

	if p.Concurrency != nil {
		cfg.MaxConcurrentChecks = *p.Concurrency
	}
	if p.Timeout != nil {
		d, err := time.ParseDuration(*p.Timeout)
		if err != nil {
			return fmt.Errorf("invalid timeout in profile: %w", err)
		}
		cfg.Timeout = d
	}
	setBool(p.SkipBrowser, &cfg.SkipBrowser)
	setBool(p.SkipDNS, &cfg.SkipDNS)
	setBool(p.ForceHTTPS, &cfg.ForceHTTPS)
	setBool(p.DetectTech, &cfg.DetectTech)
	setBool(p.SecurityCheck, &cfg.CheckSecurity)
	setBool(p.AnalyzeContent, &cfg.AnalyzeContent)
	setBool(p.Screenshots, &cfg.TakeScreenshots)
	setBool(p.Subdomains, &cfg.EnableSubdomains)
	setBool(p.PassiveOnly, &cfg.PassiveOnly)
	setBool(p.Ports, &cfg.EnablePorts)
	setBool(p.Probes, &cfg.EnableProbes)
	setBool(p.Secrets, &cfg.EnableSecrets)
	setBool(p.Templates, &cfg.EnableTemplates)
	setBool(p.Vuln, &cfg.EnableVuln)
	if p.PortSpec != nil {
		cfg.PortSpec = *p.PortSpec
	}
	if p.Rate != nil {
		cfg.RateLimit = *p.Rate
	}
	return nil
}

func setBool(src *bool, dst *bool) {
	if src != nil {
		*dst = *src
	}
}
