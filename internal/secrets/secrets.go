// Package secrets scans response content for exposed credentials and keys.
package secrets

import (
	"regexp"
	"sync"

	"github.com/Sla0ui/scanera/internal/models"
)

type pattern struct {
	id       string
	title    string
	severity models.Severity
	re       *regexp.Regexp
}

var (
	patterns []pattern
	once     sync.Once
)

func initPatterns() {
	defs := []struct {
		id, title, sev, re string
	}{
		{"aws-access-key", "AWS access key ID", "high", `AKIA[0-9A-Z]{16}`},
		{"aws-secret-key", "Possible AWS secret access key", "high", `(?i)aws_secret_access_key["'\s:=]+[A-Za-z0-9/+]{40}`},
		// Browser keys for Maps/Firebase are public by design, so this is only
		// worth a look at the key's restrictions, not an alarm.
		{"google-api-key", "Google API key (check its restrictions)", "low", `AIza[0-9A-Za-z\-_]{35}`},
		{"slack-token", "Slack token", "high", `xox[baprs]-[0-9A-Za-z\-]{10,48}`},
		{"github-token", "GitHub token", "high", `gh[pousr]_[0-9A-Za-z]{36}`},
		{"stripe-key", "Stripe secret key", "critical", `sk_live_[0-9A-Za-z]{24,}`},
		{"stripe-restricted-key", "Stripe restricted key", "high", `rk_live_[0-9A-Za-z]{24,}`},
		{"gitlab-token", "GitLab personal access token", "high", `glpat-[0-9A-Za-z_\-]{20}`},
		{"slack-webhook", "Slack incoming webhook URL", "medium", `https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+`},
		{"sendgrid-key", "SendGrid API key", "high", `SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}`},
		{"npm-token", "npm access token", "high", `npm_[0-9A-Za-z]{36}`},
		{"google-oauth-secret", "Google OAuth client secret", "high", `GOCSPX-[0-9A-Za-z_\-]{28}`},
		{"shopify-token", "Shopify access token", "high", `shpat_[0-9a-fA-F]{32}`},
		{"digitalocean-token", "DigitalOcean personal access token", "high", `dop_v1_[0-9a-f]{64}`},
		{"pypi-token", "PyPI upload token", "high", `pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\-]{50,}`},
		{"azure-storage-key", "Azure storage account key", "high", `AccountKey=[0-9A-Za-z+/=]{86,88}`},
		{"private-key", "Private key block", "critical", `-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`},
		{"jwt", "JSON Web Token", "low", `eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`},
		{"generic-secret", "Generic hardcoded secret", "medium", `(?i)(api_key|apikey|secret|passwd|password|token)["'\s:=]{1,4}["'][A-Za-z0-9\-_]{12,64}["']`},
	}
	for _, d := range defs {
		patterns = append(patterns, pattern{
			id: d.id, title: d.title, severity: models.Severity(d.sev),
			re: regexp.MustCompile(d.re),
		})
	}
}

// Scan searches content for secrets and returns findings. location identifies
// where the content came from (used in the finding).
func Scan(content, location string) []models.Finding {
	once.Do(initPatterns)

	var findings []models.Finding
	seen := make(map[string]struct{})
	for _, p := range patterns {
		m := p.re.FindString(content)
		if m == "" {
			continue
		}
		if _, ok := seen[p.id]; ok {
			continue
		}
		seen[p.id] = struct{}{}
		findings = append(findings, models.Finding{
			ID:       p.id,
			Title:    p.title,
			Severity: p.severity,
			Source:   "secret",
			Location: location,
			Evidence: redact(m),
			Tags:     []string{"secret-exposure"},
		})
	}
	return findings
}

func redact(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}
