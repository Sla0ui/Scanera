// Package probe sends a small set of safe GET requests for commonly exposed
// sensitive files and endpoints, emitting findings. Every request is gated by
// the caller's scope and rate limiter.
package probe

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/Sla0ui/scanera/internal/models"
	"github.com/Sla0ui/scanera/internal/ratelimit"
)

type probe struct {
	Path        string
	ID          string
	Title       string
	Severity    models.Severity
	Description string
	match       func(status int, body string, h http.Header) bool
}

func bodyContains(sub ...string) func(int, string, http.Header) bool {
	return func(status int, body string, _ http.Header) bool {
		if status != http.StatusOK {
			return false
		}
		for _, s := range sub {
			if strings.Contains(body, s) {
				return true
			}
		}
		return false
	}
}

var probes = []probe{
	{
		Path: "/.git/config", ID: "exposed-git-config", Title: "Exposed .git/config",
		Severity: models.SeverityHigh, Description: "A .git/config is reachable; the repository may be downloadable, leaking source and history.",
		match: bodyContains("[core]", "repositoryformatversion"),
	},
	{
		Path: "/.env", ID: "exposed-dotenv", Title: "Exposed .env file",
		Severity: models.SeverityCritical, Description: "A .env file is reachable and commonly contains credentials and secrets.",
		match: func(status int, body string, _ http.Header) bool {
			return status == http.StatusOK && strings.Contains(body, "=") &&
				(strings.Contains(strings.ToUpper(body), "KEY") ||
					strings.Contains(strings.ToUpper(body), "SECRET") ||
					strings.Contains(strings.ToUpper(body), "PASSWORD") ||
					strings.Contains(strings.ToUpper(body), "TOKEN") ||
					strings.Contains(strings.ToUpper(body), "DB_"))
		},
	},
	{
		Path: "/.DS_Store", ID: "exposed-ds-store", Title: "Exposed .DS_Store",
		Severity: models.SeverityLow, Description: "A .DS_Store file can disclose directory structure.",
		match: func(status int, body string, _ http.Header) bool {
			return status == http.StatusOK && strings.HasPrefix(body, "\x00\x00\x00\x01Bud1")
		},
	},
	{
		Path: "/.svn/entries", ID: "exposed-svn", Title: "Exposed .svn/entries",
		Severity: models.SeverityMedium, Description: "A Subversion working copy may be exposed.",
		match: bodyContains("svn://", "dir"),
	},
	{
		Path: "/server-status", ID: "apache-server-status", Title: "Apache server-status exposed",
		Severity: models.SeverityMedium, Description: "mod_status is reachable and leaks request and client details.",
		match: bodyContains("Apache Server Status", "Server uptime"),
	},
	{
		Path: "/.well-known/security.txt", ID: "missing-security-txt", Title: "security.txt present",
		Severity: models.SeverityInfo, Description: "A security.txt contact policy is published.",
		match: bodyContains("Contact:", "contact:"),
	},
	{
		Path: "/actuator/health", ID: "spring-actuator", Title: "Spring Boot actuator exposed",
		Severity: models.SeverityMedium, Description: "Spring Boot actuator endpoints are reachable and may leak environment and metrics.",
		match: bodyContains("\"status\":\"UP\"", "\"status\": \"UP\""),
	},
	{
		Path: "/phpinfo.php", ID: "phpinfo", Title: "phpinfo() exposed",
		Severity: models.SeverityMedium, Description: "phpinfo() output discloses configuration and environment.",
		match: bodyContains("phpinfo()", "PHP Version"),
	},
}

// Options controls probing.
type Options struct {
	Client    *http.Client
	UserAgent string
	Limiter   *ratelimit.Limiter
}

// Run executes the probes against baseURL (scheme://host) and returns findings.
func Run(ctx context.Context, baseURL string, opts Options) []models.Finding {
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	baseURL = strings.TrimRight(baseURL, "/")

	var findings []models.Finding
	for _, p := range probes {
		if opts.Limiter != nil {
			if err := opts.Limiter.Wait(ctx); err != nil {
				break
			}
		}
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		target := baseURL + p.Path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		if opts.UserAgent != "" {
			req.Header.Set("User-Agent", opts.UserAgent)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if p.match(resp.StatusCode, string(body), resp.Header) {
			findings = append(findings, models.Finding{
				ID:          p.ID,
				Title:       p.Title,
				Severity:    p.Severity,
				Source:      "probe",
				Description: p.Description,
				Location:    target,
				Evidence:    snippet(string(body)),
			})
		}
	}
	return findings
}

func snippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}
