// Package probe sends a small set of safe GET requests for commonly exposed
// sensitive files and endpoints, emitting findings. Every request is gated by
// the caller's scope and rate limiter.
package probe

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Sla0ui/scanera/internal/models"
	"github.com/Sla0ui/scanera/internal/ratelimit"
)

type probe struct {
	Path        string
	ID          string
	Title       string
	Severity    models.Severity
	Description string
	// artifact marks raw files (.env, .git/config, ...). Many sites answer
	// every unknown path with their HTML app shell, so an HTML response at one
	// of these paths is a catch-all page, never the file itself.
	artifact bool
	match    func(status int, body string, h http.Header) bool
}

var (
	dotenvLine  = regexp.MustCompile(`(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=`)
	contactLine = regexp.MustCompile(`(?mi)^contact:\s*\S`)
	svnHeader   = regexp.MustCompile(`^\d+\s*\n`)
	// SVN 1.7+ leaves only the format number in .svn/entries.
	svnStub = regexp.MustCompile(`^(?:[89]|[1-3][0-9])\s*$`)
)

var dotenvSensitive = []string{"KEY", "SECRET", "PASSWORD", "PASSWD", "TOKEN", "DB_", "DATABASE", "CREDENTIAL", "AUTH"}

// looksLikeDotenv requires at least one KEY=value line whose name suggests a
// credential, so a page that merely contains "=" and "KEY" doesn't qualify.
func looksLikeDotenv(status int, body string, _ http.Header) bool {
	if status != http.StatusOK {
		return false
	}
	for _, m := range dotenvLine.FindAllStringSubmatch(body, -1) {
		for _, s := range dotenvSensitive {
			if strings.Contains(m[1], s) {
				return true
			}
		}
	}
	return false
}

func looksLikeSVNEntries(status int, body string, _ http.Header) bool {
	if status != http.StatusOK {
		return false
	}
	if svnStub.MatchString(body) {
		return true
	}
	return svnHeader.MatchString(body) &&
		(strings.Contains(body, "\ndir\n") || strings.Contains(body, "svn://") || strings.Contains(body, "svn+ssh://"))
}

func bodyContainsAll(sub ...string) func(int, string, http.Header) bool {
	return func(status int, body string, _ http.Header) bool {
		if status != http.StatusOK {
			return false
		}
		for _, s := range sub {
			if !strings.Contains(body, s) {
				return false
			}
		}
		return true
	}
}

func looksLikeHTML(h http.Header, body string) bool {
	if strings.Contains(strings.ToLower(h.Get("Content-Type")), "text/html") {
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(body), "<")
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
		artifact: true,
		match:    bodyContains("[core]", "repositoryformatversion"),
	},
	{
		Path: "/.env", ID: "exposed-dotenv", Title: "Exposed .env file",
		Severity: models.SeverityCritical, Description: "A .env file is reachable and commonly contains credentials and secrets.",
		artifact: true,
		match:    looksLikeDotenv,
	},
	{
		Path: "/.DS_Store", ID: "exposed-ds-store", Title: "Exposed .DS_Store",
		Severity: models.SeverityLow, Description: "A .DS_Store file can disclose directory structure.",
		artifact: true,
		match: func(status int, body string, _ http.Header) bool {
			return status == http.StatusOK && strings.HasPrefix(body, "\x00\x00\x00\x01Bud1")
		},
	},
	{
		Path: "/.svn/entries", ID: "exposed-svn", Title: "Exposed .svn/entries",
		Severity: models.SeverityMedium, Description: "A Subversion working copy may be exposed.",
		artifact: true,
		match:    looksLikeSVNEntries,
	},
	{
		Path: "/server-status", ID: "apache-server-status", Title: "Apache server-status exposed",
		Severity: models.SeverityMedium, Description: "mod_status is reachable and leaks request and client details.",
		match: bodyContains("Apache Server Status", "Server uptime"),
	},
	{
		Path: "/.well-known/security.txt", ID: "security-txt", Title: "security.txt present",
		Severity: models.SeverityInfo, Description: "A security.txt contact policy is published.",
		artifact: true,
		match: func(status int, body string, _ http.Header) bool {
			return status == http.StatusOK && contactLine.MatchString(body)
		},
	},
	{
		Path: "/actuator/health", ID: "spring-actuator", Title: "Spring Boot actuator exposed",
		Severity: models.SeverityMedium, Description: "Spring Boot actuator endpoints are reachable and may leak environment and metrics.",
		artifact: true,
		match:    bodyContains("\"status\":\"UP\"", "\"status\": \"UP\""),
	},
	{
		Path: "/phpinfo.php", ID: "phpinfo", Title: "phpinfo() exposed",
		Severity: models.SeverityMedium, Description: "phpinfo() output discloses configuration and environment.",
		match: bodyContainsAll("phpinfo()", "PHP Version"),
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

		if p.artifact && looksLikeHTML(resp.Header, string(body)) {
			continue
		}
		if p.match(resp.StatusCode, string(body), resp.Header) {
			findings = append(findings, models.Finding{
				ID:          p.ID,
				Title:       p.Title,
				Severity:    p.Severity,
				Source:      "probe",
				Description: p.Description,
				Location:    target,
				Evidence:    evidence(p.ID, string(body)),
			})
		}
	}
	return findings
}

var (
	urlCredentials = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s:@]+(?::[^/\s@]*)?@`)
	secretAssign   = regexp.MustCompile(`(?im)^(\s*(?:export\s+)?[\w.-]*(?:pass|secret|token|key|auth|credential)[\w.-]*\s*[=:]\s*)\S.*$`)
)

// evidence describes what a probe found without copying secrets into the
// report: reports end up in CI logs and code-scanning uploads.
func evidence(id, body string) string {
	if id == "exposed-dotenv" {
		var keys []string
		seen := make(map[string]bool)
		for _, m := range dotenvLine.FindAllStringSubmatch(body, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				keys = append(keys, m[1])
			}
		}
		if len(keys) > 15 {
			keys = append(keys[:15], "...")
		}
		return "variables: " + strings.Join(keys, ", ")
	}
	body = urlCredentials.ReplaceAllString(body, "${1}****@")
	body = secretAssign.ReplaceAllString(body, "${1}****")
	return snippet(body)
}

func snippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 160 {
		return s
	}
	cut := 160
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
