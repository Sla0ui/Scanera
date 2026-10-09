// Package discovery performs active content/path discovery (directory busting)
// against a base URL, using an embedded list of commonly sensitive paths and a
// soft-404 baseline to reduce noise. It is an active scan and must be gated by
// the caller's authorization scope.
package discovery

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/Sla0ui/scanera/internal/models"
	"github.com/Sla0ui/scanera/internal/ratelimit"
)

//go:embed paths.txt
var embeddedPaths string

// Paths returns the built-in path list.
func Paths() []string {
	var out []string
	for _, l := range strings.Split(embeddedPaths, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// Options controls discovery.
type Options struct {
	Client    *http.Client
	UserAgent string
	Limiter   *ratelimit.Limiter
	Paths     []string
}

// Run probes each path under baseURL and returns findings plus the list of
// discovered URLs.
func Run(ctx context.Context, baseURL string, opts Options) ([]models.Finding, []string) {
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	base := strings.TrimRight(baseURL, "/")
	paths := opts.Paths
	if len(paths) == 0 {
		paths = Paths()
	}

	// Soft-404 baseline: a path that should not exist.
	baseStatus, baseLen := probe(ctx, client, fmt.Sprintf("%s/scanera-404-%d", base, rand.Int()), opts.UserAgent)

	var findings []models.Finding
	var discovered []string
	for _, p := range paths {
		select {
		case <-ctx.Done():
			return findings, discovered
		default:
		}
		if opts.Limiter != nil {
			if err := opts.Limiter.Wait(ctx); err != nil {
				break
			}
		}
		u := base + p
		status, length := probe(ctx, client, u, opts.UserAgent)
		if !interesting(status, length, baseStatus, baseLen) {
			continue
		}
		discovered = append(discovered, u)
		findings = append(findings, models.Finding{
			ID:       "discovered-path",
			Title:    fmt.Sprintf("Discovered path (HTTP %d): %s", status, p),
			Severity: severityFor(p, status),
			Source:   "discovery",
			Location: u,
			Evidence: "HTTP " + strconv.Itoa(status),
			Tags:     []string{"content-discovery"},
		})
	}
	return findings, discovered
}

func probe(ctx context.Context, client *http.Client, rawURL, ua string) (int, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, 0
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, len(body)
}

// interesting decides whether a response indicates a real, distinct resource
// versus the soft-404 baseline.
func interesting(status, length, baseStatus, baseLen int) bool {
	if status == 0 || status == 404 {
		return false
	}
	// 401/403 reveal a protected but present resource.
	if status == 401 || status == 403 {
		return true
	}
	if status >= 200 && status < 400 {
		// If the baseline (bogus path) also returns 2xx/3xx, only flag when the
		// body length differs meaningfully (soft-404 pages are near-identical).
		if baseStatus >= 200 && baseStatus < 400 {
			diff := length - baseLen
			if diff < 0 {
				diff = -diff
			}
			return diff > 64
		}
		return true
	}
	return false
}

func severityFor(path string, status int) models.Severity {
	lower := strings.ToLower(path)
	sensitive := []string{".env", ".git", ".svn", ".ssh", "id_rsa", "wp-config", "config", "backup", "dump.sql", "db.sql", "database", "credentials", "heapdump", ".htpasswd", ".aws", ".npmrc", "settings.py", "web.config", "appsettings"}
	for _, s := range sensitive {
		if strings.Contains(lower, s) {
			if status == 200 {
				return models.SeverityHigh
			}
			return models.SeverityMedium
		}
	}
	admin := []string{"admin", "login", "console", "manager", "phpmyadmin", "adminer", "dashboard", "cpanel", "whm"}
	for _, a := range admin {
		if strings.Contains(lower, a) {
			return models.SeverityLow
		}
	}
	return models.SeverityInfo
}
