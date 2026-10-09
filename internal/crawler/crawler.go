// Package crawler performs a breadth-first, same-host crawl so deeper scans can
// analyze more than just the root page (feeding secret and content scanning).
package crawler

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Sla0ui/scanera/internal/ratelimit"
)

var linkRe = regexp.MustCompile(`(?i)(?:href|src)=["']([^"'#\s]+)["']`)

// Options controls the crawl.
type Options struct {
	Client    *http.Client
	UserAgent string
	Depth     int
	MaxPages  int
	Limiter   *ratelimit.Limiter
}

// Page is a fetched page.
type Page struct {
	URL    string
	Status int
	Body   string
}

// Crawl walks same-host links starting at start, up to Depth and MaxPages.
func Crawl(ctx context.Context, start string, opts Options) []Page {
	if opts.Client == nil {
		opts.Client = http.DefaultClient
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 50
	}
	if opts.Depth < 0 {
		opts.Depth = 0
	}

	base, err := url.Parse(start)
	if err != nil {
		return nil
	}
	host := base.Hostname()

	type item struct {
		u string
		d int
	}
	queue := []item{{start, 0}}
	visited := map[string]bool{start: true}
	var pages []Page

	for len(queue) > 0 && len(pages) < opts.MaxPages {
		it := queue[0]
		queue = queue[1:]

		select {
		case <-ctx.Done():
			return pages
		default:
		}
		if opts.Limiter != nil {
			if err := opts.Limiter.Wait(ctx); err != nil {
				break
			}
		}

		status, body := fetch(ctx, opts.Client, it.u, opts.UserAgent)
		if status == 0 {
			continue
		}
		pages = append(pages, Page{URL: it.u, Status: status, Body: body})

		if it.d >= opts.Depth {
			continue
		}
		for _, link := range extractLinks(body, it.u, host) {
			if !visited[link] {
				visited[link] = true
				queue = append(queue, item{link, it.d + 1})
			}
		}
	}
	return pages
}

func fetch(ctx context.Context, client *http.Client, rawURL, ua string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, ""
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "html") && !strings.Contains(ct, "javascript") &&
		!strings.Contains(ct, "json") && !strings.Contains(ct, "text") {
		return resp.StatusCode, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return resp.StatusCode, string(body)
}

func extractLinks(body, pageURL, host string) []string {
	pu, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, m := range linkRe.FindAllStringSubmatch(body, -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "javascript:") ||
			strings.HasPrefix(raw, "tel:") || strings.HasPrefix(raw, "data:") {
			continue
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := pu.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			continue
		}
		if abs.Hostname() != host {
			continue
		}
		abs.Fragment = ""
		s := abs.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
