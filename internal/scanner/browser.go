package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Sla0ui/scanera/internal/models"
	"github.com/chromedp/chromedp"
)

// SetupBrowserContext creates a browser context with secure defaults
func SetupBrowserContext(config *models.Config) (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("ignore-certificate-errors", !config.VerifyTLS),
		chromedp.UserAgent(config.UserAgent),
		chromedp.DisableGPU,
		chromedp.WindowSize(1280, 800),
	)
	if config.ProxyURL != "" {
		// Keep browser traffic on the same route as the HTTP client.
		opts = append(opts, chromedp.ProxyServer(config.ProxyURL))
	}
	return chromedp.NewExecAllocator(context.Background(), opts...)
}

// Whole-title matches for generic one-word error pages; matching these as
// substrings would mark sites like "Error Tracking Software" as dead.
var errorTitlesExact = map[string]bool{
	"error": true, "forbidden": true, "unavailable": true, "not found": true,
	"access denied": true, "blocked": true, "suspended": true,
}

var errorTitlePhrases = []string{
	"404 not found", "page not found", "site not found", "file not found",
	"403 forbidden", "401 unauthorized", "502 bad gateway", "bad gateway",
	"503 service", "service unavailable", "504 gateway", "gateway timeout",
	"internal server error", "web server is returning an unknown error",
	"domain for sale", "domain is for sale", "buy this domain", "parked domain",
	"account suspended", "account has been suspended",
	"error 400", "error 401", "error 403", "error 404", "error 500", "error 502", "error 503",
}

var statusCodeTitle = regexp.MustCompile(`^(?:http\s*)?[45]\d\d\b`)

// errorPageTitle reports whether a page title looks like an error or parking
// page rather than a real site.
func errorPageTitle(title string) bool {
	t := strings.ToLower(strings.TrimSpace(title))
	if errorTitlesExact[t] || statusCodeTitle.MatchString(t) {
		return true
	}
	for _, p := range errorTitlePhrases {
		if strings.Contains(t, p) {
			return true
		}
	}
	return false
}

// PerformBrowserCheck loads url in the headless browser and returns nil when
// it renders a real page: a non-empty title that isn't an error or parking
// page. The returned error says why the page was rejected.
func PerformBrowserCheck(ctx context.Context, url string, browserCtx context.Context, result *models.Result, config *models.Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(browserCtx, config.BrowserTimeout)
	defer cancel()
	// Abort the page load as soon as the scan itself is cancelled.
	stop := context.AfterFunc(ctx, cancel)
	defer stop()

	var title string
	var shot []byte
	tasks := chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Title(&title),
	}
	if config.TakeScreenshots {
		tasks = append(tasks, chromedp.FullScreenshot(&shot, 90))
	}
	if err := chromedp.Run(checkCtx, tasks); err != nil {
		if errors.Is(checkCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("page did not load within %s", config.BrowserTimeout)
		}
		return fmt.Errorf("page load failed: %w", err)
	}

	if len(shot) > 0 {
		path := filepath.Join(config.OutputDir, config.ScreenshotDir, screenshotName(result.Domain))
		if err := os.WriteFile(path, shot, 0o644); err == nil {
			result.ScreenshotPath = path
		}
	}

	title = strings.TrimSpace(title)
	if title != "" {
		result.Title = title
	}
	if title == "" {
		return errors.New("page has no title")
	}
	if errorPageTitle(title) {
		return fmt.Errorf("error or parking page (title %q)", title)
	}
	return nil
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// screenshotName turns a domain (possibly host:port or an IPv6 literal) into a
// file name that is valid on every OS.
func screenshotName(domain string) string {
	return unsafeFileChars.ReplaceAllString(domain, "_") + ".png"
}
