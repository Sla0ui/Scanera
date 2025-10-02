package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
)

// SetupBrowserContext creates a browser context with secure defaults
func SetupBrowserContext(config *models.Config) (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("ignore-certificate-errors", !config.VerifyTLS),
		// SECURITY FIX: Removed disable-web-security flag
		chromedp.UserAgent(config.UserAgent),
		// SECURITY FIX: Only disable sandbox if explicitly needed (not by default)
		chromedp.DisableGPU,
		chromedp.WindowSize(1280, 800),
	)
	return chromedp.NewExecAllocator(context.Background(), opts...)
}

// PerformBrowserCheck checks a URL using a headless browser
func PerformBrowserCheck(ctx context.Context, url string, browserCtx context.Context, result *models.Result, config *models.Config) bool {
	checkCtx, cancel := context.WithTimeout(browserCtx, config.BrowserTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return false
	default:
	}

	var title string
	var bodyContent string

	tasks := chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Title(&title),
	}

	if config.AnalyzeContent {
		tasks = append(tasks, chromedp.InnerHTML("body", &bodyContent))
	}

	if config.TakeScreenshots {
		var buf []byte
		screenshotTask := fullScreenshot(90, &buf)
		tasks = append(tasks, screenshotTask)

		err := chromedp.Run(checkCtx, tasks)

		if err == nil && len(buf) > 0 {
			filename := fmt.Sprintf("%s.png", result.Domain)
			screenshotPath := filepath.Join(config.OutputDir, config.ScreenshotDir, filename)

			if err := os.WriteFile(screenshotPath, buf, 0644); err == nil {
				result.ScreenshotPath = screenshotPath
			}
		} else if err != nil {
			return false
		}
	} else {
		err := chromedp.Run(checkCtx, tasks)
		if err != nil {
			return false
		}
	}

	result.Title = title

	if config.AnalyzeContent && bodyContent != "" {
		// Content analysis will be done by analyzer package
		// For now, store it in a way that can be processed later
	}

	if title == "" {
		return false
	}

	// Check for error pages
	errorKeywords := []string{
		"404", "not found", "error", "unavailable",
		"forbidden", "access denied", "bad gateway",
		"domain for sale", "parked domain",
	}

	lowerTitle := strings.ToLower(title)

	for _, keyword := range errorKeywords {
		if strings.Contains(lowerTitle, keyword) {
			return false
		}
	}

	return true
}

// fullScreenshot takes a full-page screenshot
func fullScreenshot(quality int, res *[]byte) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		var buf []byte
		if err := chromedp.Run(ctx, chromedp.FullScreenshot(&buf, quality)); err != nil {
			return err
		}
		*res = buf
		return nil
	})
}

// CaptureScreenshot captures a screenshot of a domain
func CaptureScreenshot(ctx context.Context, domain string, width, height int, timeoutDuration time.Duration, fullpage bool) ([]byte, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.DisableGPU,
		chromedp.WindowSize(width, height),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	browserCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	timeoutCtx, cancel := context.WithTimeout(browserCtx, timeoutDuration)
	defer cancel()

	urls := []string{
		"https://" + domain,
		"http://" + domain,
	}

	var buf []byte
	var err error

	for _, url := range urls {
		if fullpage {
			err = chromedp.Run(timeoutCtx,
				chromedp.Navigate(url),
				chromedp.WaitReady("body", chromedp.ByQuery),
				chromedp.ActionFunc(func(ctx context.Context) error {
					err := emulation.SetDeviceMetricsOverride(int64(width), int64(height), 1, false).Do(ctx)
					if err != nil {
						return err
					}

					var pageHeight int64
					err = chromedp.Evaluate(`
						Math.max(
							document.body.scrollHeight,
							document.documentElement.scrollHeight,
							document.body.offsetHeight,
							document.documentElement.offsetHeight
						)
					`, &pageHeight).Do(ctx)
					if err != nil {
						return err
					}

					return emulation.SetDeviceMetricsOverride(int64(width), pageHeight, 1, false).Do(ctx)
				}),
				chromedp.CaptureScreenshot(&buf),
			)
		} else {
			err = chromedp.Run(timeoutCtx,
				chromedp.Navigate(url),
				chromedp.WaitReady("body", chromedp.ByQuery),
				chromedp.CaptureScreenshot(&buf),
			)
		}

		if err == nil {
			return buf, nil
		}
	}

	return nil, fmt.Errorf("failed to capture screenshot: %w", err)
}
