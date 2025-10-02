package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
	"github.com/chromedp/chromedp"
	"github.com/schollz/progressbar/v3"
)

// Scanner performs domain scanning operations
type Scanner struct {
	config *models.Config
}

// New creates a new Scanner instance
func New(config *models.Config) (*Scanner, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return &Scanner{config: config}, nil
}

// ScanDomain checks a single domain
func (s *Scanner) ScanDomain(ctx context.Context, domain string, browserCtx context.Context) *models.Result {
	startTime := time.Now()

	result := &models.Result{
		Domain:      domain,
		Active:      false,
		LastChecked: time.Now(),
		ServerInfo: models.ServerInfo{
			Headers: make(map[string]string),
		},
		SecurityInfo: models.SecurityInfo{
			SecurityHeaders: make(map[string]string),
		},
	}

	select {
	case <-ctx.Done():
		result.Error = ctx.Err()
		return result
	default:
	}

	// DNS resolution
	if !s.config.SkipDNS {
		ips, err := ResolveDomain(domain)
		if err != nil {
			result.Error = fmt.Errorf("domain not resolvable: %w", err)
			return result
		}
		result.IPAddresses = ips
	}

	// Determine protocols to try
	var protocols []string
	if s.config.ForceHTTPS {
		protocols = []string{"https://"}
	} else {
		protocols = []string{"https://", "http://"}
	}

	// Try each protocol
	for _, protocol := range protocols {
		url := protocol + domain

		reqStart := time.Now()
		resp, err := TryHTTPRequest(url, s.config)
		if err != nil {
			continue
		}

		result.ResponseTime = time.Since(reqStart)
		result.StatusCode = resp.StatusCode
		result.FinalURL = resp.Request.URL.String()

		ExtractServerInfo(resp, result)

		// Security checks for HTTPS
		if s.config.CheckSecurity && protocol == "https://" {
			CheckSecurityHeaders(resp, result)
			if s.config.IncludeCertInfo {
				FetchCertificateInfo(domain, result)
			}
		}

		// Check for redirects
		if domain != resp.Request.URL.Hostname() {
			result.RedirectTo = resp.Request.URL.Hostname()
		}

		// Check if status code is successful
		if contains(s.config.SuccessStatusCodes, resp.StatusCode) {
			if s.config.SkipBrowser {
				result.Active = true

				if s.config.AnalyzeContent || s.config.DetectTech {
					body, err := io.ReadAll(resp.Body)
					if err == nil {
						// Content will be analyzed by analyzer/detector packages
						_ = body
					}
					resp.Body.Close()
				}
				return result
			}

			// Browser-based verification
			browserSuccess := PerformBrowserCheck(ctx, result.FinalURL, browserCtx, result, s.config)

			if browserSuccess {
				result.Active = true
				return result
			}
		}

		resp.Body.Close()
	}

	result.ResponseTime = time.Since(startTime)
	return result
}

// ScanDomains scans multiple domains concurrently
func (s *Scanner) ScanDomains(ctx context.Context, domains []string) ([]*models.Result, error) {
	allocCtx, allocCancel := SetupBrowserContext(s.config)
	defer allocCancel()

	return s.processDomainsWithPool(ctx, domains, allocCtx)
}

func (s *Scanner) processDomainsWithPool(ctx context.Context, domains []string, allocCtx context.Context) ([]*models.Result, error) {
	numWorkers := s.config.MaxConcurrentChecks
	workCh := make(chan string, len(domains))
	resultCh := make(chan *models.Result, len(domains))

	var bar *progressbar.ProgressBar
	if !s.config.Quiet && !s.config.NoProgress {
		bar = progressbar.NewOptions(len(domains),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionSetWidth(50),
			progressbar.OptionSetDescription("[cyan]Processing domains[reset]"),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]=[reset]",
				SaucerHead:    "[green]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}))
	}

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			browserCtx, cancel := chromedp.NewContext(allocCtx)
			defer cancel()

			for {
				select {
				case domain, ok := <-workCh:
					if !ok {
						return
					}

					result := s.ScanDomain(ctx, domain, browserCtx)
					resultCh <- result

					if bar != nil {
						bar.Add(1)
					}

				case <-ctx.Done():
					return
				}
			}
		}(i)
	}

	// Send work to workers
	go func() {
		for _, domain := range domains {
			select {
			case workCh <- domain:
			case <-ctx.Done():
				break
			}
		}
		close(workCh)
	}()

	// Wait for workers and close result channel
	go func() {
		wg.Wait()
		close(resultCh)

		if bar != nil {
			bar.Finish()
		}
	}()

	// Collect results
	var results []*models.Result
	for result := range resultCh {
		results = append(results, result)
	}

	return results, nil
}

// CheckSecurityHeaders analyzes security headers in HTTP response
func CheckSecurityHeaders(resp *http.Response, result *models.Result) {
	result.SecurityInfo.HasHTTPS = strings.HasPrefix(resp.Request.URL.String(), "https://")

	securityFlags := []string{}

	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Feature-Policy",
		"Permissions-Policy",
	}

	for _, header := range securityHeaders {
		value := resp.Header.Get(header)
		if value != "" {
			result.SecurityInfo.SecurityHeaders[header] = value
			securityFlags = append(securityFlags, header)
		}
	}

	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
		result.SecurityInfo.HSTPEnabled = true
	}

	result.ServerInfo.SecurityFlags = securityFlags
}

func contains(slice []int, item int) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
