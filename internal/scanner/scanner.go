package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sla0ui/scanera/internal/analyzer"
	"github.com/Sla0ui/scanera/internal/crawler"
	"github.com/Sla0ui/scanera/internal/detector"
	"github.com/Sla0ui/scanera/internal/discovery"
	"github.com/Sla0ui/scanera/internal/dnsx"
	"github.com/Sla0ui/scanera/internal/models"
	"github.com/Sla0ui/scanera/internal/netx"
	"github.com/Sla0ui/scanera/internal/portscan"
	"github.com/Sla0ui/scanera/internal/probe"
	"github.com/Sla0ui/scanera/internal/ratelimit"
	"github.com/Sla0ui/scanera/internal/scope"
	"github.com/Sla0ui/scanera/internal/secrets"
	"github.com/Sla0ui/scanera/internal/signature"
	"github.com/Sla0ui/scanera/internal/vuln"
	"github.com/chromedp/chromedp"
	"github.com/schollz/progressbar/v3"
)

// Scanner performs domain scanning operations.
type Scanner struct {
	config  *models.Config
	client  *http.Client
	limiter *ratelimit.Limiter
	scope   *scope.Scope
	engine  *signature.Engine
}

// New creates a new Scanner, building the shared HTTP client (with any proxy)
// and rate limiter from the config.
func New(config *models.Config) (*Scanner, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	client, err := netx.NewHTTPClient(config)
	if err != nil {
		return nil, err
	}
	return &Scanner{
		config:  config,
		client:  client,
		limiter: ratelimit.New(config.RateLimit),
	}, nil
}

// UseScope sets the authorization scope used to gate active scanning.
func (s *Scanner) UseScope(sc *scope.Scope) { s.scope = sc }

// UseTemplates sets the signature engine used when templates are enabled.
func (s *Scanner) UseTemplates(e *signature.Engine) { s.engine = e }

// fetch performs a GET using the shared client, honoring retries and the rate
// limiter.
func (s *Scanner) fetch(ctx context.Context, rawURL string) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < s.config.RetryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if s.limiter != nil {
			if err := s.limiter.Wait(ctx); err != nil {
				return nil, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request: %w", err)
		}
		req.Header.Set("User-Agent", s.config.UserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Cache-Control", "no-cache")

		resp, err := s.client.Do(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all request attempts failed: %w", lastErr)
}

// ScanDomain checks a single domain.
func (s *Scanner) ScanDomain(ctx context.Context, domain string, browserCtx context.Context) *models.Result {
	startTime := time.Now()

	result := &models.Result{
		Domain:      domain,
		Active:      false,
		LastChecked: time.Now(),
		ServerInfo:  models.ServerInfo{Headers: make(map[string]string)},
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

	if !s.config.SkipDNS {
		ips, err := ResolveDomain(domain, s.config.Timeout)
		if err != nil {
			result.Error = fmt.Errorf("domain not resolvable: %w", err)
			return result
		}
		result.IPAddresses = ips
	}

	var protocols []string
	if s.config.ForceHTTPS {
		protocols = []string{"https://"}
	} else {
		protocols = []string{"https://", "http://"}
	}

	needBody := s.config.DetectTech || s.config.AnalyzeContent ||
		s.config.EnableSecrets || s.config.EnableVuln

	for _, protocol := range protocols {
		reqStart := time.Now()
		resp, err := s.fetch(ctx, protocol+domain)
		if err != nil {
			continue
		}

		result.ResponseTime = time.Since(reqStart)
		result.StatusCode = resp.StatusCode
		result.FinalURL = resp.Request.URL.String()

		ExtractServerInfo(resp, result)

		if s.config.CheckSecurity && protocol == "https://" {
			CheckSecurityHeaders(resp, result)
			if s.config.IncludeCertInfo {
				_ = FetchCertificateInfo(domain, result)
			}
		}

		if domain != resp.Request.URL.Hostname() {
			result.RedirectTo = resp.Request.URL.Hostname()
		}

		var body string
		if needBody {
			body = readBody(resp.Body, maxBodyBytes)
		}
		headers := resp.Header
		resp.Body.Close()

		if contains(s.config.SuccessStatusCodes, resp.StatusCode) {
			if s.config.DetectTech {
				detector.DetectTechnologies(body, headers, result)
			}
			if s.config.AnalyzeContent {
				analyzer.AnalyzePageContent(body, result)
			}

			baseRoot, host := rootAndHost(result.FinalURL, domain)
			s.enrich(ctx, result, body, headers, baseRoot, host)

			if s.config.SkipBrowser {
				result.Active = true
				return result
			}
			if PerformBrowserCheck(ctx, result.FinalURL, browserCtx, result, s.config) {
				result.Active = true
				return result
			}
		}
	}

	result.ResponseTime = time.Since(startTime)
	return result
}

// enrich runs the optional tier 1-2 modules against a live result. Active
// modules (probes, templates, ports) require the host to be in the authorized
// scope; otherwise they are skipped and recorded.
func (s *Scanner) enrich(ctx context.Context, result *models.Result, body string, headers http.Header, baseRoot, host string) {
	cfg := s.config

	if cfg.DetectTech || cfg.EnableVuln {
		if td := detector.DetectWithVersions(body, headers); len(td) > 0 {
			result.TechDetails = td
		}
	}
	if cfg.EnableVuln {
		for _, f := range vuln.Match(result.TechDetails) {
			result.AddFinding(f)
		}
	}
	if cfg.EnableSecrets {
		for _, f := range secrets.Scan(body, baseRoot) {
			result.AddFinding(f)
		}
	}
	if cfg.EnableCrawl {
		s.crawlAndScan(ctx, result, baseRoot)
	}
	if cfg.EnableDNSRecords && !cfg.SkipDNS {
		result.DNSRecords = dnsx.Lookup(ctx, host, cfg.Timeout)
	}

	if cfg.EnableProbes || cfg.EnableTemplates || cfg.EnablePorts {
		if s.scope == nil || !s.scope.InScope(host) {
			s.scope.Log("skip-out-of-scope", host, "active scan requested but host not in scope")
			s.sortFindings(result)
			return
		}
	}

	if cfg.EnableProbes {
		s.scope.Log("probe", host, baseRoot)
		for _, f := range probe.Run(ctx, baseRoot, probe.Options{
			Client: s.client, UserAgent: cfg.UserAgent, Limiter: s.limiter,
		}) {
			result.AddFinding(f)
		}
	}
	if cfg.EnableTemplates && s.engine != nil {
		s.scope.Log("templates", host, baseRoot)
		for _, f := range s.engine.Run(ctx, baseRoot, signature.RunOptions{
			Client: s.client, UserAgent: cfg.UserAgent, Limiter: s.limiter,
		}) {
			result.AddFinding(f)
		}
	}
	if cfg.EnableFuzz {
		s.scope.Log("content-discovery", host, baseRoot)
		fFindings, endpoints := discovery.Run(ctx, baseRoot, discovery.Options{
			Client: s.client, UserAgent: cfg.UserAgent, Limiter: s.limiter,
		})
		for _, f := range fFindings {
			result.AddFinding(f)
		}
		result.Endpoints = appendUnique(result.Endpoints, endpoints...)
	}
	if cfg.EnablePorts {
		s.scope.Log("portscan", host, cfg.PortSpec)
		open := portscan.Scan(ctx, host, portscan.ParsePorts(cfg.PortSpec), 50, 2*time.Second, cfg.Aggressive)
		result.OpenPorts = open
		for _, f := range riskyPortFindings(host, open) {
			result.AddFinding(f)
		}
	}

	s.sortFindings(result)
}

func (s *Scanner) crawlAndScan(ctx context.Context, result *models.Result, baseRoot string) {
	pages := crawler.Crawl(ctx, baseRoot, crawler.Options{
		Client:    s.client,
		UserAgent: s.config.UserAgent,
		Depth:     s.config.CrawlDepth,
		MaxPages:  s.config.MaxPages,
		Limiter:   s.limiter,
	})
	seen := make(map[string]bool)
	for _, f := range result.Findings {
		seen[f.ID+"|"+f.Location] = true
	}
	for _, pg := range pages {
		result.Endpoints = appendUnique(result.Endpoints, pg.URL)
		if s.config.EnableSecrets {
			for _, f := range secrets.Scan(pg.Body, pg.URL) {
				key := f.ID + "|" + f.Location
				if !seen[key] {
					seen[key] = true
					result.AddFinding(f)
				}
			}
		}
	}
}

func appendUnique(dst []string, items ...string) []string {
	seen := make(map[string]bool, len(dst))
	for _, d := range dst {
		seen[d] = true
	}
	for _, it := range items {
		if it != "" && !seen[it] {
			seen[it] = true
			dst = append(dst, it)
		}
	}
	return dst
}

func (s *Scanner) sortFindings(result *models.Result) {
	sort.SliceStable(result.Findings, func(i, j int) bool {
		return result.Findings[i].Severity.Rank() > result.Findings[j].Severity.Rank()
	})
}

var riskyServices = map[int]struct {
	name     string
	severity models.Severity
}{
	23:    {"telnet", models.SeverityMedium},
	445:   {"SMB", models.SeverityMedium},
	2049:  {"NFS", models.SeverityMedium},
	3306:  {"MySQL", models.SeverityMedium},
	3389:  {"RDP", models.SeverityMedium},
	5432:  {"PostgreSQL", models.SeverityMedium},
	5601:  {"Kibana", models.SeverityMedium},
	5900:  {"VNC", models.SeverityMedium},
	6379:  {"Redis", models.SeverityHigh},
	9200:  {"Elasticsearch", models.SeverityHigh},
	11211: {"Memcached", models.SeverityHigh},
	15672: {"RabbitMQ", models.SeverityMedium},
	27017: {"MongoDB", models.SeverityHigh},
}

func riskyPortFindings(host string, open []models.Port) []models.Finding {
	var findings []models.Finding
	for _, p := range open {
		if svc, ok := riskyServices[p.Port]; ok {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("exposed-%s", strings.ToLower(svc.name)),
				Title:       fmt.Sprintf("Exposed %s service", svc.name),
				Severity:    svc.severity,
				Source:      "port",
				Description: fmt.Sprintf("%s is reachable on %s:%d and should not be exposed to untrusted networks.", svc.name, host, p.Port),
				Location:    fmt.Sprintf("%s:%d", host, p.Port),
				Tags:        []string{"exposed-service"},
			})
		}
	}
	return findings
}

func rootAndHost(finalURL, domain string) (baseRoot, host string) {
	baseRoot = finalURL
	host = domain
	if u, err := url.Parse(finalURL); err == nil && u.Host != "" {
		baseRoot = u.Scheme + "://" + u.Host
		host = u.Hostname()
	}
	return baseRoot, host
}

// ScanDomains scans multiple domains concurrently.
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
		go func() {
			defer wg.Done()
			var ctxOpts []chromedp.ContextOption
			if !s.config.LogVerbose {
				// Chrome newer than the pinned cdproto emits cookie-partition
				// events the library can't decode; those are non-fatal, so
				// suppress the noisy per-event log lines unless verbose.
				silent := func(string, ...interface{}) {}
				ctxOpts = append(ctxOpts,
					chromedp.WithLogf(silent),
					chromedp.WithErrorf(silent),
					chromedp.WithDebugf(silent),
				)
			}
			browserCtx, cancel := chromedp.NewContext(allocCtx, ctxOpts...)
			defer cancel()

			for {
				select {
				case domain, ok := <-workCh:
					if !ok {
						return
					}
					resultCh <- s.ScanDomain(ctx, domain, browserCtx)
					if bar != nil {
						_ = bar.Add(1)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(workCh)
		for _, domain := range domains {
			select {
			case workCh <- domain:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultCh)
		if bar != nil {
			_ = bar.Finish()
		}
	}()

	var results []*models.Result
	for result := range resultCh {
		results = append(results, result)
	}
	return results, nil
}

// CheckSecurityHeaders analyzes security headers in an HTTP response.
func CheckSecurityHeaders(resp *http.Response, result *models.Result) {
	result.SecurityInfo.HasHTTPS = strings.HasPrefix(resp.Request.URL.String(), "https://")

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

	securityFlags := []string{}
	for _, header := range securityHeaders {
		if value := resp.Header.Get(header); value != "" {
			result.SecurityInfo.SecurityHeaders[header] = value
			securityFlags = append(securityFlags, header)
		}
	}
	if resp.Header.Get("Strict-Transport-Security") != "" {
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

const maxBodyBytes = 5 << 20 // cap body read for tech/content analysis at 5 MiB

// readBody reads up to limit bytes from r and returns it as a string. A partial
// read (including on error) is returned as-is, which is fine for analysis.
func readBody(r io.Reader, limit int64) string {
	if r == nil {
		return ""
	}
	data, _ := io.ReadAll(io.LimitReader(r, limit))
	return string(data)
}
