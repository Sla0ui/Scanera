package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Sla0ui/scanera/internal/analyzer"
	"github.com/Sla0ui/scanera/internal/crawler"
	"github.com/Sla0ui/scanera/internal/detector"
	"github.com/Sla0ui/scanera/internal/discovery"
	"github.com/Sla0ui/scanera/internal/dnsx"
	"github.com/Sla0ui/scanera/internal/models"
	"github.com/Sla0ui/scanera/internal/netx"
	"github.com/Sla0ui/scanera/internal/portscan"
	"github.com/Sla0ui/scanera/internal/posture"
	"github.com/Sla0ui/scanera/internal/probe"
	"github.com/Sla0ui/scanera/internal/ratelimit"
	"github.com/Sla0ui/scanera/internal/scope"
	"github.com/Sla0ui/scanera/internal/secrets"
	"github.com/Sla0ui/scanera/internal/signature"
	"github.com/Sla0ui/scanera/internal/takeover"
	"github.com/Sla0ui/scanera/internal/vuln"
	"github.com/chromedp/chromedp"
	"github.com/schollz/progressbar/v3"
)

// Scanner performs domain scanning operations.
type Scanner struct {
	config *models.Config
	client *http.Client
	// activeClient is used by modules that need authorization; its redirects
	// are confined to the scope.
	activeClient *http.Client
	limiter      *ratelimit.Limiter
	scope        *scope.Scope
	engine       *signature.Engine

	onResult func(*models.Result)
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
		config:       config,
		client:       client,
		activeClient: scopedClient(client, nil, config.MaxRedirects),
		limiter:      ratelimit.New(config.RateLimit),
	}, nil
}

// UseScope sets the authorization scope used to gate active scanning.
func (s *Scanner) UseScope(sc *scope.Scope) {
	s.scope = sc
	s.activeClient = scopedClient(s.client, sc, s.config.MaxRedirects)
}

// scopedClient shares base's transport but refuses to follow a redirect to a
// host outside sc, so an in-scope site can't bounce active probes elsewhere.
// A nil scope follows no redirects at all.
func scopedClient(base *http.Client, sc *scope.Scope, maxRedirects int) *http.Client {
	c := *base
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		if !sc.InScope(req.URL.Host) {
			sc.Log("redirect-blocked", req.URL.Hostname(), via[len(via)-1].URL.String()+" -> "+req.URL.String())
			return http.ErrUseLastResponse
		}
		return nil
	}
	return &c
}

// UseTemplates sets the signature engine used when templates are enabled.
func (s *Scanner) UseTemplates(e *signature.Engine) { s.engine = e }

// OnResult registers a callback invoked once per completed domain, in
// completion order, from a single goroutine. Use it to stream results or
// record resume progress as the scan runs.
func (s *Scanner) OnResult(fn func(*models.Result)) { s.onResult = fn }

// fetch performs a GET using the shared client, honoring the rate limiter and
// retrying transient failures RetryCount times.
func (s *Scanner) fetch(ctx context.Context, rawURL string) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt <= s.config.RetryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if err := s.limiter.Wait(ctx); err != nil {
			return nil, err
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
		if ctx.Err() != nil || !retryable(err) {
			break
		}
	}
	return nil, lastErr
}

// retryable reports whether a request error might succeed on another try.
// Failures that will repeat identically (bad certificate, unknown host,
// refused or unanswered connection, plain HTTP on the HTTPS port) are not
// retried: on large scans most HTTPS attempts against HTTP-only hosts fail
// this way, and backing off on each one adds seconds per domain.
func retryable(err error) bool {
	if _, ok := posture.CertErrorFinding(err, ""); ok {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return false
	}
	var recErr tls.RecordHeaderError
	if errors.As(err, &recErr) || errors.Is(err, http.ErrSchemeMismatch) {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" && opErr.Timeout() {
		return false // the kernel already retransmitted SYNs for the whole timeout
	}
	return true
}

// ScanDomain checks a single domain. domain may carry a port (host:port).
func (s *Scanner) ScanDomain(ctx context.Context, domain string, browserCtx context.Context) *models.Result {
	startTime := time.Now()
	cfg := s.config
	host := hostOnly(domain)

	result := &models.Result{
		Domain:      domain,
		LastChecked: startTime,
		ServerInfo:  models.ServerInfo{Headers: make(map[string]string)},
		SecurityInfo: models.SecurityInfo{
			SecurityHeaders: make(map[string]string),
		},
	}
	defer s.sortFindings(result)

	if err := ctx.Err(); err != nil {
		result.Error = err
		return result
	}

	if !cfg.SkipDNS {
		ips, err := ResolveDomain(ctx, host, cfg.Timeout)
		if err != nil {
			result.Error = fmt.Errorf("domain not resolvable: %w", err)
			if cfg.EnableTakeover && net.ParseIP(host) == nil {
				if cname, ok := dnsx.CNAME(ctx, host, cfg.Timeout); ok {
					if f, ok := takeover.CheckDangling(host, cname); ok {
						result.AddFinding(f)
					}
				}
			}
			result.ResponseTime = time.Since(startTime)
			return result
		}
		result.IPAddresses = ips
	}

	schemes := []string{"https://", "http://"}
	if cfg.ForceHTTPS {
		schemes = schemes[:1]
	}

	var failures []string
	enriched, takeoverChecked := false, false
	for _, scheme := range schemes {
		reqStart := time.Now()
		resp, err := s.fetch(ctx, scheme+domain)
		if err != nil {
			failures = append(failures, err.Error())
			if scheme == "https://" && cfg.CheckSecurity {
				if f, ok := posture.CertErrorFinding(err, scheme+domain); ok {
					result.AddFinding(f)
				}
			}
			continue
		}

		body := readBody(resp.Body, maxBodyBytes)
		resp.Body.Close()

		result.ResponseTime = time.Since(reqStart)
		result.StatusCode = resp.StatusCode
		result.FinalURL = resp.Request.URL.String()
		result.RedirectTo = ""
		if finalHost := resp.Request.URL.Hostname(); !strings.EqualFold(finalHost, host) {
			result.RedirectTo = finalHost
		}
		ExtractServerInfo(resp, result)
		if result.ServerInfo.ResponseSize == 0 && int64(len(body)) < maxBodyBytes {
			result.ServerInfo.ResponseSize = int64(len(body))
		}
		if t := extractTitle(body); t != "" {
			result.Title = t
		}
		if resp.Request.URL.Scheme == "https" {
			result.SecurityInfo.HasHTTPS = true
		}

		if cfg.EnableTakeover && !takeoverChecked && net.ParseIP(host) == nil {
			takeoverChecked = true
			if cname, ok := dnsx.CNAME(ctx, host, cfg.Timeout); ok {
				if f, ok := takeover.CheckResponse(host, cname, body); ok {
					result.AddFinding(f)
				}
			}
		}

		if !contains(cfg.SuccessStatusCodes, resp.StatusCode) {
			failures = append(failures, fmt.Sprintf("%s returned HTTP %d", result.FinalURL, resp.StatusCode))
			continue
		}

		if !enriched {
			enriched = true
			if cfg.CheckSecurity || cfg.IncludeCertInfo {
				s.assessSecurity(ctx, resp, result, domain)
			}
			if cfg.DetectTech {
				detector.DetectTechnologies(body, resp.Header, result)
			}
			if cfg.AnalyzeContent {
				analyzer.AnalyzePageContent(body, result)
			}
			baseRoot, finalHost := rootAndHost(result.FinalURL, host)
			s.enrich(ctx, result, body, resp.Header, baseRoot, finalHost)
		}

		if cfg.SkipBrowser {
			result.Active = true
			return result
		}
		err = PerformBrowserCheck(ctx, result.FinalURL, browserCtx, result, cfg)
		if err == nil {
			result.Active = true
			return result
		}
		failures = append(failures, "browser check: "+err.Error())
	}

	if result.Error == nil && len(failures) > 0 {
		result.Error = errors.New(strings.Join(failures, "; "))
	}
	result.ResponseTime = time.Since(startTime)
	return result
}

// assessSecurity records security headers and certificate details from the
// accepted response and, with --security-check, turns them into findings.
func (s *Scanner) assessSecurity(ctx context.Context, resp *http.Response, result *models.Result, domain string) {
	cfg := s.config
	now := time.Now()
	sec := &result.SecurityInfo

	var present []string
	for _, h := range []string{
		"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
		"X-Frame-Options", "X-XSS-Protection", "Referrer-Policy", "Feature-Policy", "Permissions-Policy",
	} {
		if v := resp.Header.Get(h); v != "" {
			sec.SecurityHeaders[h] = v
			present = append(present, h)
		}
	}
	result.ServerInfo.SecurityFlags = present
	sec.HSTSEnabled = resp.Header.Get("Strict-Transport-Security") != ""

	if d, ok := posture.InspectTLS(resp.TLS, resp.Request.URL.Hostname(), now); ok {
		sec.TLSVersion = d.Version
		sec.ValidCert = d.Valid
		sec.CertIssuer = d.Issuer
		sec.CertSubject = d.Subject
		sec.CertDNSNames = d.DNSNames
		sec.CertExpiry = d.NotAfter
		if d.VerifyErr != nil {
			sec.CertError = d.VerifyErr.Error()
		}
		if cfg.CheckSecurity {
			for _, f := range posture.TLSFindings(d, result.FinalURL, now) {
				result.AddFinding(f)
			}
		}
	}

	if !cfg.CheckSecurity {
		return
	}
	for _, f := range posture.Headers(resp) {
		result.AddFinding(f)
	}

	switch resp.Request.URL.Scheme {
	case "http":
		if !cfg.ForceHTTPS {
			result.AddFinding(models.Finding{
				ID: "no-https", Title: "Site served over plain HTTP", Severity: models.SeverityMedium,
				Source: "tls", Location: result.FinalURL, Tags: []string{"tls"},
				Description: "The site was only reachable without TLS, so traffic to it can be read and modified in transit.",
			})
		}
	case "https":
		// See whether plain HTTP upgrades visitors or serves the site
		// unencrypted. Skipped with --force-https (no plain-HTTP traffic at
		// all) and for host:port targets, whose HTTP port can't be guessed.
		if _, _, err := net.SplitHostPort(domain); cfg.ForceHTTPS || err == nil {
			return
		}
		if r, err := s.fetch(ctx, "http://"+domain); err == nil {
			r.Body.Close()
			sec.HTTPSRedirect = r.Request.URL.Scheme == "https" || redirectsToHTTPS(r)
			if !sec.HTTPSRedirect && r.StatusCode < 400 {
				result.AddFinding(models.Finding{
					ID: "http-not-redirected", Title: "Plain HTTP not redirected to HTTPS", Severity: models.SeverityLow,
					Source: "tls", Location: r.Request.URL.String(), Tags: []string{"tls"},
					Evidence:    fmt.Sprintf("HTTP %d", r.StatusCode),
					Description: "Visitors who type the bare hostname stay on an unencrypted connection.",
				})
			}
		}
	}
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
			if f.Location == "" {
				f.Location = baseRoot
			}
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

	if !cfg.ActiveScanRequested() {
		return
	}
	// Every active module, content discovery included, needs the final host to
	// be in scope; a redirect can land somewhere the operator never authorized.
	if !s.scope.InScope(host) {
		s.scope.Log("skip-out-of-scope", host, "active scan requested but host not in scope")
		result.SkippedActive = true
		return
	}

	if cfg.EnableProbes {
		s.scope.Log("probe", host, baseRoot)
		for _, f := range probe.Run(ctx, baseRoot, probe.Options{
			Client: s.activeClient, UserAgent: cfg.UserAgent, Limiter: s.limiter,
		}) {
			result.AddFinding(f)
		}
	}
	if cfg.EnableTemplates && s.engine != nil {
		s.scope.Log("templates", host, baseRoot)
		for _, f := range s.engine.Run(ctx, baseRoot, signature.RunOptions{
			Client: s.activeClient, UserAgent: cfg.UserAgent, Limiter: s.limiter,
			Allow: s.scope.InScope,
		}) {
			result.AddFinding(f)
		}
	}
	if cfg.EnableFuzz {
		s.scope.Log("content-discovery", host, baseRoot)
		fFindings, endpoints := discovery.Run(ctx, baseRoot, discovery.Options{
			Client: s.activeClient, UserAgent: cfg.UserAgent, Limiter: s.limiter,
		})
		reported := make(map[string]bool, len(result.Findings))
		for _, f := range result.Findings {
			reported[f.Location] = true
		}
		for _, f := range fFindings {
			// A probe or template already explained this URL in more detail.
			if !reported[f.Location] {
				result.AddFinding(f)
			}
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

// redirectsToHTTPS catches a redirect the client stopped following because
// of the redirect cap: the response is still a 3xx on plain HTTP, but it does
// point at HTTPS.
func redirectsToHTTPS(r *http.Response) bool {
	if r.StatusCode < 300 || r.StatusCode >= 400 {
		return false
	}
	loc, err := r.Location()
	return err == nil && loc.Scheme == "https"
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

func rootAndHost(finalURL, fallbackHost string) (baseRoot, host string) {
	baseRoot = finalURL
	host = fallbackHost
	if u, err := url.Parse(finalURL); err == nil && u.Host != "" {
		baseRoot = u.Scheme + "://" + u.Host
		host = u.Hostname()
	}
	return baseRoot, host
}

// ScanDomains scans multiple domains concurrently and returns results in the
// input order. Domains not finished before ctx is cancelled are left out, so
// an interrupted run never reports them as inactive or marks them done.
func (s *Scanner) ScanDomains(ctx context.Context, domains []string) ([]*models.Result, error) {
	allocCtx := context.Background()
	if !s.config.SkipBrowser {
		var allocCancel context.CancelFunc
		allocCtx, allocCancel = SetupBrowserContext(s.config)
		defer allocCancel()
	}
	return s.processDomainsWithPool(ctx, domains, allocCtx)
}

type job struct {
	index  int
	domain string
}

type done struct {
	index  int
	result *models.Result
}

func (s *Scanner) processDomainsWithPool(ctx context.Context, domains []string, allocCtx context.Context) ([]*models.Result, error) {
	numWorkers := s.config.MaxConcurrentChecks
	if numWorkers > len(domains) {
		numWorkers = len(domains)
	}
	workCh := make(chan job)
	resultCh := make(chan done)

	var bar *progressbar.ProgressBar
	if !s.config.Quiet && !s.config.NoProgress && len(domains) > 0 {
		bar = progressbar.NewOptions(len(domains),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionSetWidth(50),
			progressbar.OptionSetDescription("[cyan]Processing domains[reset]"),
			progressbar.OptionOnCompletion(func() { fmt.Fprintln(os.Stderr) }),
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
			browserCtx := allocCtx
			if !s.config.SkipBrowser {
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
				var cancel context.CancelFunc
				browserCtx, cancel = chromedp.NewContext(allocCtx, ctxOpts...)
				defer cancel()
			}

			for j := range workCh {
				r := s.ScanDomain(ctx, j.domain, browserCtx)
				if ctx.Err() != nil {
					return // interrupted mid-scan; the result is incomplete
				}
				select {
				case resultCh <- done{j.index, r}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(workCh)
		for i, domain := range domains {
			select {
			case workCh <- job{i, domain}:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	ordered := make([]*models.Result, len(domains))
	for d := range resultCh {
		ordered[d.index] = d.result
		if s.onResult != nil {
			s.onResult(d.result)
		}
		if bar != nil {
			_ = bar.Add(1)
		}
	}
	if bar != nil && ctx.Err() == nil {
		_ = bar.Finish()
	}

	results := make([]*models.Result, 0, len(domains))
	for _, r := range ordered {
		if r != nil {
			results = append(results, r)
		}
	}
	return results, nil
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
