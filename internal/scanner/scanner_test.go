package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
	"github.com/Sla0ui/scanera/internal/scope"
)

func testConfig() *models.Config {
	cfg := models.DefaultConfig()
	cfg.SkipBrowser = true
	cfg.Quiet = true
	cfg.NoProgress = true
	cfg.Timeout = 2 * time.Second
	cfg.RetryCount = 0
	cfg.OutputDir = "unused"
	return cfg
}

// target strips the scheme so the scanner tries https:// then http:// like it
// would for a real domain.
func target(srv *httptest.Server) string {
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestScanDomainActiveWithZeroRetries(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title> Acme &amp; Co </title></head><body>hi</body></html>"))
	}))
	defer srv.Close()

	s, err := New(testConfig()) // RetryCount 0 used to mean zero attempts
	if err != nil {
		t.Fatal(err)
	}
	r := s.ScanDomain(context.Background(), target(srv), nil)
	if !r.Active || r.StatusCode != 200 {
		t.Fatalf("expected active 200, got active=%v status=%d err=%v", r.Active, r.StatusCode, r.Error)
	}
	if r.Title != "Acme & Co" {
		t.Errorf("title = %q", r.Title)
	}
	if hits.Load() != 1 {
		t.Errorf("expected exactly one request, got %d", hits.Load())
	}
}

func TestScanDomainInactiveExplainsWhy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s, _ := New(testConfig())
	r := s.ScanDomain(context.Background(), target(srv), nil)
	if r.Active {
		t.Fatal("404 should not be active")
	}
	if r.Error == nil || !strings.Contains(r.Error.Error(), "returned HTTP 404") {
		t.Errorf("inactive result should say why, got %v", r.Error)
	}
}

func TestActiveModulesRespectScope(t *testing.T) {
	var discoveryHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			discoveryHits.Add(1)
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("<title>home</title>"))
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.EnableFuzz = true // fuzz alone used to bypass the per-host scope check

	outOfScope, err := scope.FromEntries("other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := New(cfg)
	s.UseScope(outOfScope)
	r := s.ScanDomain(context.Background(), target(srv), nil)
	if !r.Active || !r.SkippedActive {
		t.Fatalf("expected active result with active modules skipped, got active=%v skipped=%v", r.Active, r.SkippedActive)
	}
	if n := discoveryHits.Load(); n != 0 {
		t.Fatalf("content discovery sent %d requests to an out-of-scope host", n)
	}

	inScope, _ := scope.FromEntries("127.0.0.1")
	s.UseScope(inScope)
	r = s.ScanDomain(context.Background(), target(srv), nil)
	if r.SkippedActive || discoveryHits.Load() == 0 {
		t.Fatal("in-scope host should be fuzzed")
	}
}

func TestSecurityCheckOnPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "Apache/2.4.49 (Unix)")
		_, _ = w.Write([]byte("<title>x</title>"))
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.CheckSecurity = true
	s, _ := New(cfg)
	r := s.ScanDomain(context.Background(), target(srv), nil)

	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.ID] = true
	}
	for _, id := range []string{"no-https", "missing-csp", "version-disclosure"} {
		if !got[id] {
			t.Errorf("expected %s finding, got %v", id, got)
		}
	}
	if got["missing-hsts"] {
		t.Error("HSTS shouldn't be expected on plain HTTP")
	}
	// Findings come out worst first.
	for i := 1; i < len(r.Findings); i++ {
		if r.Findings[i].Severity.Rank() > r.Findings[i-1].Severity.Rank() {
			t.Fatalf("findings not sorted by severity: %+v", r.Findings)
		}
	}
}

func TestScanDomainsKeepsInputOrderAndReportsEach(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>ok</title>"))
	}))
	defer srv.Close()
	host := target(srv)
	port := host[strings.LastIndex(host, ":"):]

	cfg := testConfig()
	cfg.MaxConcurrentChecks = 4
	cfg.SkipDNS = true
	s, _ := New(cfg)

	domains := []string{"127.0.0.1" + port, "localhost" + port, "[::1]" + port, "127.0.0.2" + port}
	var mu sync.Mutex
	seen := map[string]bool{}
	s.OnResult(func(r *models.Result) {
		mu.Lock()
		seen[r.Domain] = true
		mu.Unlock()
	})
	results, err := s.ScanDomains(context.Background(), domains)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(domains) {
		t.Fatalf("got %d results for %d domains", len(results), len(domains))
	}
	for i, r := range results {
		if r.Domain != domains[i] {
			t.Errorf("result %d is %s, want %s", i, r.Domain, domains[i])
		}
		if !seen[r.Domain] {
			t.Errorf("OnResult not called for %s", r.Domain)
		}
	}
}

func TestScanDomainsSkipsInterruptedDomains(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	cfg := testConfig()
	cfg.SkipDNS = true
	s, _ := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	results, _ := s.ScanDomains(ctx, []string{target(srv)})
	if len(results) != 0 {
		t.Fatalf("an interrupted domain must not be reported (it would be marked done on resume), got %+v", results[0])
	}
}

func TestErrorPageTitle(t *testing.T) {
	for title, want := range map[string]bool{
		"404 Not Found":                     true,
		"403 - Forbidden: Access is denied": true,
		"Error":                             true,
		"Domain is for sale!":               true,
		"502 Bad Gateway":                   true,
		"Error Tracking Software | Acme":    false,
		"Forbidden Planet - Comics":         false,
		"Unavailable Rooms Finder":          false,
		"Welcome":                           false,
	} {
		if got := errorPageTitle(title); got != want {
			t.Errorf("errorPageTitle(%q) = %v, want %v", title, got, want)
		}
	}
}

func TestScreenshotName(t *testing.T) {
	if got := screenshotName("[::1]:8443"); got != "___1__8443.png" {
		t.Errorf("screenshotName = %q", got)
	}
	if got := screenshotName("www.example.com"); got != "www.example.com.png" {
		t.Errorf("screenshotName = %q", got)
	}
}

func TestRetryPolicy(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("<title>plain http</title>"))
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.RetryCount = 2
	s, _ := New(cfg)

	// HTTPS against a plain-HTTP port fails the same way every time; it must
	// not be retried with backoff.
	start := time.Now()
	if _, err := s.fetch(context.Background(), "https://"+target(srv)); err == nil {
		t.Fatal("expected a TLS error")
	}
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Errorf("deterministic TLS failure took %v; it was retried", d)
	}

	// A refused connection isn't retried either.
	addr := srv.Listener.Addr().String()
	srv.Close()
	start = time.Now()
	if _, err := s.fetch(context.Background(), "http://"+addr); err == nil {
		t.Fatal("expected connection refused")
	}
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Errorf("refused connection took %v; it was retried", d)
	}
}

func TestActiveRedirectsStayInScope(t *testing.T) {
	var offScopeHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offScopeHits.Add(1)
		_, _ = w.Write([]byte("APP_KEY=x\nDB_PASSWORD=y\n"))
	}))
	defer other.Close()
	// Same listener, but addressed by a name the scope doesn't cover.
	otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)

	inScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("<title>home</title>"))
			return
		}
		http.Redirect(w, r, otherURL+r.URL.Path, http.StatusFound)
	}))
	defer inScope.Close()

	cfg := testConfig()
	cfg.EnableProbes = true
	sc, _ := scope.FromEntries("127.0.0.1")
	s, _ := New(cfg)
	s.UseScope(sc)
	r := s.ScanDomain(context.Background(), target(inScope), nil)
	if !r.Active {
		t.Fatalf("expected the in-scope host to be active: %v", r.Error)
	}
	if n := offScopeHits.Load(); n != 0 {
		t.Fatalf("active probes followed redirects to an out-of-scope host %d times", n)
	}
	for _, f := range r.Findings {
		if f.Source == "probe" {
			t.Errorf("unexpected probe finding from a blocked redirect: %+v", f)
		}
	}
}
