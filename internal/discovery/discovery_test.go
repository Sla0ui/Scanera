package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sla0ui/scanera/internal/models"
)

func TestInteresting(t *testing.T) {
	const tol = 64
	// Proper 404 baseline: any 200/401/403 is interesting.
	if !interesting(200, 500, 404, 0, tol) {
		t.Error("200 vs 404 baseline should be interesting")
	}
	if !interesting(403, 10, 404, 0, tol) {
		t.Error("403 vs 404 baseline should be interesting")
	}
	if interesting(404, 0, 404, 0, tol) {
		t.Error("404 should never be interesting")
	}
	// Soft-404 baseline (200 with fixed length): near-equal length is not interesting.
	if interesting(200, 1000, 200, 1000, tol) {
		t.Error("identical soft-404 length should not be interesting")
	}
	if !interesting(200, 5000, 200, 1000, tol) {
		t.Error("very different length from soft-404 should be interesting")
	}
	// Block-everything 403 baseline: the same 403 page is not interesting.
	if interesting(403, 120, 403, 118, tol) {
		t.Error("403 matching a 403 baseline should not be interesting")
	}
	if !interesting(403, 4000, 403, 118, tol) {
		t.Error("a distinctly different 403 page should be interesting")
	}
}

func TestTolerance(t *testing.T) {
	if got := tolerance("/abc", "/abc"); got != 64 {
		t.Errorf("equal paths: got %d want 64", got)
	}
	if got := tolerance("/a", "/abcdef"); got != 64+10 {
		t.Errorf("shorter path: got %d want 74", got)
	}
}

func runAgainst(t *testing.T, h http.HandlerFunc, paths []string) ([]models.Finding, []string) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return Run(context.Background(), srv.URL, Options{Client: srv.Client(), Paths: paths})
}

var testPaths = []string{"/admin", "/backup.zip", "/.env", "/config.php", "/login"}

func TestRunWAFBlocksEverything(t *testing.T) {
	f, d := runAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html><body>Request blocked by firewall.</body></html>"))
	}, testPaths)
	if len(f) != 0 || len(d) != 0 {
		t.Fatalf("everything-403 server should yield nothing, got %d findings %v", len(f), d)
	}
}

func TestRunOnlyAdminForbidden(t *testing.T) {
	f, d := runAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
			return
		}
		http.NotFound(w, r)
	}, testPaths)
	if len(f) != 1 || len(d) != 1 || !strings.HasSuffix(d[0], "/admin") {
		t.Fatalf("expected a single /admin finding, got %+v", f)
	}
	if f[0].Severity != models.SeverityLow {
		t.Errorf("admin path should be low severity, got %s", f[0].Severity)
	}
}

func TestRunCatchAll200(t *testing.T) {
	f, _ := runAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>" + strings.Repeat("app shell ", 200) + "</body></html>"))
	}, testPaths)
	if len(f) != 0 {
		t.Fatalf("catch-all 200 should yield nothing, got %+v", f)
	}
}

func TestRunCatchAllReflectingPath(t *testing.T) {
	// A soft-404 that echoes the requested path twice must not turn long paths
	// into findings just because the page grew.
	long := "/" + strings.Repeat("very-long-segment-", 7) + "end"
	f, _ := runAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>" + r.URL.Path + " not found</title><p>No page at " + r.URL.Path + ".</p>"))
	}, []string{long})
	if len(f) != 0 {
		t.Fatalf("path-reflecting soft-404 should yield nothing, got %+v", f)
	}
}

func TestRunRealFileOnSoft404Site(t *testing.T) {
	f, _ := runAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backup.zip" {
			_, _ = w.Write([]byte(strings.Repeat("PK\x03\x04", 1000)))
			return
		}
		_, _ = w.Write([]byte("<html><body>Home</body></html>"))
	}, testPaths)
	if len(f) != 1 || !strings.HasSuffix(f[0].Location, "/backup.zip") {
		t.Fatalf("expected the real backup.zip to stand out, got %+v", f)
	}
}

func TestSeverityFor(t *testing.T) {
	if severityFor("/.env", 200) != models.SeverityHigh {
		t.Error(".env 200 should be high")
	}
	if severityFor("/admin", 200) != models.SeverityLow {
		t.Error("admin should be low")
	}
	if severityFor("/random", 200) != models.SeverityInfo {
		t.Error("generic should be info")
	}
}

func TestPathsLoaded(t *testing.T) {
	if len(Paths()) < 50 {
		t.Errorf("expected a substantial path list, got %d", len(Paths()))
	}
}
