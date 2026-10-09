package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Sla0ui/scanera/internal/models"
)

// spaShell mimics a single-page app that serves its index for every path. It
// deliberately contains the strings the old matchers keyed on.
const spaShell = `<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta name="keywords" content="token, secret, password, api key">
<meta name="csrf-token" content="abc=def">
<title>Acme</title>
</head>
<body>
<div id="app">[core] repositoryformatversion svn:// Contact: support@example.com</div>
<script>window.CONFIG={DB_HOST:"x", API_KEY:"y"};</script>
</body>
</html>`

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func run(t *testing.T, srv *httptest.Server) []models.Finding {
	t.Helper()
	return Run(context.Background(), srv.URL, Options{Client: srv.Client(), UserAgent: "test"})
}

func TestRunCatchAllHTMLHasNoFindings(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(spaShell))
	})
	if f := run(t, srv); len(f) != 0 {
		t.Fatalf("catch-all SPA produced findings: %+v", f)
	}
}

func TestRunCatchAllWithoutContentTypeHasNoFindings(t *testing.T) {
	// Some servers omit or mislabel the content type; the leading tag gives it away.
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("\n  " + spaShell))
	})
	if f := run(t, srv); len(f) != 0 {
		t.Fatalf("mislabelled catch-all produced findings: %+v", f)
	}
}

func TestRunExposedDotenv(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.env" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("APP_NAME=demo\nAPP_ENV=production\nexport DB_PASSWORD=hunter2\n"))
	})
	f := run(t, srv)
	if len(f) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", f)
	}
	if f[0].ID != "exposed-dotenv" || f[0].Severity != models.SeverityCritical {
		t.Fatalf("expected critical exposed-dotenv, got %+v", f[0])
	}
}

func TestRunDotenvWithoutSecretsIgnored(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.env" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("hello = world, this is a KEYNOTE page\n"))
	})
	if f := run(t, srv); len(f) != 0 {
		t.Fatalf("non-dotenv body should not match: %+v", f)
	}
}

func TestRunExposedGitConfig(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.git/config" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"))
	})
	f := run(t, srv)
	if len(f) != 1 || f[0].ID != "exposed-git-config" || f[0].Severity != models.SeverityHigh {
		t.Fatalf("expected one high exposed-git-config, got %+v", f)
	}
}

func TestLooksLikeSVNEntries(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{"10\n\ndir\n0\nhttp://svn.example.com/repo/trunk\n", true},
		{"8\n\ndir\n12\nsvn://svn.example.com/repo\n", true},
		{"12\n", true},
		{"The directory listing is disabled.", false},
		{"<html dir=\"ltr\"></html>", false},
		{"0\n", false},
	}
	for _, c := range cases {
		if got := looksLikeSVNEntries(http.StatusOK, c.body, nil); got != c.want {
			t.Errorf("looksLikeSVNEntries(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}

func TestSecurityTxtID(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/security.txt" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n"))
	})
	f := run(t, srv)
	if len(f) != 1 || f[0].ID != "security-txt" {
		t.Fatalf("expected one security-txt finding, got %+v", f)
	}
}

func TestEvidenceNeverCopiesSecrets(t *testing.T) {
	env := "APP_ENV=production\nDB_PASSWORD=" + "hunter" + "2\nexport API_KEY=abc123\n"
	got := evidence("exposed-dotenv", env)
	if got != "variables: APP_ENV, DB_PASSWORD, API_KEY" {
		t.Errorf("dotenv evidence = %q", got)
	}

	gitCfg := "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://deploy:" + "ghp_" + "x1y2z3" + "@github.com/acme/app.git\n\ttoken = s3cr3t\n"
	got = evidence("exposed-git-config", gitCfg)
	if strings.Contains(got, "x1y2z3") || strings.Contains(got, "deploy:") || strings.Contains(got, "s3cr3t") {
		t.Errorf("credentials leaked into evidence: %q", got)
	}
	if !strings.Contains(got, "https://****@github.com/acme/app.git") {
		t.Errorf("expected redacted remote URL, got %q", got)
	}

	long := strings.Repeat("é", 120) // 240 bytes of two-byte runes
	if s := snippet(long); !utf8.ValidString(s) {
		t.Errorf("snippet split a rune: %q", s)
	}
}
