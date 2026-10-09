package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
)

func writeProfile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyOverlaysOnlyPresentKeys(t *testing.T) {
	cfg := models.DefaultConfig()
	path := writeProfile(t, `
concurrency: 20
timeout: 5s
dns: true
crawl: true
max_pages: 10
status_codes: [200, 301]
fail_on: high
`)
	if err := Apply(path, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConcurrentChecks != 20 || cfg.Timeout != 5*time.Second {
		t.Errorf("basic overrides not applied: %+v", cfg)
	}
	if !cfg.EnableDNSRecords || !cfg.EnableCrawl || cfg.MaxPages != 10 {
		t.Error("feature overrides not applied")
	}
	if len(cfg.SuccessStatusCodes) != 2 || cfg.FailOn != models.SeverityHigh {
		t.Error("status codes / fail_on not applied")
	}
	// Untouched keys keep their defaults.
	if !cfg.VerifyTLS || cfg.RetryCount != 2 {
		t.Error("absent keys should not change the config")
	}
}

func TestApplyRejectsUnknownKeys(t *testing.T) {
	path := writeProfile(t, "concurrency: 5\nsubdomian: true\n")
	err := Apply(path, models.DefaultConfig())
	if err == nil || !strings.Contains(err.Error(), "subdomian") {
		t.Fatalf("expected an unknown-key error, got %v", err)
	}
}

func TestApplyRejectsAuthorize(t *testing.T) {
	path := writeProfile(t, "authorize: true\n")
	if err := Apply(path, models.DefaultConfig()); err == nil {
		t.Fatal("authorization must not be settable from a profile")
	}
}

func TestApplyEmptyProfile(t *testing.T) {
	path := writeProfile(t, "# nothing here\n")
	if err := Apply(path, models.DefaultConfig()); err != nil {
		t.Fatalf("empty profile should be fine: %v", err)
	}
}

func TestShippedExampleProfilesParse(t *testing.T) {
	matches, _ := filepath.Glob("../../examples/profiles/*.yaml")
	if len(matches) == 0 {
		t.Skip("no example profiles found")
	}
	for _, m := range matches {
		if err := Apply(m, models.DefaultConfig()); err != nil {
			t.Errorf("%s: %v", m, err)
		}
	}
}
