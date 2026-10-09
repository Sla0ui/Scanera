package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sla0ui/scanera/internal/models"
)

func TestCleanDomain(t *testing.T) {
	cases := map[string]string{
		"example.com":                      "example.com",
		"  Example.COM.  ":                 "example.com",
		"HTTPS://www.example.com/path?q=1": "www.example.com",
		"http://user:pw@example.com:8080/": "example.com:8080",
		"example.com:443":                  "example.com:443",
		"10.0.0.1":                         "10.0.0.1",
		"[2001:db8::1]:8443":               "[2001:db8::1]:8443",
		"2001:db8::1":                      "[2001:db8::1]",
		"example.com#frag":                 "example.com",
		"example.com:99999":                "",
		"exa mple.com":                     "",
		"":                                 "",
		"not:an:ip":                        "",
	}
	for in, want := range cases {
		if got := cleanDomain(in); got != want {
			t.Errorf("cleanDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadDomainsDedupesAndCountsSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.txt")
	body := "# targets\nexample.com\nEXAMPLE.com\nhttps://example.com/\n\nbad host\napi.example.com\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, skipped, err := readDomains(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"example.com", "api.example.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("readDomains = %v, want %v", got, want)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

func TestCountAtOrAbove(t *testing.T) {
	results := []*models.Result{
		{Findings: []models.Finding{{Severity: "high"}, {Severity: "low"}}},
		{Findings: []models.Finding{{Severity: "Critical"}, {Severity: "info"}}},
	}
	if n := countAtOrAbove(results, models.SeverityHigh); n != 2 {
		t.Errorf("high+ = %d, want 2", n)
	}
	if n := countAtOrAbove(results, models.SeverityInfo); n != 4 {
		t.Errorf("info+ = %d, want 4", n)
	}
}

func TestLoadWordlist(t *testing.T) {
	if w, err := loadWordlist(""); err != nil || w != nil {
		t.Errorf("empty path should mean built-in list, got %v %v", w, err)
	}
	if _, err := loadWordlist(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Error("a missing wordlist must be an error, not a silent fallback")
	}
}

func TestMergeInOrder(t *testing.T) {
	carried := []*models.Result{{Domain: "a.com", Active: true}, {Domain: "c.com"}}
	fresh := []*models.Result{{Domain: "d.com"}, {Domain: "b.com", Active: true}}
	got := mergeInOrder([]string{"a.com", "b.com", "c.com", "d.com"}, carried, fresh)
	var order []string
	for _, r := range got {
		order = append(order, r.Domain)
	}
	if want := []string{"a.com", "b.com", "c.com", "d.com"}; !reflect.DeepEqual(order, want) {
		t.Errorf("merge order = %v, want %v", order, want)
	}
}

func TestPriorResults(t *testing.T) {
	dir := t.TempDir()
	if got, err := priorResults(filepath.Join(dir, "none.json"), map[string]bool{"a.com": true}); err != nil || got != nil {
		t.Errorf("missing file should carry nothing, got %v %v", got, err)
	}
	path := filepath.Join(dir, "scan_results.json")
	body := `[{"domain":"a.com","active":true},{"domain":"b.com","active":false,"error":"timeout"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := priorResults(path, map[string]bool{"b.com": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Domain != "b.com" || got[0].Error == nil || got[0].Error.Error() != "timeout" {
		t.Errorf("priorResults = %+v", got)
	}
}
