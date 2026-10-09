package vuln

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Sla0ui/scanera/internal/models"
)

func cves(findings []models.Finding) []string {
	var out []string
	for _, f := range findings {
		out = append(out, f.CVEs...)
	}
	return out
}

func hasCVE(findings []models.Finding, cve string) bool {
	for _, c := range cves(findings) {
		if c == cve {
			return true
		}
	}
	return false
}

func TestMatchKnownVulnerable(t *testing.T) {
	f := Match([]models.Tech{{Name: "jQuery", Version: "3.3.1"}})
	if len(f) == 0 {
		t.Fatal("expected a CVE match for jQuery 3.3.1")
	}
	if f[0].CVEs[0] != "CVE-2020-11022" {
		t.Errorf("unexpected cve: %v", f[0].CVEs)
	}
	for _, want := range []string{"CVE-2020-11022", "CVE-2020-11023", "CVE-2019-11358"} {
		if !hasCVE(f, want) {
			t.Errorf("expected %s for jQuery 3.3.1, got %v", want, cves(f))
		}
	}
	if hasCVE(f, "CVE-2015-9251") {
		t.Error("CVE-2015-9251 was fixed in 3.0.0 and must not match 3.3.1")
	}
}

func TestMatchPatchedIsClean(t *testing.T) {
	if f := Match([]models.Tech{{Name: "jQuery", Version: "3.5.0"}}); len(f) != 0 {
		t.Fatalf("expected no match for patched jQuery 3.5.0, got %+v", f)
	}
}

func TestMatchNoVersionSkipped(t *testing.T) {
	if f := Match([]models.Tech{{Name: "jQuery"}}); len(f) != 0 {
		t.Fatal("expected no match when version is unknown")
	}
}

func TestMatchHeartbleed(t *testing.T) {
	if f := Match([]models.Tech{{Name: "OpenSSL", Version: "1.0.1f"}}); !hasCVE(f, "CVE-2014-0160") {
		t.Fatalf("OpenSSL 1.0.1f should be Heartbleed-affected, got %v", cves(f))
	}
	if f := Match([]models.Tech{{Name: "OpenSSL", Version: "1.0.1"}}); !hasCVE(f, "CVE-2014-0160") {
		t.Fatalf("OpenSSL 1.0.1 should be Heartbleed-affected, got %v", cves(f))
	}
	for _, v := range []string{"1.0.1g", "1.0.2", "1.0.0t"} {
		if f := Match([]models.Tech{{Name: "OpenSSL", Version: v}}); hasCVE(f, "CVE-2014-0160") {
			t.Errorf("OpenSSL %s should not be Heartbleed-affected", v)
		}
	}
}

func TestMatchNginxStableFix(t *testing.T) {
	if f := Match([]models.Tech{{Name: "nginx", Version: "1.20.1"}}); hasCVE(f, "CVE-2021-23017") {
		t.Fatal("nginx 1.20.1 carries the CVE-2021-23017 fix")
	}
	if f := Match([]models.Tech{{Name: "nginx", Version: "1.20.0"}}); !hasCVE(f, "CVE-2021-23017") {
		t.Fatal("nginx 1.20.0 should match CVE-2021-23017")
	}
}

func TestMatchApacheTraversalSplit(t *testing.T) {
	f := Match([]models.Tech{{Name: "Apache", Version: "2.4.50"}})
	if hasCVE(f, "CVE-2021-41773") {
		t.Error("2.4.50 fixed CVE-2021-41773")
	}
	if !hasCVE(f, "CVE-2021-42013") {
		t.Error("2.4.50 is affected by CVE-2021-42013")
	}
	f = Match([]models.Tech{{Name: "Apache", Version: "2.4.49"}})
	if !hasCVE(f, "CVE-2021-41773") || !hasCVE(f, "CVE-2021-42013") {
		t.Errorf("2.4.49 should match both traversal CVEs, got %v", cves(f))
	}
}

func TestDescriptionWithoutFixedVersion(t *testing.T) {
	d := describe(models.Tech{Name: "X", Version: "1.0"}, Entry{CVE: "CVE-0000-0001"})
	if strings.Contains(d, "fixed in") || !strings.HasSuffix(d, ".") {
		t.Fatalf("unexpected description: %q", d)
	}
	d = describe(models.Tech{Name: "X", Version: "1.0"}, Entry{CVE: "CVE-0000-0001", Fixed: "1.1"})
	if !strings.Contains(d, "(fixed in 1.1)") {
		t.Fatalf("unexpected description: %q", d)
	}
}

func TestDatabaseWellFormed(t *testing.T) {
	var entries []Entry
	if err := json.Unmarshal(dbJSON, &entries); err != nil {
		t.Fatalf("db.json does not parse: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("db.json is empty")
	}
	for i, e := range entries {
		if e.Tech == "" || e.CVE == "" || e.Severity == "" {
			t.Errorf("entry %d missing tech/cve/severity: %+v", i, e)
		}
		if !strings.HasPrefix(e.CVE, "CVE-") {
			t.Errorf("entry %d has malformed CVE id %q", i, e.CVE)
		}
		if models.Severity(e.Severity).Normalize() != models.Severity(strings.ToLower(e.Severity)) {
			t.Errorf("entry %d has unknown severity %q", i, e.Severity)
		}
		if e.Introduced != "" && e.Fixed != "" && compareVersions(e.Introduced, e.Fixed) >= 0 {
			t.Errorf("entry %d has an empty range: %s..%s", i, e.Introduced, e.Fixed)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.4.49", "2.4.51", -1},
		{"2.4.51", "2.4.49", 1},
		{"3.0.0", "3.0.0", 0},
		{"1.21.0", "1.9.0", 1},
		{"3.0", "3.0.0", 0},
		// OpenSSL patch letters sort after the bare release and in order.
		{"3.0.7a", "3.0.7", 1},
		{"1.0.1f", "1.0.1g", -1},
		{"1.0.1g", "1.0.1f", 1},
		{"1.0.2zf", "1.0.2k", 1},
		{"1.0.2z", "1.0.2za", -1},
		// Pre-releases sort before the release.
		{"1.2.3-beta", "1.2.3", -1},
		{"1.2.3", "1.2.3-rc1", 1},
		{"1.2.3-rc1", "1.2.3-rc2", -1},
		{"1.2.3-alpha.2", "1.2.3", -1},
		{"1.2.4-beta", "1.2.3", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
