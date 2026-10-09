package vuln

import (
	"testing"

	"github.com/Sla0ui/scanera/internal/models"
)

func TestMatchKnownVulnerable(t *testing.T) {
	f := Match([]models.Tech{{Name: "jQuery", Version: "3.3.1"}})
	if len(f) == 0 {
		t.Fatal("expected a CVE match for jQuery 3.3.1")
	}
	if f[0].CVEs[0] != "CVE-2020-11022" {
		t.Errorf("unexpected cve: %v", f[0].CVEs)
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

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.4.49", "2.4.51", -1},
		{"2.4.51", "2.4.49", 1},
		{"3.0.0", "3.0.0", 0},
		{"1.21.0", "1.9.0", 1},
		{"3.0.7a", "3.0.7", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
