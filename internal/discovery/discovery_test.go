package discovery

import (
	"testing"

	"github.com/Sla0ui/scanera/internal/models"
)

func TestInteresting(t *testing.T) {
	// Proper 404 baseline: any 200/401/403 is interesting.
	if !interesting(200, 500, 404, 0) {
		t.Error("200 vs 404 baseline should be interesting")
	}
	if !interesting(403, 10, 404, 0) {
		t.Error("403 should be interesting")
	}
	if interesting(404, 0, 404, 0) {
		t.Error("404 should never be interesting")
	}
	// Soft-404 baseline (200 with fixed length): near-equal length is not interesting.
	if interesting(200, 1000, 200, 1000) {
		t.Error("identical soft-404 length should not be interesting")
	}
	if !interesting(200, 5000, 200, 1000) {
		t.Error("very different length from soft-404 should be interesting")
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
