package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sla0ui/scanera/internal/models"
)

func TestCompare(t *testing.T) {
	oldRun := []models.Result{
		{Domain: "a.com", Active: true,
			Findings:  []models.Finding{{ID: "missing-csp", Location: "https://a.com/", Severity: "low"}},
			OpenPorts: []models.Port{{Port: 80}, {Port: 22}}},
		{Domain: "b.com", Active: true},
		{Domain: "gone.com", Active: true},
	}
	newRun := []models.Result{
		{Domain: "a.com", Active: true,
			Findings: []models.Finding{
				{ID: "exposed-dotenv", Location: "https://a.com/.env", Severity: "critical"},
				{ID: "version-disclosure", Location: "https://a.com/", Severity: "info"},
			},
			OpenPorts: []models.Port{{Port: 80}, {Port: 6379}}},
		{Domain: "B.com", Active: false},
		{Domain: "new.com", Active: true},
	}
	rep := Compare(oldRun, newRun)

	check := func(name string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	check("added", rep.AddedDomains, []string{"new.com"})
	check("removed", rep.RemovedDomains, []string{"gone.com"})
	check("newly active", rep.NewlyActive, []string{"new.com"})
	check("newly inactive", rep.NewlyInactive, []string{"b.com"})
	if len(rep.NewFindings) != 2 || rep.NewFindings[0].Finding.ID != "exposed-dotenv" {
		t.Errorf("new findings should be sorted worst first: %+v", rep.NewFindings)
	}
	if len(rep.ResolvedFindings) != 1 || rep.ResolvedFindings[0].Finding.ID != "missing-csp" {
		t.Errorf("resolved findings wrong: %+v", rep.ResolvedFindings)
	}
	if len(rep.OpenedPorts) != 1 || rep.OpenedPorts[0].Port.Port != 6379 {
		t.Errorf("opened ports wrong: %+v", rep.OpenedPorts)
	}
	if len(rep.ClosedPorts) != 1 || rep.ClosedPorts[0].Port.Port != 22 {
		t.Errorf("closed ports wrong: %+v", rep.ClosedPorts)
	}
	if sev, ok := rep.MaxNewSeverity(); !ok || sev != models.SeverityCritical {
		t.Errorf("MaxNewSeverity = %v,%v", sev, ok)
	}
	if rep.Empty() {
		t.Error("report should not be empty")
	}
	if !Compare(newRun, newRun).Empty() {
		t.Error("identical runs should produce an empty report")
	}
}

func TestLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan_results.json")
	in := []*models.Result{{Domain: "a.com", Active: true, Findings: []models.Finding{{ID: "x", Severity: "high"}}}}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Domain != "a.com" || len(got[0].Findings) != 1 {
		t.Errorf("round trip lost data: %+v", got)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("a non-array file should be rejected")
	}
}
