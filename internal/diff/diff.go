// Package diff compares two scan result files, so recurring scans can report
// what changed: hosts that appeared or went dark, new or resolved findings,
// and ports that opened or closed.
package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Sla0ui/scanera/internal/models"
)

// FindingChange is a finding that appeared or disappeared on a domain.
type FindingChange struct {
	Domain  string         `json:"domain"`
	Finding models.Finding `json:"finding"`
}

// PortChange is a port that opened or closed on a domain.
type PortChange struct {
	Domain string      `json:"domain"`
	Port   models.Port `json:"port"`
}

// Report lists everything that differs between two runs.
type Report struct {
	AddedDomains     []string        `json:"added_domains,omitempty"`
	RemovedDomains   []string        `json:"removed_domains,omitempty"`
	NewlyActive      []string        `json:"newly_active,omitempty"`
	NewlyInactive    []string        `json:"newly_inactive,omitempty"`
	NewFindings      []FindingChange `json:"new_findings,omitempty"`
	ResolvedFindings []FindingChange `json:"resolved_findings,omitempty"`
	OpenedPorts      []PortChange    `json:"opened_ports,omitempty"`
	ClosedPorts      []PortChange    `json:"closed_ports,omitempty"`
}

// Empty reports whether nothing changed.
func (r Report) Empty() bool {
	return len(r.AddedDomains)+len(r.RemovedDomains)+len(r.NewlyActive)+len(r.NewlyInactive)+
		len(r.NewFindings)+len(r.ResolvedFindings)+len(r.OpenedPorts)+len(r.ClosedPorts) == 0
}

// Load reads a scan_results.json file.
func Load(path string) ([]models.Result, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, err
	}
	var results []models.Result
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("%s is not a scan results file: %w", path, err)
	}
	return results, nil
}

// Compare diffs two runs. Findings are matched on domain, ID and location,
// since titles can embed details (such as versions) that change between runs.
func Compare(oldRun, newRun []models.Result) Report {
	oldBy := index(oldRun)
	newBy := index(newRun)
	var rep Report

	for _, d := range sortedKeys(newBy) {
		n := newBy[d]
		o, existed := oldBy[d]
		if !existed {
			rep.AddedDomains = append(rep.AddedDomains, d)
			if n.Active {
				rep.NewlyActive = append(rep.NewlyActive, d)
			}
		} else if n.Active != o.Active {
			if n.Active {
				rep.NewlyActive = append(rep.NewlyActive, d)
			} else {
				rep.NewlyInactive = append(rep.NewlyInactive, d)
			}
		}
		var oldFindings []models.Finding
		var oldPorts []models.Port
		if existed {
			oldFindings, oldPorts = o.Findings, o.OpenPorts
		}
		for _, f := range missingFindings(n.Findings, oldFindings) {
			rep.NewFindings = append(rep.NewFindings, FindingChange{d, f})
		}
		for _, f := range missingFindings(oldFindings, n.Findings) {
			rep.ResolvedFindings = append(rep.ResolvedFindings, FindingChange{d, f})
		}
		for _, p := range missingPorts(n.OpenPorts, oldPorts) {
			rep.OpenedPorts = append(rep.OpenedPorts, PortChange{d, p})
		}
		for _, p := range missingPorts(oldPorts, n.OpenPorts) {
			rep.ClosedPorts = append(rep.ClosedPorts, PortChange{d, p})
		}
	}
	for _, d := range sortedKeys(oldBy) {
		if _, ok := newBy[d]; !ok {
			rep.RemovedDomains = append(rep.RemovedDomains, d)
		}
	}

	sort.SliceStable(rep.NewFindings, func(i, j int) bool {
		return rep.NewFindings[i].Finding.Severity.Rank() > rep.NewFindings[j].Finding.Severity.Rank()
	})
	return rep
}

func index(results []models.Result) map[string]models.Result {
	m := make(map[string]models.Result, len(results))
	for _, r := range results {
		m[strings.ToLower(r.Domain)] = r
	}
	return m
}

func sortedKeys(m map[string]models.Result) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func findingKey(f models.Finding) string { return f.ID + "\x00" + f.Location }

// missingFindings returns findings in a that are not in b.
func missingFindings(a, b []models.Finding) []models.Finding {
	have := make(map[string]bool, len(b))
	for _, f := range b {
		have[findingKey(f)] = true
	}
	var out []models.Finding
	for _, f := range a {
		if !have[findingKey(f)] {
			have[findingKey(f)] = true
			out = append(out, f)
		}
	}
	return out
}

func missingPorts(a, b []models.Port) []models.Port {
	have := make(map[int]bool, len(b))
	for _, p := range b {
		have[p.Port] = true
	}
	var out []models.Port
	for _, p := range a {
		if !have[p.Port] {
			out = append(out, p)
		}
	}
	return out
}

// MaxNewSeverity returns the worst severity among new findings, and false
// when there are none.
func (r Report) MaxNewSeverity() (models.Severity, bool) {
	if len(r.NewFindings) == 0 {
		return "", false
	}
	worst := r.NewFindings[0].Finding.Severity.Normalize()
	for _, c := range r.NewFindings[1:] {
		if s := c.Finding.Severity.Normalize(); s.Rank() > worst.Rank() {
			worst = s
		}
	}
	return worst, true
}
