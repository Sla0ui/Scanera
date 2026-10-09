// Package vuln maps detected technologies and versions to known CVEs using a
// local, embedded database. The database is a seed set and is meant to be
// extended; it keeps matching offline and deterministic.
package vuln

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/Sla0ui/scanera/internal/models"
)

//go:embed db.json
var dbJSON []byte

// Entry is one vulnerability record. A detected version V is considered
// affected when (Introduced == "" or V >= Introduced) and (Fixed == "" or
// V < Fixed).
type Entry struct {
	Tech       string `json:"tech"`
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
	CVE        string `json:"cve"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Reference  string `json:"reference"`
}

var (
	db     []Entry
	dbErr  error
	dbOnce sync.Once
)

func load() {
	dbErr = json.Unmarshal(dbJSON, &db)
}

// Match returns findings for technologies whose version falls in a known
// vulnerable range. Technologies without a detected version are skipped.
func Match(techs []models.Tech) []models.Finding {
	dbOnce.Do(load)
	if dbErr != nil {
		return nil
	}

	var findings []models.Finding
	for _, t := range techs {
		if t.Version == "" {
			continue
		}
		for _, e := range db {
			if !strings.EqualFold(e.Tech, t.Name) {
				continue
			}
			if !affected(t.Version, e.Introduced, e.Fixed) {
				continue
			}
			findings = append(findings, models.Finding{
				ID:          e.CVE,
				Title:       fmt.Sprintf("%s %s: %s", t.Name, t.Version, e.Title),
				Severity:    models.Severity(e.Severity),
				Source:      "vuln",
				Description: fmt.Sprintf("Detected %s %s is affected by %s (fixed in %s).", t.Name, t.Version, e.CVE, e.Fixed),
				References:  []string{e.Reference},
				Tags:        []string{"cve", strings.ToLower(t.Name)},
				CVEs:        []string{e.CVE},
			})
		}
	}
	return findings
}

func affected(version, introduced, fixed string) bool {
	if introduced != "" && compareVersions(version, introduced) < 0 {
		return false
	}
	if fixed != "" && compareVersions(version, fixed) >= 0 {
		return false
	}
	return true
}

// compareVersions compares dotted numeric versions, ignoring any trailing
// non-numeric suffix on a segment. Returns -1, 0, or 1.
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = numPrefix(as[i])
		}
		if i < len(bs) {
			bv = numPrefix(bs[i])
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func numPrefix(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0
	}
	n, _ := strconv.Atoi(s[:i])
	return n
}
