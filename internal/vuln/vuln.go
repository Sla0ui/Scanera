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
				Description: describe(t, e),
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

func describe(t models.Tech, e Entry) string {
	desc := fmt.Sprintf("Detected %s %s is affected by %s", t.Name, t.Version, e.CVE)
	if e.Fixed != "" {
		desc += fmt.Sprintf(" (fixed in %s)", e.Fixed)
	}
	// Distributions backport security fixes without bumping the version a
	// server reports, so a match is a lead to confirm, not proof.
	return desc + ". This is a version-based match; distribution packages often carry backported fixes, so confirm before acting."
}

// compareVersions compares dotted versions segment by segment. Numbers compare
// numerically; on a tie the suffix decides (see compareSuffix). Returns -1, 0,
// or 1.
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var an, bn int
		var asuf, bsuf string
		if i < len(as) {
			an, asuf = splitSegment(as[i])
		}
		if i < len(bs) {
			bn, bsuf = splitSegment(bs[i])
		}
		if an != bn {
			if an < bn {
				return -1
			}
			return 1
		}
		if c := compareSuffix(asuf, bsuf); c != 0 {
			return c
		}
	}
	return 0
}

// splitSegment splits "1f" into 1 and "f".
func splitSegment(s string) (int, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	n, _ := strconv.Atoi(s[:i])
	return n, s[i:]
}

// compareSuffix orders what follows a segment's number. A bare run of
// lowercase letters is an OpenSSL-style patch release (1.0.1 < 1.0.1a < 1.0.1g
// < 1.0.2zf), so it sorts after no suffix. Anything else ("-beta", "rc1") is a
// pre-release and sorts before it.
func compareSuffix(a, b string) int {
	ra, rb := suffixRank(a), suffixRank(b)
	if ra != rb {
		if ra < rb {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func suffixRank(s string) int {
	if s == "" {
		return 0
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return -1
		}
	}
	return 1
}
