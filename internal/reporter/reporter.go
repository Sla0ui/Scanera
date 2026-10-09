package reporter

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Sla0ui/scanera/internal/models"
)

// Version is stamped into generated reports. The CLI overrides it with the
// application version at startup.
var Version = "dev"

// Reporter handles generating scan reports in various formats
type Reporter struct {
	results   []*models.Result
	outputDir string
}

// New creates a new Reporter instance
func New(results []*models.Result, outputDir string) *Reporter {
	return &Reporter{
		results:   results,
		outputDir: outputDir,
	}
}

// WriteResultsToFiles writes results to the standard output files. Every file
// is rewritten from scratch so repeated runs into the same directory don't
// accumulate stale lines.
func (r *Reporter) WriteResultsToFiles() error {
	activeFile := filepath.Join(r.outputDir, "active_domains.txt")
	inactiveFile := filepath.Join(r.outputDir, "inactive_domains.txt")
	logFile := filepath.Join(r.outputDir, "domain_check_log.csv")
	jsonFile := filepath.Join(r.outputDir, "scan_results.json")

	if err := r.writeLogCSV(logFile); err != nil {
		return err
	}

	jsonData, err := json.MarshalIndent(r.results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	if err := os.WriteFile(jsonFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	var active, inactive strings.Builder
	for _, result := range r.results {
		if result.Active {
			line := result.FinalURL
			if result.RedirectTo != "" {
				line += fmt.Sprintf(" (Redirected to: %s)", result.RedirectTo)
			}
			active.WriteString(line + "\n")
		} else {
			inactive.WriteString(result.Domain + "\n")
		}
	}
	if err := os.WriteFile(activeFile, []byte(active.String()), 0644); err != nil {
		return fmt.Errorf("failed to write active domains: %w", err)
	}
	if err := os.WriteFile(inactiveFile, []byte(inactive.String()), 0644); err != nil {
		return fmt.Errorf("failed to write inactive domains: %w", err)
	}
	return nil
}

func (r *Reporter) writeLogCSV(path string) error {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	rows := [][]string{{"Domain", "Status", "StatusCode", "FinalURL", "RedirectTo", "ResponseTime", "Title", "Server", "IPAddresses", "Error"}}
	for _, result := range r.results {
		rows = append(rows, []string{
			result.Domain,
			statusLabel(result),
			fmt.Sprint(result.StatusCode),
			result.FinalURL,
			result.RedirectTo,
			fmt.Sprintf("%dms", result.ResponseTime.Milliseconds()),
			oneLine(result.Title),
			result.ServerInfo.Server,
			strings.Join(result.IPAddresses, "|"),
			errString(result),
		})
	}
	if err := writeCSVRows(w, rows); err != nil {
		return fmt.Errorf("failed to encode log CSV: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write log file: %w", err)
	}
	return nil
}

// ParseFormats turns a comma-separated format list into report formats. "all"
// expands to every supported format; an unknown format is an error rather
// than a silent no-op.
func ParseFormats(format string) ([]string, error) {
	var formats []string
	for _, f := range strings.Split(format, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		switch f {
		case "":
			continue
		case "all":
			return []string{"json", "csv", "html", "markdown"}, nil
		case "json", "csv", "html", "markdown":
			formats = append(formats, f)
		case "md":
			formats = append(formats, "markdown")
		default:
			return nil, fmt.Errorf("unknown report format %q (want json, csv, html, markdown, or all)", f)
		}
	}
	if len(formats) == 0 {
		return nil, fmt.Errorf("no report format given")
	}
	return formats, nil
}

// GenerateReport creates a report in each requested format.
func (r *Reporter) GenerateReport(outputPath, format string) error {
	formats, err := ParseFormats(format)
	if err != nil {
		return err
	}

	outputBase := strings.TrimSuffix(outputPath, filepath.Ext(outputPath))
	for _, f := range formats {
		var err error
		switch f {
		case "json":
			err = r.GenerateJSON(outputBase + ".json")
		case "csv":
			err = r.GenerateCSV(outputBase + ".csv")
		case "html":
			err = r.GenerateHTML(outputBase + ".html")
		case "markdown":
			err = r.GenerateMarkdown(outputBase + ".md")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// GetStats returns active and inactive counts
func (r *Reporter) GetStats() (active, inactive int) {
	for _, result := range r.results {
		if result.Active {
			active++
		} else {
			inactive++
		}
	}
	return
}

// domainFinding pairs a finding with the domain it was reported on.
type domainFinding struct {
	Domain string
	models.Finding
}

// sortedFindings flattens findings across results, worst first. The sort is
// stable so findings of equal severity keep scan order.
func (r *Reporter) sortedFindings() []domainFinding {
	var out []domainFinding
	for _, res := range r.results {
		for _, f := range res.Findings {
			out = append(out, domainFinding{Domain: res.Domain, Finding: f})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Severity.Rank() > out[j].Severity.Rank()
	})
	return out
}

// severityCounts returns finding counts keyed by normalized severity.
func (r *Reporter) severityCounts() map[models.Severity]int {
	counts := make(map[models.Severity]int)
	for _, res := range r.results {
		for _, f := range res.Findings {
			counts[f.Severity.Normalize()]++
		}
	}
	return counts
}

// techList prefers versioned tech details and falls back to bare names.
func techList(result *models.Result) []string {
	if len(result.TechDetails) > 0 {
		out := make([]string, 0, len(result.TechDetails))
		for _, t := range result.TechDetails {
			if t.Version != "" {
				out = append(out, t.Name+" "+t.Version)
			} else {
				out = append(out, t.Name)
			}
		}
		return out
	}
	return result.Technologies
}

func statusLabel(result *models.Result) string {
	if result.Active {
		return "active"
	}
	return "inactive"
}

func errString(result *models.Result) string {
	if result.Error == nil {
		return ""
	}
	return result.Error.Error()
}

// oneLine collapses any run of whitespace, including newlines, to one space.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// csvSafe defuses spreadsheet formula injection: a cell beginning with one of
// these characters is evaluated by Excel/LibreOffice, and scanned sites
// control titles, headers and URLs.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func writeCSVRows(w *csv.Writer, rows [][]string) error {
	for _, row := range rows {
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
