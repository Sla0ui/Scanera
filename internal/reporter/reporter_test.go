package reporter

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
)

const xss = `<script>alert(1)</script>`

func sampleResults() []*models.Result {
	return []*models.Result{
		{
			Domain:       "active.example",
			Active:       true,
			FinalURL:     "https://active.example/",
			StatusCode:   200,
			Title:        "Hello, \"world\"\nsecond " + xss,
			ResponseTime: 120 * time.Millisecond,
			ServerInfo:   models.ServerInfo{Server: "nginx " + xss},
			Technologies: []string{"nginx", "jQuery"},
			TechDetails:  []models.Tech{{Name: "jQuery", Version: "3.4.1"}},
			OpenPorts:    []models.Port{{Port: 6379, Protocol: "tcp", Service: "redis", Banner: xss}},
			Findings: []models.Finding{
				{ID: "zz-low", Title: "Low thing", Severity: models.SeverityLow, Source: "probe", Location: "https://active.example/x"},
				{ID: "aa-crit", Title: "Critical thing", Severity: models.SeverityCritical, Source: "secret", Evidence: xss, Location: "https://active.example/"},
			},
		},
		{
			Domain:     "=cmd|' /C calc'!A0",
			StatusCode: 0,
			Error:      errors.New(`Get "https://bad.example": dial tcp, refused ` + xss),
		},
	}
}

func TestHTMLEscapesScannedValues(t *testing.T) {
	dir := t.TempDir()
	results := sampleResults()
	results[1].Domain = "<img src=x onerror=alert(1)>"
	out := filepath.Join(dir, "r.html")
	if err := New(results, dir).GenerateHTML(out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, raw := range []string{xss, "<img src=x"} {
		if strings.Contains(html, raw) {
			t.Errorf("report contains unescaped %q", raw)
		}
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("expected escaped script tag in report")
	}
	for _, want := range []string{"Critical thing", "jQuery 3.4.1", "6379/tcp", "Open ports"} {
		if !strings.Contains(html, want) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Index(html, "Critical thing") > strings.Index(html, "Low thing") {
		t.Error("findings should be sorted by severity, worst first")
	}
}

func TestHTMLOmitsFindingsSectionWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "r.html")
	results := []*models.Result{{Domain: "a.example", Active: true, StatusCode: 200}}
	if err := New(results, dir).GenerateHTML(out); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	if strings.Contains(string(data), "<h2>Findings</h2>") {
		t.Error("findings section should be omitted when there are none")
	}
}

func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("%s does not parse as CSV: %v", path, err)
	}
	return rows
}

func TestCSVReportsParseBack(t *testing.T) {
	dir := t.TempDir()
	rep := New(sampleResults(), dir)
	if err := rep.WriteResultsToFiles(); err != nil {
		t.Fatal(err)
	}
	if err := rep.GenerateCSV(filepath.Join(dir, "report.csv")); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		file string
		cols int
	}{
		{"domain_check_log.csv", 10},
		{"report.csv", 11},
	} {
		rows := readCSV(t, filepath.Join(dir, tc.file))
		if len(rows) != 3 {
			t.Fatalf("%s: got %d rows, want 3", tc.file, len(rows))
		}
		for i, row := range rows {
			if len(row) != tc.cols {
				t.Errorf("%s row %d: got %d columns, want %d", tc.file, i, len(row), tc.cols)
			}
		}
		if got := rows[2][0]; got != `'=cmd|' /C calc'!A0` {
			t.Errorf("%s: formula cell not neutralized: %q", tc.file, got)
		}
	}

	log := readCSV(t, filepath.Join(dir, "domain_check_log.csv"))
	if got := log[1][6]; strings.Contains(got, "\n") || !strings.Contains(got, `"world"`) {
		t.Errorf("title should keep quotes and lose newlines, got %q", got)
	}
	if got := log[2][9]; !strings.Contains(got, "dial tcp, refused") {
		t.Errorf("error message mangled: %q", got)
	}
	if got := readCSV(t, filepath.Join(dir, "report.csv"))[1][10]; got != "2" {
		t.Errorf("findings column = %q, want 2", got)
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{
		"":             "",
		"example.com":  "example.com",
		"=1+1":         "'=1+1",
		"+1":           "'+1",
		"-1":           "'-1",
		"@SUM(A1)":     "'@SUM(A1)",
		"\tx":          "'\tx",
		"\rx":          "'\rx",
		"a=b":          "a=b",
		"https://x/-y": "https://x/-y",
	} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteResultsToFilesOverwrites(t *testing.T) {
	dir := t.TempDir()
	rep := New(sampleResults(), dir)
	for i := 0; i < 2; i++ {
		if err := rep.WriteResultsToFiles(); err != nil {
			t.Fatal(err)
		}
	}
	for file, want := range map[string]int{"active_domains.txt": 1, "inactive_domains.txt": 1} {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		if got := len(strings.Split(strings.TrimSpace(string(data)), "\n")); got != want {
			t.Errorf("%s has %d lines after two runs, want %d", file, got, want)
		}
	}
}

func TestSARIFDeterministic(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "r.sarif")
	if err := New(sampleResults(), dir).GenerateSARIF(out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Version != Version {
		t.Errorf("driver version = %q, want %q", run.Tool.Driver.Version, Version)
	}
	if len(run.Tool.Driver.Rules) != 2 || run.Tool.Driver.Rules[0].ID != "aa-crit" || run.Tool.Driver.Rules[1].ID != "zz-low" {
		t.Fatalf("rules not sorted by ID: %+v", run.Tool.Driver.Rules)
	}
	for _, res := range run.Results {
		if got := run.Tool.Driver.Rules[res.RuleIndex].ID; got != res.RuleID {
			t.Errorf("result %s has ruleIndex %d pointing at %s", res.RuleID, res.RuleIndex, got)
		}
	}
}

func TestSARIFEmptyResultsIsArray(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "r.sarif")
	if err := New([]*models.Result{{Domain: "a.example"}}, dir).GenerateSARIF(out); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), `"results": []`) {
		t.Errorf("expected empty results array, got:\n%s", data)
	}
}

func TestGenerateReportFormats(t *testing.T) {
	dir := t.TempDir()
	rep := New(sampleResults(), dir)
	base := filepath.Join(dir, "bundle.out")

	if err := rep.GenerateReport(base, "json,pdf"); err == nil || !strings.Contains(err.Error(), "pdf") {
		t.Errorf("expected unknown-format error naming pdf, got %v", err)
	}
	if err := rep.GenerateReport(base, " "); err == nil {
		t.Error("expected error for empty format")
	}

	if err := rep.GenerateReport(base, "All"); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".json", ".csv", ".html", ".md"} {
		if _, err := os.Stat(filepath.Join(dir, "bundle"+ext)); err != nil {
			t.Errorf("missing %s output: %v", ext, err)
		}
	}
}

func TestMarkdownEscapesCells(t *testing.T) {
	dir := t.TempDir()
	results := sampleResults()
	results[0].ServerInfo.Server = "a|b\nc [click](javascript:alert(1)) <img src=x onerror=alert(1)>"
	out := filepath.Join(dir, "r.md")
	if err := New(results, dir).GenerateMarkdown(out); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	md := string(data)
	if !strings.Contains(md, `a\|b c`) {
		t.Error("pipe/newline in cell not escaped")
	}
	if !strings.Contains(md, `\[click\](javascript:`) || strings.Contains(md, "<img") {
		t.Error("server-controlled text can still form links or raw HTML in markdown")
	}
	if !strings.Contains(md, "## Findings") || !strings.Contains(md, "Generated by Scanera "+Version) {
		t.Error("markdown missing findings section or version footer")
	}
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| active.example") && strings.Count(strings.ReplaceAll(line, `\|`, ""), "|") != 6 {
			t.Errorf("active row has wrong column count: %q", line)
		}
	}
}
