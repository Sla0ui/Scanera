package reporter

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
)

// htmlTemplate is rendered with html/template, so every value from a scanned
// site (titles, headers, errors, evidence) is escaped for its context.
var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"join": strings.Join,
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scanera Report</title>
<style>
:root {
  color-scheme: light;
  --bg: #ffffff; --fg: #1f2933; --muted: #616e7c; --line: #e4e7eb; --head: #f5f7fa;
  --ok-bg: #e3f9e5; --ok-fg: #1f6b2c; --bad-bg: #fde8e8; --bad-fg: #9b1c1c;
  --crit: #7f1d1d; --high: #c2410c; --med: #a16207; --low: #1d4ed8; --info: #52606d;
  --chip: #e6effc; --chip-fg: #1e3a8a;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --bg: #12161c; --fg: #e4e7eb; --muted: #9aa5b1; --line: #2a313b; --head: #1b2129;
    --ok-bg: #173a20; --ok-fg: #9be3a8; --bad-bg: #431a1a; --bad-fg: #f5b4b4;
    --crit: #fca5a5; --high: #fdba74; --med: #fde047; --low: #93c5fd; --info: #cbd2d9;
    --chip: #1e2a44; --chip-fg: #bfd4ff;
  }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 24px 16px; background: var(--bg); color: var(--fg);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1200px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 4px; }
h2 { font-size: 1.15rem; margin: 32px 0 8px; }
.meta { color: var(--muted); margin: 0 0 20px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; }
.stat { border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
.stat b { display: block; font-size: 1.5rem; font-variant-numeric: tabular-nums; }
.stat span { color: var(--muted); }
.wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: var(--head); font-weight: 600; white-space: nowrap; }
tr:last-child td { border-bottom: 0; }
td { overflow-wrap: anywhere; }
td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
code { font-size: 12px; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.ok { background: var(--ok-bg); color: var(--ok-fg); }
.bad { background: var(--bad-bg); color: var(--bad-fg); }
.chip { display: inline-block; margin: 1px 4px 1px 0; padding: 0 6px; border-radius: 4px; background: var(--chip); color: var(--chip-fg); font-size: 12px; }
.sev { border: 1px solid currentColor; }
.sev-critical { color: var(--crit); } .sev-high { color: var(--high); } .sev-medium { color: var(--med); }
.sev-low { color: var(--low); } .sev-info { color: var(--info); }
footer { margin-top: 32px; color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<main>
<h1>Scanera Report</h1>
<p class="meta">Generated {{.Generated}}</p>

<div class="stats">
  <div class="stat"><b>{{.Total}}</b><span>Domains</span></div>
  <div class="stat"><b>{{.Active}}</b><span>Active</span></div>
  <div class="stat"><b>{{.Inactive}}</b><span>Inactive</span></div>
  <div class="stat"><b>{{len .Findings}}</b><span>Findings</span></div>
  {{range .SeverityStats}}<div class="stat"><b class="sev-{{.Name}}">{{.Count}}</b><span>{{.Name}}</span></div>
  {{end}}
</div>

{{if .Findings}}
<h2>Findings</h2>
<div class="wrap"><table>
<tr><th>Severity</th><th>Title</th><th>Domain</th><th>Location</th><th>Evidence</th><th>Source</th></tr>
{{range .Findings}}<tr>
  <td><span class="badge sev sev-{{.Severity}}">{{.Severity}}</span></td>
  <td>{{.Title}}</td>
  <td>{{.Domain}}</td>
  <td>{{.Location}}</td>
  <td>{{if .Evidence}}<code>{{.Evidence}}</code>{{end}}</td>
  <td>{{.Source}}</td>
</tr>
{{end}}</table></div>
{{end}}

<h2>Active domains</h2>
{{if .ActiveRows}}<div class="wrap"><table>
<tr><th>Domain</th><th>Final URL</th><th>Status</th><th>Title</th><th>Technologies</th><th>Server</th><th>Response</th></tr>
{{range .ActiveRows}}<tr>
  <td>{{.Domain}}</td>
  <td>{{.FinalURL}}</td>
  <td class="num"><span class="badge ok">{{.StatusCode}}</span></td>
  <td>{{.Title}}</td>
  <td>{{range .Techs}}<span class="chip">{{.}}</span>{{end}}</td>
  <td>{{.Server}}</td>
  <td class="num">{{.ResponseMS}} ms</td>
</tr>
{{end}}</table></div>
{{else}}<p class="meta">None.</p>{{end}}

{{if .PortRows}}
<h2>Open ports</h2>
<div class="wrap"><table>
<tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th></tr>
{{range .PortRows}}<tr>
  <td>{{.Host}}</td>
  <td class="num">{{.Port}}/{{.Protocol}}</td>
  <td>{{.Service}}</td>
  <td>{{if .Banner}}<code>{{.Banner}}</code>{{end}}</td>
</tr>
{{end}}</table></div>
{{end}}

<h2>Inactive domains</h2>
{{if .InactiveRows}}<div class="wrap"><table>
<tr><th>Domain</th><th>Status</th><th>Error</th></tr>
{{range .InactiveRows}}<tr>
  <td>{{.Domain}}</td>
  <td class="num"><span class="badge bad">{{if .StatusCode}}{{.StatusCode}}{{else}}—{{end}}</span></td>
  <td>{{.Error}}</td>
</tr>
{{end}}</table></div>
{{else}}<p class="meta">None.</p>{{end}}

<footer>Generated by Scanera {{.Version}}</footer>
</main>
</body>
</html>
`))

type htmlSeverityStat struct {
	Name  string
	Count int
}

type htmlFinding struct {
	Severity models.Severity
	Title    string
	Domain   string
	Location string
	Evidence string
	Source   string
}

type htmlActiveRow struct {
	Domain     string
	FinalURL   string
	StatusCode int
	Title      string
	Techs      []string
	Server     string
	ResponseMS int64
}

type htmlPortRow struct {
	Host     string
	Port     int
	Protocol string
	Service  string
	Banner   string
}

type htmlInactiveRow struct {
	Domain     string
	StatusCode int
	Error      string
}

type htmlData struct {
	Generated     string
	Version       string
	Total         int
	Active        int
	Inactive      int
	SeverityStats []htmlSeverityStat
	Findings      []htmlFinding
	ActiveRows    []htmlActiveRow
	PortRows      []htmlPortRow
	InactiveRows  []htmlInactiveRow
}

// GenerateHTML creates an HTML report
func (r *Reporter) GenerateHTML(outputPath string) error {
	data := htmlData{
		Generated: time.Now().Format("January 2, 2006 15:04:05"),
		Version:   Version,
		Total:     len(r.results),
	}
	data.Active, data.Inactive = r.GetStats()

	counts := r.severityCounts()
	for _, s := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo} {
		if counts[s] > 0 {
			data.SeverityStats = append(data.SeverityStats, htmlSeverityStat{Name: string(s), Count: counts[s]})
		}
	}

	for _, f := range r.sortedFindings() {
		data.Findings = append(data.Findings, htmlFinding{
			Severity: f.Severity.Normalize(),
			Title:    f.Title,
			Domain:   f.Domain,
			Location: f.Location,
			Evidence: f.Evidence,
			Source:   f.Source,
		})
	}

	for _, result := range r.results {
		if result.Active {
			data.ActiveRows = append(data.ActiveRows, htmlActiveRow{
				Domain:     result.Domain,
				FinalURL:   result.FinalURL,
				StatusCode: result.StatusCode,
				Title:      result.Title,
				Techs:      techList(result),
				Server:     result.ServerInfo.Server,
				ResponseMS: result.ResponseTime.Milliseconds(),
			})
		} else {
			data.InactiveRows = append(data.InactiveRows, htmlInactiveRow{
				Domain:     result.Domain,
				StatusCode: result.StatusCode,
				Error:      errString(result),
			})
		}
		// Ports are scanned on the host the site finally landed on.
		host := result.Domain
		if result.RedirectTo != "" {
			host = result.RedirectTo
		}
		for _, p := range result.OpenPorts {
			data.PortRows = append(data.PortRows, htmlPortRow{
				Host: host, Port: p.Port, Protocol: p.Protocol, Service: p.Service, Banner: p.Banner,
			})
		}
	}

	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to render HTML report: %w", err)
	}
	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write HTML file: %w", err)
	}
	return nil
}
