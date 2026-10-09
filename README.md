# Scanera

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**Scanera** is a domain analysis and validation tool. It checks whether domains are live and gathers intelligence about them using DNS resolution, HTTP(S) requests, headless-browser rendering, technology detection, and security assessment.

![S](https://github.com/user-attachments/assets/ef5a17fe-b719-422e-a252-78723f3b5d95)


## 🚀 Features

- **Multi-layer validation** – DNS resolution, HTTP/HTTPS requests, and headless-browser checks
- **Technology detection** – Identify CMSs, frameworks, libraries, and server software
- **Security assessment** – Findings for missing security headers, weak cookie flags, expired or untrusted certificates, legacy TLS, and HTTP without an HTTPS redirect
- **Subdomain takeover detection** – Dangling CNAMEs and unclaimed GitHub Pages, S3, Heroku, Azure and other services
- **Screenshot capture** – Full-page screenshots of active domains
- **Content analysis** – Word counts, links, metadata, login-form and parked-domain detection
- **High performance** – Process thousands of domains with a bounded worker pool
- **Comprehensive reporting** – JSON, CSV, HTML, Markdown and SARIF output, plus JSON-lines streaming
- **Automation-friendly** – Read targets from stdin, fail CI on a severity threshold, and diff two runs
- **User-friendly CLI** – Progress bar, colored output, and a small, predictable flag set


## 🛠️ Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/Sla0ui/scanera.git
cd scanera

# Build the application
go build -o scanera ./cmd/scanera

# Run from the current directory
./scanera --help

# (Optional) Make it available system-wide
sudo cp scanera /usr/local/bin/
```


## ⚡ Quick Start

1. Create a text file with one domain per line (blank lines and `#` comments are ignored):

```txt
example.com
github.com
invalid-domain-12345.com
```

2. Run a scan:

```bash
./scanera scan domains.txt
```

3. View the results in the `results/` directory.


## 🧭 Commands

```
scan      [flags] DOMAIN_FILE   Scan every target listed in a file (- reads stdin)
single    [flags] DOMAIN        Scan a single target
enum      [flags] DOMAIN        Enumerate subdomains (crt.sh + Cert Spotter + DNS brute-force)
ports     [flags] HOST          TCP port scan (active; requires authorization)
templates [flags]               List and validate signature templates
diff      [flags] OLD NEW       Show what changed between two scan_results.json files
```

Targets can be bare hosts, `host:port`, IP addresses or full URLs; they are
normalized and de-duplicated. Status messages and the progress bar go to stderr,
so stdout stays clean for piping.


## 💡 Usage Examples

### Scan domains from a file

```bash
./scanera scan domains.txt
./scanera scan -s "200,301,302" -t 15s -c 10 -o results domains.txt
./scanera scan --detect-tech --security-check --screenshots domains.txt
./scanera scan --force-https domains.txt
```

### Scan a single domain

```bash
./scanera single example.com
./scanera single -v --detect-tech example.com
./scanera single --skip-browser --security-check --cert-info example.com
```

### Faster scans (no browser)

```bash
./scanera scan --skip-browser domains.txt
```

### Generate a bundled report

```bash
# Writes report.json, report.csv, report.html, and report.md
./scanera scan --export report --output-format all domains.txt

# Only HTML and JSON
./scanera scan --export report --output-format html,json domains.txt
```


## ⚙️ Command-Line Options

### Basic Options

| Flag                 | Description                             | Default                                   |
|----------------------|-----------------------------------------|-------------------------------------------|
| `-s, --status-codes` | Comma-separated successful status codes | `200`                                     |
| `-t, --timeout`      | Timeout for HTTP requests               | `10s`                                     |
| `-r, --retries`      | Retries for failed requests             | `2`                                       |
| `-c, --concurrency`  | Maximum concurrent checks               | `5`                                       |
| `-T, --verify-tls`   | Verify TLS certificates                 | `true`                                    |
| `-u, --user-agent`   | User-Agent string                       | `Mozilla/5.0 (compatible; Scanera/2.0)`   |
| `-o, --output-dir`   | Output directory                        | `results`                                 |
| `-v, --verbose`      | Verbose logging                         | `false`                                   |
| `-n, --no-color`     | Disable colored output                  | `false`                                   |
| `-q, --quiet`        | Suppress terminal output (files only)   | `false`                                   |
| `--no-progress`      | Disable the progress bar                | `false`                                   |
| `--force-https`      | Only scan HTTPS                         | `false`                                   |
| `--skip-dns`         | Skip DNS resolution                     | `false`                                   |
| `--skip-browser`     | Skip browser-based checks               | `false`                                   |
| `--max-redirects`    | Maximum redirects to follow             | `10`                                      |

### Feature Options

| Flag                | Description                                              | Default       |
|---------------------|---------------------------------------------------------|---------------|
| `--detect-tech`     | Detect technologies from HTML and headers               | `false`       |
| `--security-check`  | Report header, cookie and TLS problems as findings      | `false`       |
| `--cert-info`       | Include TLS certificate details                         | `false`       |
| `--analyze-content` | Analyze page content (words, links, metadata, forms)    | `false`       |
| `--screenshots`     | Capture screenshots of active domains                   | `false`       |
| `--screenshot-dir`  | Screenshot subdirectory (under the output directory)    | `screenshots` |
| `--export`          | Base path for a bundled report                          | `""`          |
| `--output-format`   | Report formats: `csv,json,html,markdown`, or `all`      | `all`         |


## 📁 Output Files

Scanera writes into the output directory (default `results/`):

- `active_domains.txt` – Domains that responded successfully
- `inactive_domains.txt` – Unreachable or failed domains
- `domain_check_log.csv` – Per-domain check log (CSV)
- `scan_results.json` – Full structured results (JSON)

With `--export <path>`: `path.json`, `path.csv`, `path.html`, `path.md` (per `--output-format`).

With `--screenshots`: PNG files under `<output-dir>/<screenshot-dir>/`.

Inactive domains carry an `error` explaining why (DNS failure, connection error,
unexpected status, or the browser check's reason). Reports are listed in input order.


## 🧨 Attack-Surface Mapping & Vulnerability Scanning

Beyond liveness checking, Scanera maps attack surface and produces severity-ranked
**findings** (stored in `scan_results.json` and exportable as SARIF for CI).

### Passive / safe features (no authorization needed)

```bash
# Subdomains (passive crt.sh + DNS brute-force) and scan each one
./scanera scan --subdomains domains.txt
./scanera enum --passive example.com          # passive only, no brute-force

# Full DNS records with wildcard detection
./scanera single --dns example.com

# Versioned tech detection + CVE matching
./scanera single --detect-tech --vuln example.com

# Secret scanning of response bodies (AWS/Google/Slack/GitHub keys, JWTs, ...)
./scanera single --secrets example.com

# Header, cookie and TLS findings
./scanera single --security-check --cert-info example.com

# Subdomain takeover (dangling CNAMEs, unclaimed third-party services)
./scanera scan --subdomains --takeover domains.txt
```

### Active features (require authorization)

Port scanning, sensitive-file probes, template requests and content discovery send
crafted requests to hosts, so they are gated. You must pass either a **scope file**
listing the hosts you are permitted to test, or `--authorize` to assert you own/are
allowed to test every target. Optionally record an audit trail with `--audit-log`.

The scope check applies to the host a target finally redirects to, and active
modules won't follow a redirect that leaves the scope (blocked redirects are logged
to the audit trail). Scope file syntax:

```txt
example.com          # exactly this host
*.example.com        # the domain and all of its subdomains
203.0.113.7          # a single IP address
203.0.113.0/24       # an IP range (IPv4 or IPv6 CIDR)
!dev.example.com     # an exclusion; exclusions always win
```

```bash
# Authorize with a scope file (one host or *.wildcard per line)
./scanera scan --probes --templates --ports --scope scope.txt --audit-log audit.log domains.txt

# Or explicitly authorize all targets (use only on systems you control)
./scanera single --probes --templates example.com --authorize

# Standalone port scan
./scanera ports --authorize --port-spec "80,443,8000-8100" example.com
```

### Deepest, most aggressive scan

`--aggressive` (`-A`) turns on the full battery in one flag: technology and version
detection, security checks, certificates, content analysis, full DNS records,
subdomain enumeration, takeover checks, secret scanning, CVE matching, and same-host
crawling. When
you also pass `--scope` or `--authorize`, it escalates to the active modules too
(probes, templates, port scan with `top1000`, and content discovery).

```bash
# Deep passive/intel sweep (no active requests, no authorization needed)
./scanera scan --aggressive domains.txt

# Everything, including active modules, on authorized targets
./scanera scan --aggressive --scope examples/scope.txt --audit-log audit.log domains.txt
./scanera single --aggressive --authorize example.com

# Deeper crawling and full-range ports, tuned manually
./scanera single --crawl --crawl-depth 3 --max-pages 200 --secrets example.com --authorize
./scanera ports --authorize --port-spec full example.com
```

### Templates (YAML signature engine)

Detection is data-driven. Built-in templates are embedded; add your own directory:

```bash
./scanera templates                              # list and validate templates
./scanera templates --templates-dir ./my-templates
./scanera single --templates --templates-dir ./my-templates example.com --authorize
```

Templates are validated on load: unknown keys, matcher types or severities, bad
regexes and duplicate IDs are errors. Requests can set `headers` and a `body`, and
paths, header values and bodies can use `{{BaseURL}}`, `{{RootURL}}`, `{{Scheme}}`,
`{{Hostname}}` (with port) and `{{Host}}` (without). Matchers support
`negative: true` and `case-insensitive: true`. See `examples/templates/`.

### Automation and CI

```bash
# SARIF for code-scanning dashboards
./scanera scan --detect-tech --vuln --secrets --sarif findings.sarif domains.txt

# Fail the job (exit 2) if anything high or critical turns up
./scanera scan --security-check --takeover --vuln --fail-on high domains.txt

# Pipe targets in and stream results out as JSON lines
subfinder -d example.com -silent | ./scanera scan - --skip-browser --jsonl | jq -c 'select(.active)'

# What changed since the last run? (--fail-on applies to new findings only)
./scanera diff old/scan_results.json results/scan_results.json
./scanera diff --json --fail-on medium old/scan_results.json results/scan_results.json
```

Exit codes: `0` success, `1` error, `2` `--fail-on` threshold reached, `130`
interrupted. On the first Ctrl+C Scanera stops, writes what it has finished and
exits; press Ctrl+C again to quit immediately.

### Profiles, proxy, rate limiting, resume

```bash
./scanera scan --profile profiles/thorough.yaml domains.txt   # saved flag set
./scanera scan --proxy socks5://127.0.0.1:9050 domains.txt    # route through a proxy
./scanera scan --rate 10 domains.txt                          # max 10 req/s
./scanera scan --resume state.json domains.txt                # skip completed domains
```

Profiles reject unknown keys, so a typo fails instead of being ignored; they can't
grant authorization. With `--resume`, completed domains are skipped and their earlier
results are carried forward from `scan_results.json`, so the reports still cover the
whole list. Only domains that finished are recorded; anything interrupted is scanned
again next time.

`--proxy` (and the standard `HTTP_PROXY`/`HTTPS_PROXY` variables) applies to HTTP(S)
requests and the headless browser. DNS lookups and port scans still go out directly.

## 🔐 Responsible Use

Scanera can perform active scanning that sends requests to remote systems. Only scan
hosts you own or have explicit written permission to test. The active features
(`--ports`, `--probes`, `--templates`, `--fuzz`) refuse to run without `--scope` or
`--authorize`, and `--audit-log` records every active action for accountability.

## 🧩 Attack-Surface and Automation Options

| Flag                | Description                                                        |
|---------------------|--------------------------------------------------------------------|
| `--subdomains`      | Enumerate subdomains and scan them too                             |
| `--passive`         | Subdomains: passive sources only (no brute-force)                  |
| `--dns`             | Collect full DNS records (A/AAAA/CNAME/MX/NS/TXT) + wildcard        |
| `--takeover`        | Check for subdomain takeover (dangling CNAMEs, unclaimed services) |
| `--ports`           | Port scan (active; requires scope)                                 |
| `--port-spec`       | Ports: `top`, `top1000` (1-1024), `full`, or a list/range (`80,443,8000-8100`) |
| `--probes`          | Probe for exposed sensitive files (active; requires scope)         |
| `--secrets`         | Scan response bodies for exposed secrets                           |
| `--templates`       | Run YAML signature templates (active; requires scope)              |
| `--templates-dir`   | Directory of additional YAML templates                             |
| `--vuln`            | Match detected tech versions against known CVEs                    |
| `--sarif`           | Write findings to a SARIF file                                     |
| `-A, --aggressive`  | Deepest, most aggressive scan (enables the full suite)             |
| `--crawl`           | Crawl same-host pages and scan them (deeper)                       |
| `--crawl-depth`     | Crawl depth (default 2)                                            |
| `--max-pages`       | Maximum pages to crawl per host (default 50)                       |
| `--fuzz`            | Content/path discovery, aka dir-busting (active; requires scope)   |
| `--subdomain-wordlist` | Custom subdomain wordlist file                                 |
| `--port-spec full`  | Scan all 65535 ports (with `--ports`)                             |
| `--proxy`           | Proxy URL (`http(s)://` or `socks5://`)                            |
| `--rate`            | Max requests per second (0 = unlimited)                            |
| `--scope`           | Scope file authorizing hosts for active scanning                   |
| `--authorize`       | Authorize active scanning of all targets                           |
| `--audit-log`       | Append an audit trail of active actions                            |
| `--resume`          | Resume file: skip domains completed in a prior run                 |
| `--profile`         | YAML profile of flag overrides                                     |
| `--jsonl`           | Stream each result to stdout as a JSON line                        |
| `--fail-on`         | Exit 2 if a finding is at or above `info`/`low`/`medium`/`high`/`critical` |

## 🛠️ Troubleshooting

- **Unknown command** – Use `scan` or `single` (e.g. `./scanera scan domains.txt`).
- **No subdomains found** – Certificate-transparency services are slow and rate-limited; Scanera prints a warning when a source fails. Retry later or add `--subdomain-wordlist`.
- **Browser errors** – Install Chrome or Chromium, or pass `--skip-browser`.
- **Slow scans** – Raise `-c`, lower `-t`, or pass `--skip-browser`.

### Check Chrome installation

```bash
which google-chrome chromium chromium-browser
```

### Minimal run (no DNS, no browser)

```bash
./scanera scan --skip-dns --skip-browser domains.txt
```


## 🔍 Use Cases

- **Website monitoring** – Confirm domains are live and correctly configured
- **Security review** – Inspect HTTPS, headers, and certificates at a glance
- **Technology discovery** – Identify the stack behind a site
- **Domain portfolio management** – Track large sets of domains


## 📦 Requirements

- Go 1.21+
- Chrome or Chromium (only for browser-based features and screenshots)


## 🤝 Contributing

Contributions are welcome:

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-feature`
3. Commit your changes
4. Push and open a Pull Request


## 📄 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file.


Built with ❤️ by [Sla0ui](https://github.com/Sla0ui)
