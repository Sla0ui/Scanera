# Scanera

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**Scanera** is a domain analysis and validation tool. It checks whether domains are live and gathers intelligence about them using DNS resolution, HTTP(S) requests, headless-browser rendering, technology detection, and security assessment.

![S](https://github.com/user-attachments/assets/ef5a17fe-b719-422e-a252-78723f3b5d95)


## 🚀 Features

- **Multi-layer validation** – DNS resolution, HTTP/HTTPS requests, and headless-browser checks
- **Technology detection** – Identify CMSs, frameworks, libraries, and server software
- **Security assessment** – Inspect HTTPS configuration, security headers, and TLS certificates
- **Screenshot capture** – Full-page screenshots of active domains
- **Content analysis** – Word counts, links, metadata, login-form and parked-domain detection
- **High performance** – Process thousands of domains with a bounded worker pool
- **Comprehensive reporting** – JSON, CSV, HTML, and Markdown output
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
scan      [flags] DOMAIN_FILE   Scan every domain listed in a file
single    [flags] DOMAIN        Scan a single domain
enum      [flags] DOMAIN        Enumerate subdomains (passive crt.sh + DNS brute-force)
ports     [flags] HOST          TCP port scan (active; requires authorization)
templates [flags]               List loaded signature templates
```

All commands accept the same flags.


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
| `--security-check`  | Check security headers (HTTPS responses)                | `false`       |
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
```

### Active features (require authorization)

Port scanning, sensitive-file probes, and template requests send crafted requests
to hosts, so they are gated. You must pass either a **scope file** listing the hosts
you are permitted to test, or `--authorize` to assert you own/are allowed to test
every target. Optionally record an audit trail with `--audit-log`.

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
detection, security headers, certificates, content analysis, full DNS records,
subdomain enumeration, secret scanning, CVE matching, and same-host crawling. When
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
./scanera templates                              # list loaded templates
./scanera single --templates --templates-dir ./my-templates example.com --authorize
```

### SARIF output for CI

```bash
./scanera scan --detect-tech --vuln --secrets --sarif findings.sarif domains.txt
```

### Profiles, proxy, rate limiting, resume

```bash
./scanera scan --profile profiles/thorough.yaml domains.txt   # saved flag set
./scanera scan --proxy socks5://127.0.0.1:9050 domains.txt    # route through a proxy
./scanera scan --rate 10 domains.txt                          # max 10 req/s
./scanera scan --resume state.json domains.txt                # skip completed domains
```

## 🔐 Responsible Use

Scanera can perform active scanning that sends requests to remote systems. Only scan
hosts you own or have explicit written permission to test. The active features
(`--ports`, `--probes`, `--templates`) refuse to run without `--scope` or `--authorize`,
and `--audit-log` records every active action for accountability.

## 🧩 New Command-Line Options

| Flag                | Description                                                        |
|---------------------|--------------------------------------------------------------------|
| `--subdomains`      | Enumerate subdomains and scan them too                             |
| `--passive`         | Subdomains: passive sources only (no brute-force)                  |
| `--dns`             | Collect full DNS records (A/AAAA/CNAME/MX/NS/TXT) + wildcard        |
| `--ports`           | Port scan (active; requires scope)                                 |
| `--port-spec`       | Ports: `top`, `top1000`, or a list/range (`80,443,8000-8100`)      |
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

## 🛠️ Troubleshooting

- **Unknown command** – Use `scan` or `single` (e.g. `./scanera scan domains.txt`).
- **Browser errors** – Install Chrome or Chromium, or pass `--skip-browser`.
- **Slow scans** – Raise `-c`, lower `-t`, or pass `--skip-browser`.

### Check Chrome installation

```bash
which google-chrome || which chromium-browser
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
