# Scanera - Quick Start Guide

## Installation

### Requirements
- Go 1.21 or higher
- Chrome or Chromium browser (for browser-based checks)

### Build from Source
```bash
cd /path/to/scanera
go mod download
go build -o scanera ./cmd/scanera
```

### Verify Installation
```bash
./scanera --version
```

## Basic Usage

### 1. Prepare Your Domain List
Create a text file with one target per line. Bare hosts, `host:port` and full
URLs all work; duplicates are dropped:

```txt
# domains.txt
example.com
https://github.com/
api.example.com:8443
```

### 2. Run a Basic Scan
```bash
./scanera scan domains.txt

# or pipe targets in from another tool
cat domains.txt | ./scanera scan -
```

### 3. Check the Results
Results are saved in the `results/` directory:
- `active_domains.txt` - Successfully scanned domains
- `inactive_domains.txt` - Unreachable domains
- `domain_check_log.csv` - Detailed CSV log
- `scan_results.json` - Complete JSON results

## Common Use Cases

### Fast Scan (Skip Browser Checks)
```bash
./scanera scan --skip-browser domains.txt
```

### Comprehensive Scan
```bash
./scanera scan \
  --detect-tech \
  --security-check \
  --screenshots \
  --analyze-content \
  domains.txt
```

### High Concurrency Scan
```bash
./scanera scan -c 20 domains.txt
```

### HTTPS Only
```bash
./scanera scan --force-https domains.txt
```

### Custom Timeout
```bash
./scanera scan -t 30s domains.txt
```

### Generate HTML Report
```bash
./scanera scan \
  --export reports/report \
  --output-format html \
  domains.txt
```

### Fail a CI Job on Serious Findings
```bash
./scanera scan --security-check --takeover --vuln --sarif findings.sarif --fail-on high domains.txt
# exit status 2 when any finding is high or critical
```

### Compare Two Runs
```bash
./scanera diff last-week/scan_results.json results/scan_results.json
```

## Configuration Examples

### Security-Focused Scan
```bash
./scanera scan \
  --security-check \
  --cert-info \
  --force-https \
  --verify-tls \
  domains.txt
```

### Technology Stack Analysis
```bash
./scanera scan \
  --detect-tech \
  --analyze-content \
  --export tech-report \
  --output-format html,json \
  domains.txt
```

### Screenshot Collection
```bash
./scanera scan \
  --screenshots \
  --screenshot-dir screenshots \
  domains.txt
```

## Flags Reference

### Essential Flags
- `-c, --concurrency` - Number of concurrent scans (default: 5)
- `-t, --timeout` - Request timeout (default: 10s)
- `-o, --output-dir` - Output directory (default: results)

### Feature Flags
- `--detect-tech` - Detect technologies used
- `--security-check` - Report missing security headers, weak cookies and TLS problems
- `--takeover` - Look for dangling CNAMEs and unclaimed third-party services
- `--screenshots` - Take screenshots of pages
- `--analyze-content` - Analyze page content
- `--cert-info` - Include certificate details

### Performance Flags
- `--skip-browser` - Skip browser-based checks (faster)
- `--skip-dns` - Skip DNS resolution
- `--force-https` - Only check HTTPS

### Output Flags
- `--export PATH` - Export report to path
- `--output-format FORMATS` - Output formats (csv,json,html,markdown)
- `--jsonl` - Stream each result to stdout as one JSON line
- `--fail-on SEVERITY` - Exit with status 2 if a finding meets the severity
- `-q, --quiet` - Quiet mode
- `-v, --verbose` - Verbose logging

Progress and status messages go to stderr, so stdout stays clean for piping.

## Troubleshooting

### "go: command not found"
Install Go from https://golang.org/dl/

### "Chrome not found" Error
Install Chrome or Chromium:
```bash
# Ubuntu/Debian
sudo apt install chromium-browser

# macOS
brew install --cask google-chrome

# Or skip browser checks:
./scanera scan --skip-browser domains.txt
```

### Permission Denied
Make sure the binary is executable:
```bash
chmod +x scanera
```

### Slow Scans
- Increase concurrency: `-c 20`
- Skip browser checks: `--skip-browser`
- Reduce timeout: `-t 5s`

## Running Tests

### Run All Tests
```bash
go test ./...
```

### With Coverage
```bash
go test -cover ./...
```

### With Race Detection
```bash
go test -race ./...
```

## Development

### Project Structure
```
cmd/scanera/          - CLI entry point
internal/models/      - Config, Result and Finding types
internal/scanner/     - Scan orchestration, HTTP and browser checks
internal/posture/     - Header, cookie and TLS findings
internal/takeover/    - Subdomain takeover checks
internal/detector/    - Technology and version detection
internal/analyzer/    - Content analysis
internal/subdomain/   - Passive and brute-force subdomain discovery
internal/probe/       - Sensitive-file probes (active)
internal/discovery/   - Content discovery (active)
internal/signature/   - YAML template engine (active)
internal/portscan/    - TCP port scanning (active)
internal/vuln/        - Version-to-CVE matching
internal/secrets/     - Secret detection in responses
internal/scope/       - Authorization scope and audit log
internal/reporter/    - JSON, CSV, HTML, Markdown and SARIF output
internal/diff/        - Comparing two runs
```

See `ARCHITECTURE.md` for how these fit together.

### Adding Tests
```bash
# Create test file
touch internal/yourpackage/yourfile_test.go

# Run specific package tests
go test -v ./internal/yourpackage
```

### Linting
```bash
# Install golangci-lint (the config uses the v2 format)
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6

# Run linter
golangci-lint run
```

## Next Steps

1. **Read the full documentation**: `README.md`
2. **Understand the architecture**: `ARCHITECTURE.md`
3. **Contribute**: See GitHub repository

## Support

- **Issues**: https://github.com/Sla0ui/scanera/issues
- **Documentation**: See README.md
- **Architecture**: See ARCHITECTURE.md

---

**Happy Scanning! 🚀**
