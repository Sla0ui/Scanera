# Scanera

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**Scanera** is a powerful domain analysis and validation tool that performs comprehensive checks using DNS resolution, HTTP(S) requests, browser-based rendering, technology detection, and security assessments.

![S](https://github.com/user-attachments/assets/ef5a17fe-b719-422e-a252-78723f3b5d95)


## 🚀 Features

- **Multi-layer validation** – DNS resolution, HTTP/HTTPS requests, and headless browser checks  
- **Technology detection** – Identify CMSs, frameworks, libraries, and server software  
- **Security assessment** – Inspect HTTPS configuration, security headers, and TLS certificates  
- **Screenshot capture** – Full-page screenshots of active domains  
- **Content analysis** – Analyze page content, links, and metadata  
- **High performance** – Process thousands of domains with intelligent concurrency  
- **Comprehensive reporting** – Generate results in various formats  
- **User-friendly CLI** – Progress bars, statistics, and intuitive commands  



## 🛠️ Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/Sla0ui/scanera.git
cd scanera

# Build the application
go build -o scanera

# Run from current directory
./scanera --help

# (Optional) Make it available system-wide
sudo cp scanera /usr/local/bin/
```



## ⚡ Quick Start

1. Create a text file with one domain per line:

```txt
example.com
github.com
invalid-domain-12345.com
```

2. Run a domain check:

```bash
./scanera check domains.txt
```

3. View the results in the `results` directory.



## 🧭 Command Structure

Scanera uses a subcommand structure. Main commands include:

```
check        - Scan domains from a file
single       - Scan a single domain
tech         - Detect technologies
screenshot   - Take a screenshot
security     - Check security headers
report       - Generate a report
list         - List previous scan results
batch        - Process domain files in batch
```


## 💡 Usage Examples

### Check Domains from a File

```bash
./scanera check domains.txt
./scanera check -s "200,301,302" -t 15s -c 10 -o results domains.txt
./scanera check --screenshots --detect-tech --security-check domains.txt
./scanera check --force-https domains.txt
```

### Check a Single Domain

```bash
./scanera single example.com
./scanera single -v --detect-tech example.com
```

### Detect Technologies

```bash
./scanera tech example.com
```

### Take a Screenshot

```bash
./scanera screenshot example.com
./scanera screenshot -w 1920 -h 1080 -o custom_output.png example.com
```

### Check Security Headers

```bash
./scanera security example.com
```

### Generate a Report

```bash
./scanera report -i results/scan_results.json -o report -f html
```

### List Results

```bash
./scanera list
./scanera list -t active
./scanera list -c
```

### Batch Process Domains

```bash
./scanera batch domain_directory/
./scanera batch -p "*.csv" -C 2 domain_directory/
```



## ⚙️ Command Line Options

### Basic Options

| Flag                  | Description                                             | Default                                 |
|-----------------------|---------------------------------------------------------|-----------------------------------------|
| `-s, --status-codes`  | Successful HTTP status codes                            | `200`                                   |
| `-t, --timeout`       | Timeout for HTTP requests                               | `10s`                                   |
| `-r, --retries`       | Retries for failed requests                             | `2`                                     |
| `-c, --concurrency`   | Concurrent checks                                       | `5`                                     |
| `-T, --verify-tls`    | Verify TLS certificates                                 | `false`                                 |
| `-u, --user-agent`    | User-Agent string                                       | `Mozilla/5.0 (compatible; Scanera/1.0)` |
| `-o, --output-dir`    | Output directory                                        | `results`                               |
| `-v, --verbose`       | Verbose logging                                         | `false`                                 |
| `-n, --no-color`      | Disable color output                                    | `false`                                 |
| `-f, --format`        | Output format (`text`, `json`, `csv`)                   | `text`                                  |
| `-q, --quiet`         | Suppress terminal output                                | `false`                                 |
| `--browser-timeout`   | Timeout for browser-based checks                        | `20s`                                   |
| `--no-progress`       | Disable progress bar                                    | `false`                                 |
| `--force-https`       | Only scan HTTPS URLs                                    | `false`                                 |
| `--skip-dns`          | Skip DNS resolution                                     | `false`                                 |
| `--skip-browser`      | Skip browser-based checks                               | `false`                                 |

### Advanced Options

| Flag                  | Description                                             | Default      |
|-----------------------|---------------------------------------------------------|--------------|
| `--screenshots`       | Take screenshots of active domains                      | `false`      |
| `--screenshot-dir`    | Screenshot output directory                             | `screenshots`|
| `--detect-tech`       | Enable technology detection                             | `false`      |
| `--security-check`    | Check security headers                                  | `false`      |
| `--output-format`     | Report formats (comma-separated: csv,json,html,text)    | `all`        |
| `--analyze-content`   | Analyze page keywords and structure                     | `false`      |
| `--batch-size`        | Batch size for domain processing                        | `100`        |
| `--webhook`           | Webhook URL for result delivery                         | `""`         |
| `--compare`           | Compare with previous scan                              | `false`      |
| `--export`            | Path to export bundled report                           | `""`         |
| `--max-redirects`     | Max redirects to follow                                 | `10`         |
| `--cert-info`         | Include TLS certificate info                            | `false`      |



## 🛠️ Troubleshooting

### Common Issues

- **Command not found** – Use `./scanera` or ensure it's in your PATH  
- **Unknown command** – Use correct subcommand (e.g., `./scanera check domains.txt`)  
- **Browser errors** – Ensure Chrome or Chromium is installed  
- **Slow scans** – Adjust concurrency and timeouts or use `--skip-browser`  
- **Memory issues** – Use batching with `--batch-size`  

### Check Chrome Installation

```bash
which google-chrome
which chromium-browser
```

### Minimal Run

```bash
./scanera check --skip-browser --skip-dns domains.txt
```



## 📁 Output Files

Scanera generates output in the specified directory:

- `active_domains.txt` – Successfully scanned domains  
- `inactive_domains.txt` – Unreachable or failed domains  
- `domain_check_log.csv` – Basic check results (CSV)  
- `scan_results.json` – Full JSON report  

With advanced features:
- `screenshots/` – Screenshot images of domains



## 🔍 Use Cases

- **Website monitoring** – Ensure your domains are live and secure  
- **Security audits** – Check HTTPS and headers  
- **Tech discovery** – Identify stack of any site  
- **Domain portfolio management** – Keep tabs on large sets of domains  
- **Competitive analysis** – Spy on competitors’ tech stacks



## 📦 Requirements

- Go 1.18+  
- Chrome or Chromium (for browser-based features)



## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repo  
2. Create a branch: `git checkout -b feature/my-feature`  
3. Commit your changes: `git commit -m 'Add my feature'`  
4. Push: `git push origin feature/my-feature`  
5. Open a Pull Request



## 📄 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file.



Built with ❤️ by [Sla0ui](https://github.com/Sla0ui)
