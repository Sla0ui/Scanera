## # Scanera Architecture Documentation

## Overview

Scanera v2.0 follows Clean Architecture principles with clear separation of concerns. The codebase is organized into distinct layers that can be tested independently.

## Design Principles

### 1. **Separation of Concerns**
- Each package has a single, well-defined responsibility
- Business logic is isolated from CLI concerns
- Data models are independent of implementation details

### 2. **Dependency Injection**
- No global mutable state
- Configuration passed explicitly to components
- Scanner accepts Config, not global variables

### 3. **Interface-Based Design** (Future)
```go
type Scanner interface {
    ScanDomain(ctx context.Context, domain string, browserCtx context.Context) *models.Result
    ScanDomains(ctx context.Context, domains []string) ([]*models.Result, error)
}

type Reporter interface {
    WriteResultsToFiles() error
    GenerateReport(outputPath, format string) error
}
```

### 4. **Error Handling**
- All errors are wrapped with context using `fmt.Errorf("context: %w", err)`
- Functions that can fail return `error`
- No silent failures

## Package Structure

### `cmd/scanera`
**Purpose**: CLI interface and user interaction

**Responsibilities**:
- Parse command-line flags
- Display output to user (colored, formatted)
- Coordinate between scanner and reporter
- Handle graceful shutdown (SIGTERM, SIGINT)

**Does NOT**:
- Contain business logic
- Directly manipulate results
- Know implementation details of scanning

### `internal/models`
**Purpose**: Core data structures

**Key Types**:
- `Config` - All configuration options with validation
- `Result` - Comprehensive scan results
- `ServerInfo` - HTTP server information
- `SecurityInfo` - Security assessment data
- `ContentInfo` - Page content analysis

**Features**:
- Validation methods (`Config.Validate()`)
- Safe cloning (`Config.Clone()`)
- JSON serialization tags

### `internal/scanner`
**Purpose**: Domain scanning operations

**Sub-modules**:
- `dns.go` - DNS resolution with timeout
- `http.go` - HTTP requests with retries
- `browser.go` - Headless browser automation
- `scanner.go` - Orchestration and concurrency

**Key Functions**:
```go
// Create new scanner with validated config
func New(config *models.Config) (*Scanner, error)

// Scan single domain
func (s *Scanner) ScanDomain(ctx context.Context, domain string, browserCtx context.Context) *models.Result

// Scan multiple domains concurrently
func (s *Scanner) ScanDomains(ctx context.Context, domains []string) ([]*models.Result, error)
```

**Concurrency Model**:
- Worker pool pattern
- Each worker has own browser context
- Results collected via channel
- Graceful cancellation via context

### `internal/detector`
**Purpose**: Technology fingerprinting

**Features**:
- Pre-compiled regex patterns (performance)
- Content and header analysis
- Technology categorization
- No false positive guarantees (heuristic-based)

**Pattern Initialization**:
```go
var (
    techPatterns     map[string]*regexp.Regexp
    techPatternsOnce sync.Once
)

func initTechPatterns() {
    // Compiled once, used many times
}
```

### `internal/analyzer`
**Purpose**: Content analysis and extraction

**Capabilities**:
- Word count
- Link analysis (internal vs external)
- Meta tag extraction (description, keywords, language)
- Form detection (login forms)
- Social profile detection
- Parked domain detection

**Performance**:
- Regex patterns pre-compiled with `sync.Once`
- No external dependencies
- Fast pattern matching

### `internal/reporter`
**Purpose**: Result output and formatting

**Formats Supported**:
- JSON (structured data)
- CSV (spreadsheet import)
- HTML (visual reports)
- Markdown (documentation)
- Plain text (active/inactive lists)

**Design**:
- Reporter initialized with results
- Generate multiple formats from single dataset
- No side effects on original data

## Data Flow

```
┌─────────────┐
│   User CLI  │
└──────┬──────┘
       │ Commands
       ↓
┌─────────────────┐
│  cmd/scanera    │  Parse flags, create Config
└──────┬──────────┘
       │ Config
       ↓
┌─────────────────┐
│ scanner.New()   │  Validate config
└──────┬──────────┘
       │ Scanner
       ↓
┌─────────────────────────────┐
│ scanner.ScanDomains()       │
│                             │
│  ┌──────────────┐          │
│  │  Worker Pool │          │
│  └──────┬───────┘          │
│         │                   │
│    ┌────▼────┐             │
│    │ DNS     │ → ResolveDomain()
│    └────┬────┘             │
│         │                   │
│    ┌────▼────┐             │
│    │ HTTP    │ → TryHTTPRequest()
│    └────┬────┘             │
│         │                   │
│    ┌────▼────┐             │
│    │ Browser │ → PerformBrowserCheck()
│    └────┬────┘             │
│         │                   │
│    ┌────▼────┐             │
│    │ Detector│ → DetectTechnologies()
│    └────┬────┘             │
│         │                   │
│    ┌────▼────┐             │
│    │ Analyzer│ → AnalyzePageContent()
│    └────┬────┘             │
│         │                   │
│         ▼                   │
│    []*Result               │
└─────────┬───────────────────┘
          │
          ↓
┌─────────────────┐
│ reporter.New()  │
└──────┬──────────┘
       │
       ↓
┌──────────────────────────┐
│ WriteResultsToFiles()    │ → CSV, JSON, TXT
└──────┬───────────────────┘
       │
       ↓
┌──────────────────────────┐
│ GenerateReport()         │ → HTML, Markdown
└──────┬───────────────────┘
       │
       ↓
┌──────────────┐
│  Disk Files  │
└──────────────┘
```

## Concurrency Strategy

### Worker Pool Pattern
```go
// Create worker pool
numWorkers := config.MaxConcurrentChecks
workCh := make(chan string, len(domains))
resultCh := make(chan *models.Result, len(domains))

// Start workers
for i := 0; i < numWorkers; i++ {
    go func(workerID int) {
        browserCtx, cancel := chromedp.NewContext(allocCtx)
        defer cancel()

        for domain := range workCh {
            result := s.ScanDomain(ctx, domain, browserCtx)
            resultCh <- result
        }
    }(i)
}
```

### Benefits:
- Controlled concurrency (no resource exhaustion)
- Browser context reuse per worker
- Graceful cancellation via context
- Progress tracking via channel

### Race Condition Prevention:
- Config is cloned before passing to goroutines
- No shared mutable state
- Results collected via channel (MPSC pattern)
- Mutex for file appends only

## Performance Considerations

### 1. Regex Pre-compilation
**Before** (v1.0):
```go
// Compiled on EVERY domain scan!
pattern := regexp.MustCompile(`wordpress|wp-content`)
```

**After** (v2.0):
```go
var (
    techPatterns map[string]*regexp.Regexp
    techPatternsOnce sync.Once
)

// Compiled ONCE at startup
func initTechPatterns() {
    techPatterns["WordPress"] = regexp.MustCompile(`wordpress|wp-content`)
}
```

**Impact**: ~100x faster for repeated scans

### 2. Connection Pooling
```go
transport := &http.Transport{
    DisableKeepAlives: false,  // Reuse connections
    MaxIdleConns:      100,
    IdleConnTimeout:   90 * time.Second,
}
```

### 3. Browser Context Reuse
- One browser context per worker (not per domain)
- Reduced Chrome startup overhead
- Memory efficiency

## Security Design

### Defense in Depth
1. **TLS Verification** - Enabled by default
2. **Input Validation** - Config.Validate()
3. **Context Timeouts** - Prevent hanging requests
4. **Resource Limits** - Max concurrency, redirects
5. **Error Handling** - No silent failures

### Threat Model
**Protected Against**:
- Certificate MITM attacks (TLS verification)
- Infinite redirects (MaxRedirects limit)
- Resource exhaustion (concurrency limits)
- Timeouts (context deadlines)

**Not Protected Against** (user responsibility):
- Rate limiting (coming in future version)
- IP blocking
- WAF detection

## Testing Strategy

### Unit Tests
- Test individual functions in isolation
- Mock external dependencies
- Table-driven tests for multiple scenarios

### Example:
```go
func TestConfigValidate(t *testing.T) {
    tests := []struct {
        name    string
        config  *Config
        wantErr bool
    }{
        {"valid", DefaultConfig(), false},
        {"invalid timeout", &Config{Timeout: 0}, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.config.Validate()
            if (err != nil) != tt.wantErr {
                t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Integration Tests (Future)
- Mock HTTP server
- Complete scan workflow
- Error propagation

## Extension Points

### Adding New Output Formats
```go
// In reporter package
func (r *Reporter) GenerateXML(outputPath string) error {
    // Implementation
}

// Register in GenerateReport()
case "xml":
    r.GenerateXML(outputBase + ".xml")
```

### Adding New Technology Detectors
```go
// In detector/technology.go
func initTechPatterns() {
    techPatterns["NewTech"] = regexp.MustCompile(`pattern`)
}
```

### Adding New Content Analyzers
```go
// In analyzer/content.go
func AnalyzePageContent(content string, result *models.Result) {
    // Add new analysis
    result.ContentInfo.NewField = analyzeNewThing(content)
}
```

## Future Architecture Improvements

### 1. Plugin System
```go
type Plugin interface {
    Name() string
    Analyze(result *Result) error
}
```

### 2. Middleware Pattern
```go
type Middleware func(Scanner) Scanner

func WithLogging(s Scanner) Scanner { ... }
func WithRetry(s Scanner) Scanner { ... }
```

### 3. Configuration DSL
```yaml
profiles:
  fast:
    concurrency: 20
    skip_browser: true
  thorough:
    concurrency: 5
    detect_tech: true
    screenshots: true
```

## Dependency Graph

```
cmd/scanera
    ├── internal/models
    ├── internal/scanner
    │   └── internal/models
    ├── internal/reporter
    │   └── internal/models
    └── external/cobra, fatih/color

internal/scanner
    ├── internal/models
    ├── internal/detector
    ├── internal/analyzer
    └── external/chromedp, progressbar

internal/detector
    └── internal/models

internal/analyzer
    └── internal/models

internal/reporter
    └── internal/models
```

**Key Insight**: Models have zero dependencies (pure data structures)

---

**Maintained by**: [Sla0ui](https://github.com/Sla0ui)
**Last Updated**: 2025-01-XX

---

## v2.1: Attack-Surface Mapping, Intelligence, and Safety

v2.1 extends the pipeline from passive validation into attack-surface mapping and
vulnerability scanning, organized as independent, testable packages.

### New packages

**Tier 1 — attack-surface mapping**
- `internal/dnsx` — full DNS record resolution (A/AAAA/CNAME/MX/NS/TXT) and wildcard detection.
- `internal/subdomain` — subdomain discovery via passive certificate transparency (crt.sh) and a DNS brute-force over an embedded wordlist.
- `internal/portscan` — concurrent TCP connect scanning with service identification and optional banner grabbing.
- `internal/probe` — safe GET probes for commonly exposed sensitive files (`.git/config`, `.env`, backups, actuators), emitting findings.
- `internal/secrets` — regex scanning of response bodies for exposed credentials and keys.

**Tier 2 — intelligence layer**
- `internal/signature` — a data-driven, nuclei-style YAML template engine (status/word/regex matchers) with embedded built-in templates and a user template directory. Replaces hardcoded checks with extensible data.
- `internal/detector` (extended) — `DetectWithVersions` extracts technology versions to feed the matcher.
- `internal/vuln` — maps detected technology versions to known CVEs using an embedded, extensible JSON database with a simple version comparator.
- `internal/reporter` (extended) — `GenerateSARIF` emits SARIF 2.1.0 for CI code-scanning ingestion.

**Tier 3 — hardening and safety**
- `internal/ratelimit` — dependency-free token-bucket limiter for polite scanning.
- `internal/netx` — shared HTTP client builder with proxy support (http/https/socks5).
- `internal/scope` — an authorization gate (scope file or `--authorize`) plus an audit log. Active modules (ports, probes, templates) run only against in-scope hosts.
- `internal/state` — persists completed domains so interrupted scans resume.
- `internal/profile` — applies a YAML profile of flag overrides onto a Config.

### The Finding model

All detection modules emit a common `models.Finding` (id, title, severity, source,
evidence, location, references, tags, CVEs), attached to each `Result` and sorted by
severity. This is the single shape consumed by JSON, SARIF, and the terminal summary.

### Orchestration

`scanner.Scanner` now holds shared resources (HTTP client, rate limiter, scope,
template engine). After the base HTTP scan of a domain, `enrich()` runs the enabled
modules in order, gating the active ones behind scope authorization.
