package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Sla0ui/scanera/internal/diff"
	"github.com/Sla0ui/scanera/internal/models"
	"github.com/Sla0ui/scanera/internal/netx"
	"github.com/Sla0ui/scanera/internal/portscan"
	"github.com/Sla0ui/scanera/internal/profile"
	"github.com/Sla0ui/scanera/internal/ratelimit"
	"github.com/Sla0ui/scanera/internal/reporter"
	"github.com/Sla0ui/scanera/internal/scanner"
	"github.com/Sla0ui/scanera/internal/scope"
	"github.com/Sla0ui/scanera/internal/signature"
	"github.com/Sla0ui/scanera/internal/state"
	"github.com/Sla0ui/scanera/internal/subdomain"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// flagSet aliases pflag.FlagSet for the small flag-reading helpers below.
type flagSet = pflag.FlagSet

// version is overridden at build time: go build -ldflags "-X main.version=v2.1.0"
var version = "2.1.0"

// Exit codes beyond the usual 0/1.
const (
	exitFindings    = 2   // --fail-on threshold reached
	exitInterrupted = 130 // stopped by Ctrl+C / SIGTERM
)

// Human-readable output goes to stderr so stdout stays clean for data
// (--jsonl, enum results, port tables) that is meant to be piped.
var logOut io.Writer = os.Stderr

var (
	green   = color.New(color.FgGreen).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	blue    = color.New(color.FgBlue).SprintFunc()
	cyan    = color.New(color.FgCyan).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
)

func logo() string {
	return `

 @@@@@@    @@@@@@@   @@@@@@   @@@  @@@  @@@@@@@@  @@@@@@@    @@@@@@
@@@@@@@   @@@@@@@@  @@@@@@@@  @@@@ @@@  @@@@@@@@  @@@@@@@@  @@@@@@@@
!@@       !@@       @@!  @@@  @@!@!@@@  @@!       @@!  @@@  @@!  @@@
!@!       !@!       !@!  @!@  !@!!@!@!  !@!       !@!  @!@  !@!  @!@
!!@@!!    !@!       @!@!@!@!  @!@ !!@!  @!!!:!    @!@!!@!   @!@!@!@!
 !!@!!!   !!!       !!!@!!!!  !@!  !!!  !!!!!:    !!@!@!    !!!@!!!!
     !:!  :!!       !!:  !!!  !!:  !!!  !!:       !!: :!!   !!:  !!!
    !:!   :!:       :!:  !:!  :!:  !:!  :!:       :!:  !:!  :!:  !:!
:::: ::    ::: :::  ::   :::   ::   ::   :: ::::  ::   :::  ::   :::
:: : :     :: :: :   :   : :  ::    :   : :: ::    :   : :   :   : :
                                                By github.com/Sla0ui
                                                     Version ` + version + `
`
}

// exitError carries a specific process exit code out of a command.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func logf(format string, args ...any) { fmt.Fprintf(logOut, format, args...) }

func main() {
	reporter.Version = version

	rootCmd := &cobra.Command{
		Use:           "scanera",
		Short:         "A domain analysis, attack-surface mapping, and vulnerability-scanning tool",
		Long:          logo() + "\n\nScanera validates domains and maps their attack surface using DNS, HTTP(S),\nheadless-browser checks, technology and version detection, subdomain enumeration,\nport scanning, safe active probes, a YAML signature engine, and CVE matching.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	scanCmd := &cobra.Command{
		Use:   "scan [flags] DOMAIN_FILE",
		Short: "Scan every domain listed in a file (use - to read from stdin)",
		Args:  cobra.ExactArgs(1),
		RunE:  runScan,
	}
	addScanFlags(scanCmd)
	rootCmd.AddCommand(scanCmd)

	singleCmd := &cobra.Command{
		Use:   "single [flags] DOMAIN",
		Short: "Scan a single domain",
		Args:  cobra.ExactArgs(1),
		RunE:  runSingle,
	}
	addScanFlags(singleCmd)
	rootCmd.AddCommand(singleCmd)

	enumCmd := &cobra.Command{
		Use:   "enum [flags] DOMAIN",
		Short: "Enumerate subdomains (passive certificate transparency + DNS brute-force)",
		Args:  cobra.ExactArgs(1),
		RunE:  runEnum,
	}
	addScanFlags(enumCmd)
	rootCmd.AddCommand(enumCmd)

	portsCmd := &cobra.Command{
		Use:   "ports [flags] HOST",
		Short: "TCP port scan of a host (requires --scope or --authorize)",
		Args:  cobra.ExactArgs(1),
		RunE:  runPorts,
	}
	addScanFlags(portsCmd)
	rootCmd.AddCommand(portsCmd)

	templatesCmd := &cobra.Command{
		Use:   "templates [flags]",
		Short: "List and validate signature templates",
		Args:  cobra.NoArgs,
		RunE:  runTemplates,
	}
	addScanFlags(templatesCmd)
	rootCmd.AddCommand(templatesCmd)

	diffCmd := &cobra.Command{
		Use:   "diff [flags] OLD_RESULTS.json NEW_RESULTS.json",
		Short: "Show what changed between two scan_results.json files",
		Args:  cobra.ExactArgs(2),
		RunE:  runDiff,
	}
	diffCmd.Flags().Bool("json", false, "Print the diff as JSON")
	diffCmd.Flags().String("fail-on", "", "Exit with status 2 if a new finding is at or above this severity")
	diffCmd.Flags().BoolP("no-color", "n", false, "Disable colorized output")
	rootCmd.AddCommand(diffCmd)

	if err := rootCmd.Execute(); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintln(os.Stderr, ee.msg)
			}
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, red("Error:"), err)
		os.Exit(1)
	}
}

func addScanFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	// Basic
	f.StringP("status-codes", "s", "200", "Comma-separated successful HTTP status codes")
	f.DurationP("timeout", "t", 10*time.Second, "Timeout for HTTP requests")
	f.IntP("retries", "r", 2, "Number of retries for failed requests")
	f.IntP("concurrency", "c", 5, "Maximum concurrent checks")
	f.BoolP("verify-tls", "T", true, "Verify TLS certificates")
	f.StringP("user-agent", "u", models.DefaultUserAgent, "User agent string")
	f.StringP("output-dir", "o", "results", "Output directory")
	f.BoolP("verbose", "v", false, "Enable verbose logging")
	f.BoolP("no-color", "n", false, "Disable colorized output")
	f.BoolP("quiet", "q", false, "Quiet mode - only output to files")
	f.Bool("no-progress", false, "Disable progress bar")
	f.Bool("force-https", false, "Only check HTTPS")
	f.Bool("skip-dns", false, "Skip DNS resolution")
	f.Bool("skip-browser", false, "Skip browser-based checks")
	f.Int("max-redirects", 10, "Maximum redirects to follow")

	// Feature
	f.Bool("detect-tech", false, "Detect technologies")
	f.Bool("security-check", false, "Check security headers, cookies and TLS, and report findings")
	f.Bool("cert-info", false, "Include certificate information")
	f.Bool("analyze-content", false, "Analyze page content")
	f.Bool("screenshots", false, "Take screenshots of active domains")
	f.String("screenshot-dir", "screenshots", "Screenshot directory")
	f.String("export", "", "Export path for a bundled report")
	f.String("output-format", "all", "Report formats (csv,json,html,markdown) or all")

	// Tier 1: attack-surface mapping
	f.Bool("subdomains", false, "Enumerate subdomains and scan them too")
	f.Bool("passive", false, "Subdomains: passive sources only (no brute-force)")
	f.Bool("dns", false, "Collect full DNS records (A/AAAA/CNAME/MX/NS/TXT, wildcard)")
	f.Bool("takeover", false, "Check for subdomain takeover (dangling CNAMEs, unclaimed services)")
	f.Bool("ports", false, "Port scan (active; requires --scope or --authorize)")
	f.String("port-spec", "top", "Ports to scan: top, top1000 (1-1024), full, or a list/range (80,443,8000-8100)")
	f.Bool("probes", false, "Probe for exposed sensitive files (active; requires scope)")
	f.Bool("secrets", false, "Scan response bodies for exposed secrets")
	f.Bool("crawl", false, "Crawl same-host pages and scan them (deeper)")
	f.Int("crawl-depth", 2, "Crawl depth when --crawl is set")
	f.Int("max-pages", 50, "Maximum pages to crawl per host")
	f.Bool("fuzz", false, "Content/path discovery, aka dir-busting (active; requires scope)")
	f.String("subdomain-wordlist", "", "Custom subdomain wordlist file")
	f.BoolP("aggressive", "A", false, "Deepest, most aggressive scan: enables the full suite (active features still require --scope/--authorize)")

	// Tier 2: intelligence
	f.Bool("templates", false, "Run YAML signature templates (active; requires scope)")
	f.String("templates-dir", "", "Directory of additional YAML templates")
	f.Bool("vuln", false, "Match detected tech versions against known CVEs")
	f.String("sarif", "", "Write findings to this SARIF file")

	// Tier 3: hardening and safety
	f.String("proxy", "", "Proxy URL (http(s):// or socks5://)")
	f.Float64("rate", 0, "Max requests per second (0 = unlimited)")
	f.String("scope", "", "Scope file authorizing hosts for active scanning")
	f.Bool("authorize", false, "Authorize active scanning of all targets (use only on systems you own/are permitted to test)")
	f.String("audit-log", "", "Append an audit trail of active actions to this file")
	f.String("resume", "", "Resume file: skip domains already completed in a prior run")
	f.String("profile", "", "YAML profile of flag overrides")

	// Automation
	f.Bool("jsonl", false, "Stream each result to stdout as a JSON line as soon as it finishes")
	f.String("fail-on", "", "Exit with status 2 if any finding is at or above this severity (info|low|medium|high|critical)")
}

func loadConfig(cmd *cobra.Command) (*models.Config, error) {
	config := models.DefaultConfig()

	// Profile layers over defaults; explicit flags (below) layer over the profile.
	if p, _ := cmd.Flags().GetString("profile"); p != "" {
		if err := profile.Apply(p, config); err != nil {
			return nil, err
		}
		config.Profile = p
	}

	f := cmd.Flags()
	if f.Changed("status-codes") {
		s, _ := f.GetString("status-codes")
		var codes []int
		for _, c := range strings.Split(s, ",") {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			n, err := strconv.Atoi(c)
			if err != nil || n < 100 || n > 599 {
				return nil, fmt.Errorf("invalid status code %q in --status-codes", c)
			}
			codes = append(codes, n)
		}
		config.SuccessStatusCodes = codes
	}
	setDur(f, "timeout", &config.Timeout)
	setInt(f, "retries", &config.RetryCount)
	setInt(f, "concurrency", &config.MaxConcurrentChecks)
	setBool(f, "verify-tls", &config.VerifyTLS)
	setStr(f, "user-agent", &config.UserAgent)
	setStr(f, "output-dir", &config.OutputDir)
	setBool(f, "verbose", &config.LogVerbose)
	setBool(f, "no-color", &config.NoColor)
	setBool(f, "quiet", &config.Quiet)
	setBool(f, "no-progress", &config.NoProgress)
	setBool(f, "force-https", &config.ForceHTTPS)
	setBool(f, "skip-dns", &config.SkipDNS)
	setBool(f, "skip-browser", &config.SkipBrowser)
	setInt(f, "max-redirects", &config.MaxRedirects)
	setBool(f, "detect-tech", &config.DetectTech)
	setBool(f, "security-check", &config.CheckSecurity)
	setBool(f, "cert-info", &config.IncludeCertInfo)
	setBool(f, "analyze-content", &config.AnalyzeContent)
	setBool(f, "screenshots", &config.TakeScreenshots)
	setStr(f, "screenshot-dir", &config.ScreenshotDir)
	setStr(f, "export", &config.ExportPath)
	setStr(f, "output-format", &config.OutputFormat)
	setBool(f, "subdomains", &config.EnableSubdomains)
	setBool(f, "passive", &config.PassiveOnly)
	setBool(f, "dns", &config.EnableDNSRecords)
	setBool(f, "takeover", &config.EnableTakeover)
	setBool(f, "ports", &config.EnablePorts)
	setStr(f, "port-spec", &config.PortSpec)
	setBool(f, "probes", &config.EnableProbes)
	setBool(f, "secrets", &config.EnableSecrets)
	setBool(f, "crawl", &config.EnableCrawl)
	setInt(f, "crawl-depth", &config.CrawlDepth)
	setInt(f, "max-pages", &config.MaxPages)
	setBool(f, "fuzz", &config.EnableFuzz)
	setStr(f, "subdomain-wordlist", &config.SubdomainWordlist)
	setBool(f, "aggressive", &config.Aggressive)
	setBool(f, "templates", &config.EnableTemplates)
	setStr(f, "templates-dir", &config.TemplatesDir)
	setBool(f, "vuln", &config.EnableVuln)
	setStr(f, "sarif", &config.SARIFPath)
	setStr(f, "proxy", &config.ProxyURL)
	setFloat(f, "rate", &config.RateLimit)
	setStr(f, "scope", &config.ScopeFile)
	setBool(f, "authorize", &config.Authorize)
	setStr(f, "audit-log", &config.AuditLogPath)
	setStr(f, "resume", &config.ResumeFile)
	setBool(f, "jsonl", &config.JSONL)
	if f.Changed("fail-on") {
		v, _ := f.GetString("fail-on")
		config.FailOn = models.Severity(strings.ToLower(strings.TrimSpace(v)))
	}

	if config.Aggressive {
		config.DetectTech = true
		config.CheckSecurity = true
		config.IncludeCertInfo = true
		config.AnalyzeContent = true
		config.EnableDNSRecords = true
		config.EnableTakeover = true
		config.EnableSecrets = true
		config.EnableVuln = true
		config.EnableSubdomains = true
		config.EnableCrawl = true
		// Active modules escalate only when the operator has authorized them.
		if config.ScopeFile != "" || config.Authorize {
			config.EnableProbes = true
			config.EnableTemplates = true
			config.EnablePorts = true
			config.EnableFuzz = true
			if !f.Changed("port-spec") {
				config.PortSpec = "top1000"
			}
		}
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.NoColor {
		color.NoColor = true
	}
	return config, nil
}

func setStr(f *flagSet, name string, dst *string) {
	if f.Changed(name) {
		*dst, _ = f.GetString(name)
	}
}
func setBool(f *flagSet, name string, dst *bool) {
	if f.Changed(name) {
		*dst, _ = f.GetBool(name)
	}
}
func setInt(f *flagSet, name string, dst *int) {
	if f.Changed(name) {
		*dst, _ = f.GetInt(name)
	}
}
func setDur(f *flagSet, name string, dst *time.Duration) {
	if f.Changed(name) {
		*dst, _ = f.GetDuration(name)
	}
}
func setFloat(f *flagSet, name string, dst *float64) {
	if f.Changed(name) {
		*dst, _ = f.GetFloat64(name)
	}
}

// signalContext is cancelled on the first Ctrl+C / SIGTERM so the scan can
// stop cleanly and write partial results; a second signal exits immediately.
func signalContext(quiet bool) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
		case <-ctx.Done():
			return
		}
		if !quiet {
			logf("\n%s Interrupted: finishing up and writing partial results (Ctrl+C again to quit now)\n", yellow("WARN:"))
		}
		cancel()
		<-sigCh
		os.Exit(exitInterrupted)
	}()
	return ctx, func() {
		signal.Stop(sigCh)
		cancel()
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	domains, skipped, err := readDomains(args[0])
	if err != nil {
		return fmt.Errorf("failed to read domains: %w", err)
	}
	if skipped > 0 {
		logf("%s Skipped %d invalid line(s) in %s\n", yellow("WARN:"), skipped, args[0])
	}
	if len(domains) == 0 {
		return fmt.Errorf("no domains to scan in %s", args[0])
	}
	return runDomains(cmd, domains)
}

func runSingle(cmd *cobra.Command, args []string) error {
	domain := cleanDomain(args[0])
	if domain == "" {
		return fmt.Errorf("invalid domain: %q", args[0])
	}
	return runDomains(cmd, []string{domain})
}

func runDomains(cmd *cobra.Command, domains []string) error {
	config, err := loadConfig(cmd)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if config.ExportPath != "" {
		if _, err := reporter.ParseFormats(config.OutputFormat); err != nil {
			return err
		}
	}
	if !config.Quiet {
		logf("%s\n", logo())
	}

	// Authorization gate for any active scanning.
	sc, err := buildScope(config)
	if err != nil {
		return err
	}
	if config.ActiveScanRequested() && sc == nil {
		return fmt.Errorf("active scanning (--ports/--probes/--templates/--fuzz) requires --scope <file> or --authorize")
	}
	if sc != nil {
		if err := sc.AttachAudit(config.AuditLogPath); err != nil {
			return err
		}
		defer sc.Close()
	}

	for _, dir := range []string{config.OutputDir, parentDir(config.ExportPath), parentDir(config.SARIFPath)} {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}
	if config.TakeScreenshots {
		if err := os.MkdirAll(filepath.Join(config.OutputDir, config.ScreenshotDir), 0o755); err != nil {
			return fmt.Errorf("failed to create screenshots directory: %w", err)
		}
	}

	ctx, stop := signalContext(config.Quiet)
	defer stop()

	// Subdomain expansion.
	if config.EnableSubdomains {
		if !config.Quiet {
			logf("%s Enumerating subdomains...\n", blue("INFO:"))
		}
		domains, err = expandSubdomains(ctx, domains, config)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return &exitError{code: exitInterrupted, msg: "Interrupted during subdomain enumeration; nothing was scanned and existing results were left untouched"}
		}
	}

	// Resume: skip already-completed domains, and carry their earlier results
	// forward so the reports cover the whole run rather than just this part.
	allDomains := domains
	var st *state.State
	var carried []*models.Result
	if config.ResumeFile != "" {
		st, err = state.Load(config.ResumeFile)
		if err != nil {
			return fmt.Errorf("failed to load resume file: %w", err)
		}
		var pending []string
		done := make(map[string]bool)
		for _, d := range domains {
			if st.Done(d) {
				done[d] = true
			} else {
				pending = append(pending, d)
			}
		}
		if len(pending) == 0 {
			logf("%s All %d domains are already completed in %s; nothing to scan\n", blue("INFO:"), len(domains), config.ResumeFile)
			return nil
		}
		prior := filepath.Join(config.OutputDir, "scan_results.json")
		carried, err = priorResults(prior, done)
		if err != nil {
			return err
		}
		if missing := len(done) - len(carried); missing > 0 && !config.Quiet {
			logf("%s %d completed domain(s) have no earlier results in %s and will be missing from the reports\n",
				yellow("WARN:"), missing, prior)
		}
		if !config.Quiet {
			logf("%s Resume: %d of %d domains remaining\n", blue("INFO:"), len(pending), len(domains))
		}
		domains = pending
	}

	if !config.Quiet {
		logf("%s Starting scan of %s domains\n", blue("INFO:"), magenta(len(domains)))
	}

	s, err := scanner.New(config)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}
	s.UseScope(sc)
	if config.EnableTemplates {
		eng, err := signature.Load(config.TemplatesDir)
		if err != nil {
			return fmt.Errorf("failed to load templates: %w", err)
		}
		s.UseTemplates(eng)
	}

	var jsonl *json.Encoder
	if config.JSONL {
		jsonl = json.NewEncoder(os.Stdout)
	}
	var stateErr error
	s.OnResult(func(r *models.Result) {
		if jsonl != nil {
			_ = jsonl.Encode(r)
		}
		if st != nil && stateErr == nil {
			// Record progress as each domain finishes so a crash or kill
			// still leaves a usable resume file.
			if stateErr = st.Mark(r.Domain); stateErr != nil {
				logf("%s could not update resume file: %v\n", yellow("WARN:"), stateErr)
			}
		}
	})

	results, err := s.ScanDomains(ctx, domains)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	interrupted := ctx.Err() != nil
	if st != nil {
		if err := st.Flush(); err != nil {
			logf("%s could not save resume file: %v\n", yellow("WARN:"), err)
		}
	}
	if interrupted && len(results) == 0 {
		return &exitError{code: exitInterrupted, msg: "Interrupted before any domain completed; existing results were left untouched"}
	}
	scannedNow := len(results)
	results = mergeInOrder(allDomains, carried, results)

	rep := reporter.New(results, config.OutputDir)
	if err := rep.WriteResultsToFiles(); err != nil {
		return fmt.Errorf("failed to write results: %w", err)
	}
	if config.ExportPath != "" {
		if err := rep.GenerateReport(config.ExportPath, config.OutputFormat); err != nil {
			return fmt.Errorf("failed to generate report: %w", err)
		}
	}
	if config.SARIFPath != "" {
		if err := rep.GenerateSARIF(config.SARIFPath); err != nil {
			return fmt.Errorf("failed to write SARIF: %w", err)
		}
		if !config.Quiet {
			logf("%s SARIF written to %s\n", blue("INFO:"), config.SARIFPath)
		}
	}

	if !config.Quiet {
		active, inactive := rep.GetStats()
		logf("\n%s Scan complete: %s active, %s inactive\n",
			green("SUCCESS:"), green(active), red(inactive))
		if skipped := countSkippedActive(results); skipped > 0 {
			logf("%s Active modules skipped on %d out-of-scope host(s); add them to the scope file to include them\n",
				yellow("WARN:"), skipped)
		}
		printFindingsSummary(results)
	}

	if interrupted {
		return &exitError{code: exitInterrupted, msg: fmt.Sprintf(
			"Scan interrupted: %d of %d domains completed; partial results written to %s",
			scannedNow, len(domains), config.OutputDir)}
	}
	if config.FailOn != "" {
		if n := countAtOrAbove(results, config.FailOn); n > 0 {
			return &exitError{code: exitFindings, msg: fmt.Sprintf(
				"%d finding(s) at or above %s severity", n, config.FailOn.Normalize())}
		}
	}
	return nil
}

// priorResults loads results for already-completed domains from an earlier
// run's scan_results.json. A missing file just means there is nothing to carry.
func priorResults(path string, done map[string]bool) ([]*models.Result, error) {
	prev, err := diff.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot carry earlier results forward: %w", err)
	}
	var out []*models.Result
	for i := range prev {
		if done[prev[i].Domain] {
			out = append(out, &prev[i])
		}
	}
	return out, nil
}

// mergeInOrder combines carried-over and fresh results in input order.
func mergeInOrder(order []string, carried, fresh []*models.Result) []*models.Result {
	if len(carried) == 0 {
		return fresh
	}
	by := make(map[string]*models.Result, len(carried)+len(fresh))
	for _, r := range carried {
		by[r.Domain] = r
	}
	for _, r := range fresh {
		by[r.Domain] = r
	}
	out := make([]*models.Result, 0, len(by))
	for _, d := range order {
		if r, ok := by[d]; ok {
			out = append(out, r)
			delete(by, d)
		}
	}
	return out
}

// parentDir returns the directory a report file will be written into, or ""
// when there is no file or it goes in the working directory.
func parentDir(path string) string {
	if path == "" {
		return ""
	}
	if d := filepath.Dir(path); d != "." {
		return d
	}
	return ""
}

func countSkippedActive(results []*models.Result) int {
	n := 0
	for _, r := range results {
		if r.SkippedActive {
			n++
		}
	}
	return n
}

func countAtOrAbove(results []*models.Result, threshold models.Severity) int {
	n := 0
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Severity.Rank() >= threshold.Normalize().Rank() {
				n++
			}
		}
	}
	return n
}

func runEnum(cmd *cobra.Command, args []string) error {
	config, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	domain := cleanDomain(args[0])
	if domain == "" {
		return fmt.Errorf("invalid domain: %q", args[0])
	}
	if net.ParseIP(hostOnly(domain)) != nil {
		return fmt.Errorf("%q is an IP address; subdomain enumeration needs a domain name", domain)
	}
	domain = hostOnly(domain)
	wordlist, err := loadWordlist(config.SubdomainWordlist)
	if err != nil {
		return err
	}

	ctx, stop := signalContext(config.Quiet)
	defer stop()
	client, err := netx.NewHTTPClient(config)
	if err != nil {
		return err
	}

	if !config.Quiet {
		logf("%s Enumerating subdomains of %s\n", blue("INFO:"), magenta(domain))
	}
	subs, err := subdomain.Enumerate(ctx, domain, subdomain.Options{
		PassiveOnly: config.PassiveOnly,
		Wordlist:    wordlist,
		Concurrency: config.MaxConcurrentChecks * 4,
		Timeout:     config.Timeout,
		Client:      client,
		Limiter:     ratelimit.New(config.RateLimit),
	})
	if err != nil && !config.Quiet {
		logf("%s some sources failed: %v\n", yellow("WARN:"), err)
	}

	for _, s := range subs {
		fmt.Println(s)
	}
	if err := os.MkdirAll(config.OutputDir, 0o755); err != nil {
		return err
	}
	out := filepath.Join(config.OutputDir, "subdomains.txt")
	var content []byte
	if len(subs) > 0 {
		content = []byte(strings.Join(subs, "\n") + "\n")
	}
	if err := os.WriteFile(out, content, 0o644); err != nil {
		return err
	}
	if !config.Quiet {
		logf("%s Found %s subdomains, written to %s\n", green("DONE:"), magenta(len(subs)), out)
	}
	return nil
}

func runPorts(cmd *cobra.Command, args []string) error {
	config, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	target := cleanDomain(args[0])
	if target == "" {
		return fmt.Errorf("invalid host: %q", args[0])
	}
	host := hostOnly(target)

	sc, err := buildScope(config)
	if err != nil {
		return err
	}
	if sc == nil || !sc.InScope(host) {
		return fmt.Errorf("port scanning %q requires authorization: pass --scope <file> listing the host, or --authorize", host)
	}
	if err := sc.AttachAudit(config.AuditLogPath); err != nil {
		return err
	}
	defer sc.Close()
	sc.Log("portscan", host, config.PortSpec)

	ctx, stop := signalContext(config.Quiet)
	defer stop()

	if !config.Quiet {
		logf("%s Scanning ports (%s) on %s\n", blue("INFO:"), config.PortSpec, magenta(host))
	}
	open := portscan.Scan(ctx, host, portscan.ParsePorts(config.PortSpec), 100, 2*time.Second, true)
	if ctx.Err() != nil {
		return &exitError{code: exitInterrupted, msg: "Port scan interrupted"}
	}
	if len(open) == 0 {
		logf("%s\n", yellow("No open ports found."))
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "PORT\tSERVICE\tBANNER")
	for _, p := range open {
		fmt.Fprintf(w, "%d/tcp\t%s\t%s\n", p.Port, p.Service, p.Banner)
	}
	return w.Flush()
}

func runTemplates(cmd *cobra.Command, _ []string) error {
	config, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	eng, err := signature.Load(config.TemplatesDir)
	if err != nil {
		return fmt.Errorf("failed to load templates: %w", err)
	}
	tpls := eng.Templates()

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSEVERITY\tNAME")
	for _, t := range tpls {
		fmt.Fprintf(w, "%s\t%s\t%s\n", t.ID, t.Info.Severity, t.Info.Name)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	logf("\n%d templates loaded.\n", len(tpls))
	return nil
}

func runDiff(cmd *cobra.Command, args []string) error {
	if noColor, _ := cmd.Flags().GetBool("no-color"); noColor {
		color.NoColor = true
	}
	failOnRaw, _ := cmd.Flags().GetString("fail-on")
	failOn := models.Severity(strings.ToLower(strings.TrimSpace(failOnRaw)))
	if failOn != "" && !failOn.Valid() {
		return fmt.Errorf("unknown --fail-on severity %q", failOnRaw)
	}

	oldRun, err := diff.Load(args[0])
	if err != nil {
		return err
	}
	newRun, err := diff.Load(args[1])
	if err != nil {
		return err
	}
	rep := diff.Compare(oldRun, newRun)

	if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		printDiff(os.Stdout, rep)
	}

	if failOn != "" {
		if worst, ok := rep.MaxNewSeverity(); ok && worst.Rank() >= failOn.Rank() {
			return &exitError{code: exitFindings}
		}
	}
	return nil
}

func printDiff(w io.Writer, rep diff.Report) {
	if rep.Empty() {
		fmt.Fprintln(w, "No changes.")
		return
	}
	list := func(label string, items []string) {
		if len(items) > 0 {
			fmt.Fprintf(w, "%s (%d): %s\n", label, len(items), strings.Join(items, ", "))
		}
	}
	list(green("Added domains"), rep.AddedDomains)
	list(yellow("Removed domains"), rep.RemovedDomains)
	list(green("Now active"), rep.NewlyActive)
	list(red("No longer active"), rep.NewlyInactive)

	findings := func(label string, items []diff.FindingChange) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(w, "%s (%d):\n", label, len(items))
		for _, c := range items {
			loc := c.Finding.Location
			if loc == "" {
				loc = c.Domain
			}
			fmt.Fprintf(w, "  %s %s  %s — %s\n", severityLabel(c.Finding.Severity), magenta(c.Domain), c.Finding.Title, loc)
		}
	}
	findings(red("New findings"), rep.NewFindings)
	findings(green("Resolved findings"), rep.ResolvedFindings)

	ports := func(label string, items []diff.PortChange) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(w, "%s (%d):\n", label, len(items))
		for _, c := range items {
			fmt.Fprintf(w, "  %s %d/tcp %s\n", magenta(c.Domain), c.Port.Port, c.Port.Service)
		}
	}
	ports(red("Opened ports"), rep.OpenedPorts)
	ports(green("Closed ports"), rep.ClosedPorts)
}

func severityLabel(s models.Severity) string {
	label := "[" + strings.ToUpper(string(s.Normalize())) + "]"
	switch s.Normalize() {
	case models.SeverityCritical, models.SeverityHigh:
		return red(label)
	case models.SeverityMedium:
		return yellow(label)
	case models.SeverityLow:
		return cyan(label)
	default:
		return label
	}
}

func buildScope(config *models.Config) (*scope.Scope, error) {
	if config.ScopeFile != "" {
		sc, err := scope.Load(config.ScopeFile)
		if err != nil {
			return nil, err
		}
		return sc, nil
	}
	if config.Authorize {
		return scope.Authorized(), nil
	}
	return nil, nil
}

// loadWordlist reads a wordlist file; an empty path means "use the built-in
// list". A path that can't be read is an error rather than a silent fallback.
func loadWordlist(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("failed to read subdomain wordlist: %w", err)
	}
	var words []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			words = append(words, l)
		}
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("subdomain wordlist %s is empty", path)
	}
	return words, nil
}

func expandSubdomains(ctx context.Context, seeds []string, config *models.Config) ([]string, error) {
	client, err := netx.NewHTTPClient(config)
	if err != nil {
		return nil, err
	}
	wl, err := loadWordlist(config.SubdomainWordlist)
	if err != nil {
		return nil, err
	}
	lim := ratelimit.New(config.RateLimit)

	seen := make(map[string]bool)
	var order []string
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			order = append(order, d)
		}
	}
	for _, seed := range seeds {
		add(seed)
		host := hostOnly(seed)
		if net.ParseIP(host) != nil {
			continue // subdomain enumeration is meaningless for an IP target
		}
		subs, err := subdomain.Enumerate(ctx, host, subdomain.Options{
			PassiveOnly: config.PassiveOnly,
			Wordlist:    wl,
			Concurrency: config.MaxConcurrentChecks * 4,
			Timeout:     config.Timeout,
			Client:      client,
			Limiter:     lim,
		})
		if err != nil && !config.Quiet {
			logf("%s %s: some subdomain sources failed: %v\n", yellow("WARN:"), host, err)
		}
		for _, sub := range subs {
			add(sub)
		}
	}
	return order, nil
}

func printFindingsSummary(results []*models.Result) {
	counts := map[models.Severity]int{}
	total := 0
	for _, r := range results {
		for _, f := range r.Findings {
			counts[f.Severity.Normalize()]++
			total++
		}
	}
	if total == 0 {
		return
	}
	logf("\n%s %d findings: %s critical, %s high, %s medium, %s low, %d info\n",
		yellow("FINDINGS:"), total,
		red(counts[models.SeverityCritical]),
		red(counts[models.SeverityHigh]),
		yellow(counts[models.SeverityMedium]),
		cyan(counts[models.SeverityLow]),
		counts[models.SeverityInfo],
	)
	shown := 0
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Severity.Rank() < models.SeverityMedium.Rank() {
				continue
			}
			logf("  %s %s %s — %s\n", magenta(r.Domain), severityLabel(f.Severity), f.Title, f.Location)
			shown++
			if shown >= 20 {
				return
			}
		}
	}
}

// readDomains reads one target per line from path, or stdin when path is "-".
// Blank lines and # comments are ignored, targets are normalized and
// de-duplicated, and the number of unusable lines is returned.
func readDomains(path string) ([]string, int, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path) //nolint:gosec // operator-supplied path
		if err != nil {
			return nil, 0, fmt.Errorf("failed to open file: %w", err)
		}
		defer f.Close()
		r = f
	}

	seen := make(map[string]bool)
	var domains []string
	skipped := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d := cleanDomain(line)
		if d == "" {
			skipped++
			continue
		}
		if !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, 0, fmt.Errorf("error reading input: %w", err)
	}
	return domains, skipped, nil
}

// hostOnly strips a :port suffix and IPv6 brackets so IP checks and scope
// lookups work on host:port inputs.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")
}

// cleanDomain normalizes a raw input (bare host, host:port, or URL) into a
// lowercase host with an optional port. It returns "" for unusable input.
func cleanDomain(line string) string {
	s := strings.TrimSpace(line)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:] // drop user:pass@
	}
	s = strings.ToLower(s)

	host, port := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if host == "" || strings.ContainsAny(host, " \t\"'<>\\,;|") {
		return ""
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return ""
		}
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		if net.ParseIP(host) == nil {
			return ""
		}
		return "[" + host + "]" // IPv6 literals need brackets in URLs
	}
	return host
}
