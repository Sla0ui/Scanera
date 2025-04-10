package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

const (
	AppName    = "scanera"
	AppVersion = "1.0.0"
	AppAuthor  = "Sla0ui"
	AppRepo    = "https://github.com/Sla0ui/scanera"
)

type Config struct {
	SuccessStatusCodes  []int
	Timeout             time.Duration
	RetryCount          int
	MaxConcurrentChecks int
	VerifyTLS           bool
	UserAgent           string
	OutputDir           string
	LogVerbose          bool
	NoColor             bool
	Format              string
	Quiet               bool
	BrowserTimeout      time.Duration
	NoProgress          bool
	ForceHTTPS          bool
	SkipDNS             bool
	SkipBrowser         bool
	TakeScreenshots     bool
	ScreenshotDir       string
	DetectTech          bool
	CheckSecurity       bool
	OutputFormat        string
	AnalyzeContent      bool
	BatchSize           int
	WebhookURL          string
	HistoricalCompare   bool
	ExportPath          string
	MaxRedirects        int
	IncludeCertInfo     bool
}

type Result struct {
	Domain         string
	Active         bool
	FinalURL       string
	StatusCode     int
	RedirectTo     string
	Error          error
	ResponseTime   time.Duration
	Title          string
	ServerInfo     ServerInfo
	ScreenshotPath string
	SecurityInfo   SecurityInfo
	ContentInfo    ContentInfo
	IPAddresses    []string
	LastChecked    time.Time
	Technologies   []string
}

type ServerInfo struct {
	Server        string
	PoweredBy     string
	ContentType   string
	Headers       map[string]string
	ResponseSize  int64
	LastModified  string
	SecurityFlags []string
}

type SecurityInfo struct {
	HasHTTPS        bool
	ValidCert       bool
	CertIssuer      string
	CertExpiry      time.Time
	SecurityHeaders map[string]string
	HTTPSRedirect   bool
	HSTPEnabled     bool
	TLSVersion      string
}

type ContentInfo struct {
	WordCount      int
	HasLoginForm   bool
	LinkCount      int
	ExternalLinks  int
	Favicon        string
	PageLanguage   string
	IsParked       bool
	HasAnalytics   bool
	Description    string
	Keywords       []string
	SocialProfiles []string
}

var (
	config    Config
	fileMutex sync.Mutex
	rootCmd   *cobra.Command

	green   = color.New(color.FgGreen).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	blue    = color.New(color.FgBlue).SprintFunc()
	cyan    = color.New(color.FgCyan).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()

	logo = `

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
`
)

func init() {

	rootCmd = &cobra.Command{
		Use:   "scanera [flags] DOMAIN_FILE",
		Short: "A powerful domain analysis and validation tool",
		Long: logo + `
Scanera is a powerful domain analysis and validation tool that performs comprehensive
domain checks using DNS resolution, HTTP(S) requests, browser-based checks, technology
detection, and security assessments.

Examples:
  scanera domains.txt
  scanera -s 200,301,302 -t 15s -c 10 domains.txt
  scanera check --output-dir=results --verbose domains.txt
  scanera check --screenshots --detect-tech domains.txt`,
		Version: AppVersion,
		Run:     runCheck,
	}

	rootCmd.Flags().StringP("status-codes", "s", "200", "Comma-separated list of HTTP status codes considered successful")
	rootCmd.Flags().DurationP("timeout", "t", 10*time.Second, "Timeout for HTTP requests")
	rootCmd.Flags().IntP("retries", "r", 2, "Number of retries for failed requests")
	rootCmd.Flags().IntP("concurrency", "c", 5, "Maximum number of concurrent checks")
	rootCmd.Flags().BoolP("verify-tls", "T", false, "Verify TLS certificates")
	rootCmd.Flags().StringP("user-agent", "u", "Mozilla/5.0 (compatible; Scanera/1.0; +https://github.com/Sla0ui/scanera)", "User agent string")
	rootCmd.Flags().StringP("output-dir", "o", "results", "Directory for output files")
	rootCmd.Flags().BoolP("verbose", "v", false, "Enable verbose logging")
	rootCmd.Flags().BoolP("no-color", "n", false, "Disable colorized output")
	rootCmd.Flags().StringP("format", "f", "text", "Output format (text, json, csv)")
	rootCmd.Flags().BoolP("quiet", "q", false, "Quiet mode - only output to files")
	rootCmd.Flags().Duration("browser-timeout", 20*time.Second, "Timeout for browser-based checks")
	rootCmd.Flags().Bool("no-progress", false, "Disable progress bar")
	rootCmd.Flags().Bool("force-https", false, "Only check HTTPS (skip HTTP)")
	rootCmd.Flags().Bool("skip-dns", false, "Skip DNS resolution check")
	rootCmd.Flags().Bool("skip-browser", false, "Skip browser-based checks")

	rootCmd.Flags().Bool("screenshots", false, "Take screenshots of active domains")
	rootCmd.Flags().String("screenshot-dir", "screenshots", "Directory for screenshots")
	rootCmd.Flags().Bool("detect-tech", false, "Detect technologies used by websites")
	rootCmd.Flags().Bool("security-check", false, "Perform security headers check")
	rootCmd.Flags().String("output-format", "all", "Output format(s) - comma separated (csv,json,html,text,xml)")
	rootCmd.Flags().Bool("analyze-content", false, "Analyze page content for keywords and structure")
	rootCmd.Flags().Int("batch-size", 100, "Batch size for processing large domain lists")
	rootCmd.Flags().String("webhook", "", "Webhook URL to send results")
	rootCmd.Flags().Bool("compare", false, "Compare with previous scan results")
	rootCmd.Flags().String("export", "", "Export path for bundled report file")
	rootCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	rootCmd.Flags().Bool("cert-info", false, "Include certificate information for HTTPS sites")

	checkCmd := &cobra.Command{
		Use:   "check [flags] DOMAIN_FILE",
		Short: "Check domains from a file",
		Long:  `Check the status of domains listed in the specified file.`,
		Run:   runCheck,
	}

	checkCmd.Flags().AddFlagSet(rootCmd.Flags())

	rootCmd.AddCommand(checkCmd)

	singleCmd := &cobra.Command{
		Use:   "single [flags] DOMAIN",
		Short: "Check a single domain",
		Long:  `Check the status of a single domain without requiring a file.`,
		Args:  cobra.ExactArgs(1),
		Run:   runSingleDomain,
	}

	singleCmd.Flags().AddFlagSet(rootCmd.Flags())

	rootCmd.AddCommand(singleCmd)

	listCmd := &cobra.Command{
		Use:   "list [flags] [OUTPUT_PREFIX]",
		Short: "List results from previous checks",
		Long:  `List active or inactive domains from previous check results.`,
		Run:   runList,
	}

	listCmd.Flags().StringP("output-dir", "o", "results", "Directory containing result files")
	listCmd.Flags().StringP("type", "t", "all", "Type of domains to list (active, inactive, all)")
	listCmd.Flags().BoolP("count", "c", false, "Only show count of domains")

	rootCmd.AddCommand(listCmd)

	techCmd := &cobra.Command{
		Use:   "tech [flags] DOMAIN",
		Short: "Detect technologies used by a website",
		Long:  `Detect technologies, frameworks, libraries and server software used by a website.`,
		Args:  cobra.ExactArgs(1),
		Run:   runTechDetection,
	}

	techCmd.Flags().DurationP("timeout", "t", 10*time.Second, "Timeout for HTTP requests")
	techCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	rootCmd.AddCommand(techCmd)

	screenshotCmd := &cobra.Command{
		Use:   "screenshot [flags] DOMAIN",
		Short: "Take a screenshot of a website",
		Long:  `Take a full-page screenshot of a website and save it to a file.`,
		Args:  cobra.ExactArgs(1),
		Run:   runScreenshot,
	}

	screenshotCmd.Flags().StringP("output", "o", "", "Output file path (default: domain.png)")
	screenshotCmd.Flags().IntP("width", "w", 1280, "Viewport width")
	screenshotCmd.Flags().IntP("height", "h", 800, "Viewport height")
	screenshotCmd.Flags().DurationP("timeout", "t", 20*time.Second, "Timeout for screenshot capture")
	screenshotCmd.Flags().BoolP("fullpage", "f", true, "Capture full page (not just viewport)")

	rootCmd.AddCommand(screenshotCmd)

	securityCmd := &cobra.Command{
		Use:   "security [flags] DOMAIN",
		Short: "Check security headers of a website",
		Long:  `Check the security headers, HTTPS configuration, and certificate information of a website.`,
		Args:  cobra.ExactArgs(1),
		Run:   runSecurityCheck,
	}

	securityCmd.Flags().DurationP("timeout", "t", 10*time.Second, "Timeout for HTTP requests")
	securityCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	rootCmd.AddCommand(securityCmd)

	reportCmd := &cobra.Command{
		Use:   "report [flags] [RESULTS_FILE]",
		Short: "Generate a report from scan results",
		Long:  `Generate a comprehensive report from scan results in various formats.`,
		Run:   runReportGeneration,
	}

	reportCmd.Flags().StringP("input", "i", "", "Input results file (JSON format)")
	reportCmd.Flags().StringP("output", "o", "report", "Output file prefix")
	reportCmd.Flags().StringP("format", "f", "html", "Report format (html, pdf, markdown, csv, json)")
	reportCmd.Flags().BoolP("include-screenshots", "s", true, "Include screenshots in the report")

	rootCmd.AddCommand(reportCmd)

	batchCmd := &cobra.Command{
		Use:   "batch [flags] DOMAINS_DIRECTORY",
		Short: "Process multiple domain files in batch",
		Long:  `Process multiple domain files from a directory in batch mode.`,
		Args:  cobra.ExactArgs(1),
		Run:   runBatchProcessing,
	}

	batchCmd.Flags().StringP("pattern", "p", "*.txt", "File pattern to match domain files")
	batchCmd.Flags().StringP("output-dir", "o", "batch_results", "Directory for batch results")
	batchCmd.Flags().IntP("concurrent-files", "C", 1, "Number of files to process concurrently")
	batchCmd.Flags().AddFlagSet(rootCmd.Flags())

	rootCmd.AddCommand(batchCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCheck(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		cmd.Help()
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !config.Quiet {
			fmt.Println("\nReceived termination signal. Shutting down gracefully...")
		}
		cancel()

		time.Sleep(2 * time.Second)
		os.Exit(1)
	}()

	loadConfig(cmd)

	if config.NoColor {
		color.NoColor = true
	}

	if !config.Quiet {
		if !config.NoColor {
			fmt.Println(logo)
		} else {
			fmt.Println(strings.Replace(logo, "By Sla0ui", "By Sla0ui - Version "+AppVersion, 1))
		}
	}

	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to create output directory: %v\n", red("ERROR:"), err)
		os.Exit(1)
	}

	if config.TakeScreenshots {
		screenshotPath := filepath.Join(config.OutputDir, config.ScreenshotDir)
		if err := os.MkdirAll(screenshotPath, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to create screenshots directory: %v\n", red("ERROR:"), err)
			os.Exit(1)
		}
	}

	domainFile := args[0]
	domains, err := readDomainsFromFile(domainFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to read domains: %v\n", red("ERROR:"), err)
		os.Exit(1)
	}

	if !config.Quiet {
		fmt.Printf("%s Starting domain check for %s domains\n",
			blue("INFO:"), magenta(len(domains)))

		if config.TakeScreenshots {
			fmt.Printf("%s Screenshots will be saved to: %s\n",
				blue("INFO:"), filepath.Join(config.OutputDir, config.ScreenshotDir))
		}

		if config.DetectTech {
			fmt.Printf("%s Technology detection enabled\n", blue("INFO:"))
		}

		if config.CheckSecurity {
			fmt.Printf("%s Security checks enabled\n", blue("INFO:"))
		}
	}

	allocCtx, allocCancel := setupBrowserContext()
	defer allocCancel()

	results := processDomainsWithPool(ctx, domains, allocCtx)

	processResults(results)

	if config.ExportPath != "" {
		generateReport(results, config.ExportPath, config.OutputFormat)
	}

	if config.WebhookURL != "" {
		sendResultsToWebhook(results, config.WebhookURL)
	}

	if !config.Quiet {
		fmt.Printf("%s Domain check completed successfully\n", green("SUCCESS:"))
	}
}

func loadConfig(cmd *cobra.Command) {

	statusCodesStr, _ := cmd.Flags().GetString("status-codes")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	retryCount, _ := cmd.Flags().GetInt("retries")
	concurrentChecks, _ := cmd.Flags().GetInt("concurrency")
	verifyTLS, _ := cmd.Flags().GetBool("verify-tls")
	userAgent, _ := cmd.Flags().GetString("user-agent")
	outputDir, _ := cmd.Flags().GetString("output-dir")
	verbose, _ := cmd.Flags().GetBool("verbose")
	noColor, _ := cmd.Flags().GetBool("no-color")
	format, _ := cmd.Flags().GetString("format")
	quiet, _ := cmd.Flags().GetBool("quiet")
	browserTimeout, _ := cmd.Flags().GetDuration("browser-timeout")
	noProgress, _ := cmd.Flags().GetBool("no-progress")
	forceHTTPS, _ := cmd.Flags().GetBool("force-https")
	skipDNS, _ := cmd.Flags().GetBool("skip-dns")
	skipBrowser, _ := cmd.Flags().GetBool("skip-browser")

	takeScreenshots, _ := cmd.Flags().GetBool("screenshots")
	screenshotDir, _ := cmd.Flags().GetString("screenshot-dir")
	detectTech, _ := cmd.Flags().GetBool("detect-tech")
	securityCheck, _ := cmd.Flags().GetBool("security-check")
	outputFormat, _ := cmd.Flags().GetString("output-format")
	analyzeContent, _ := cmd.Flags().GetBool("analyze-content")
	batchSize, _ := cmd.Flags().GetInt("batch-size")
	webhookURL, _ := cmd.Flags().GetString("webhook")
	compare, _ := cmd.Flags().GetBool("compare")
	exportPath, _ := cmd.Flags().GetString("export")
	maxRedirects, _ := cmd.Flags().GetInt("max-redirects")
	certInfo, _ := cmd.Flags().GetBool("cert-info")

	var statusCodes []int
	for _, codeStr := range strings.Split(statusCodesStr, ",") {
		code, err := strconv.Atoi(strings.TrimSpace(codeStr))
		if err == nil {
			statusCodes = append(statusCodes, code)
		}
	}
	if len(statusCodes) == 0 {
		statusCodes = []int{200}
	}

	if envTimeout := os.Getenv("SCANERA_TIMEOUT"); envTimeout != "" {
		if duration, err := time.ParseDuration(envTimeout); err == nil {
			timeout = duration
		}
	}
	if envRetries := os.Getenv("SCANERA_RETRIES"); envRetries != "" {
		if retries, err := strconv.Atoi(envRetries); err == nil {
			retryCount = retries
		}
	}
	if envConcurrency := os.Getenv("SCANERA_CONCURRENCY"); envConcurrency != "" {
		if concurrency, err := strconv.Atoi(envConcurrency); err == nil {
			concurrentChecks = concurrency
		}
	}
	if envUserAgent := os.Getenv("SCANERA_USER_AGENT"); envUserAgent != "" {
		userAgent = envUserAgent
	}

	config = Config{
		SuccessStatusCodes:  statusCodes,
		Timeout:             timeout,
		RetryCount:          retryCount,
		MaxConcurrentChecks: concurrentChecks,
		VerifyTLS:           verifyTLS,
		UserAgent:           userAgent,
		OutputDir:           outputDir,
		LogVerbose:          verbose,
		NoColor:             noColor,
		Format:              format,
		Quiet:               quiet,
		BrowserTimeout:      browserTimeout,
		NoProgress:          noProgress,
		ForceHTTPS:          forceHTTPS,
		SkipDNS:             skipDNS,
		SkipBrowser:         skipBrowser,
		TakeScreenshots:     takeScreenshots,
		ScreenshotDir:       screenshotDir,
		DetectTech:          detectTech,
		CheckSecurity:       securityCheck,
		OutputFormat:        outputFormat,
		AnalyzeContent:      analyzeContent,
		BatchSize:           batchSize,
		WebhookURL:          webhookURL,
		HistoricalCompare:   compare,
		ExportPath:          exportPath,
		MaxRedirects:        maxRedirects,
		IncludeCertInfo:     certInfo,
	}
}

func setupBrowserContext() (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("ignore-certificate-errors", !config.VerifyTLS),
		chromedp.Flag("disable-web-security", true),
		chromedp.UserAgent(config.UserAgent),
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.WindowSize(1280, 800),
	)
	return chromedp.NewExecAllocator(context.Background(), opts...)
}

func readDomainsFromFile(fileName string) ([]string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open domain file: %w", err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {

			domain := line
			domain = strings.TrimPrefix(domain, "http://")
			domain = strings.TrimPrefix(domain, "https://")
			domain = strings.Split(domain, "/")[0]

			domains = append(domains, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning domain file: %w", err)
	}

	return domains, nil
}

func processDomainsWithPool(ctx context.Context, domains []string, allocCtx context.Context) []Result {
	numWorkers := config.MaxConcurrentChecks
	workCh := make(chan string, len(domains))
	resultCh := make(chan Result, len(domains))

	var bar *progressbar.ProgressBar
	if !config.Quiet && !config.NoProgress {
		bar = progressbar.NewOptions(len(domains),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionSetWidth(50),
			progressbar.OptionSetDescription("[cyan]Processing domains[reset]"),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]=[reset]",
				SaucerHead:    "[green]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}))
	}

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			browserCtx, cancel := chromedp.NewContext(allocCtx)
			defer cancel()

			for {
				select {
				case domain, ok := <-workCh:
					if !ok {
						return
					}

					if config.LogVerbose && !config.Quiet {
						fmt.Printf("%s Worker %d processing domain: %s\n",
							blue("DEBUG:"), workerID, domain)
					}

					result := checkDomain(ctx, domain, browserCtx)
					resultCh <- result

					if bar != nil {
						bar.Add(1)
					}

				case <-ctx.Done():
					if config.LogVerbose && !config.Quiet {
						fmt.Printf("%s Worker %d shutting down\n",
							yellow("DEBUG:"), workerID)
					}
					return
				}
			}
		}(i)
	}

	go func() {
		for _, domain := range domains {
			select {
			case workCh <- domain:

			case <-ctx.Done():
				break
			}
		}
		close(workCh)
	}()

	go func() {
		wg.Wait()
		close(resultCh)

		if bar != nil {
			bar.Finish()
		}
	}()

	var results []Result
	for result := range resultCh {
		results = append(results, result)
	}

	return results
}

func checkDomain(ctx context.Context, domain string, browserCtx context.Context) Result {
	startTime := time.Now()

	result := Result{
		Domain:      domain,
		Active:      false,
		LastChecked: time.Now(),
		ServerInfo: ServerInfo{
			Headers: make(map[string]string),
		},
		SecurityInfo: SecurityInfo{
			SecurityHeaders: make(map[string]string),
		},
	}

	select {
	case <-ctx.Done():
		result.Error = ctx.Err()
		return result
	default:

	}

	if !config.SkipDNS {
		if ips, err := resolveDomain(domain); err != nil {
			if config.LogVerbose && !config.Quiet {
				fmt.Printf("%s Domain not resolvable: %s\n", yellow("DEBUG:"), domain)
			}
			result.Error = fmt.Errorf("domain not resolvable")
			return result
		} else {
			result.IPAddresses = ips
		}
	}

	var protocols []string
	if config.ForceHTTPS {
		protocols = []string{"https://"}
	} else {
		protocols = []string{"https://", "http://"}
	}

	for _, protocol := range protocols {
		url := protocol + domain

		reqStart := time.Now()
		resp, err := tryRequest(url)
		if err != nil {
			if config.LogVerbose && !config.Quiet {
				fmt.Printf("%s Request failed for %s: %v\n",
					yellow("DEBUG:"), url, err)
			}
			continue
		}

		result.ResponseTime = time.Since(reqStart)
		result.StatusCode = resp.StatusCode
		result.FinalURL = resp.Request.URL.String()

		extractServerInfo(resp, &result)

		if config.CheckSecurity && protocol == "https://" {
			checkSecurityHeaders(resp, &result)
			if config.IncludeCertInfo {
				fetchCertificateInfo(domain, &result)
			}
		}

		if domain != resp.Request.URL.Hostname() {
			result.RedirectTo = resp.Request.URL.Hostname()
		}

		if contains(config.SuccessStatusCodes, resp.StatusCode) {

			if config.SkipBrowser {
				result.Active = true

				if config.AnalyzeContent || config.DetectTech {
					body, err := io.ReadAll(resp.Body)
					if err == nil {
						analyzePageContent(string(body), &result)
						if config.DetectTech {
							detectTechnologies(string(body), resp.Header, &result)
						}
					}
					resp.Body.Close()
				}
				return result
			}

			browserSuccess := performBrowserCheck(ctx, result.FinalURL, browserCtx, &result)

			if browserSuccess {
				result.Active = true
				return result
			}
		}

		resp.Body.Close()
	}

	result.ResponseTime = time.Since(startTime)
	return result
}

func resolveDomain(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var resolver net.Resolver
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}

	return ips, nil
}

func tryRequest(url string) (*http.Response, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifyTLS,
		},
		DisableKeepAlives: false,
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
	}

	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("User-Agent", config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")

	var lastErr error
	for attempt := 0; attempt < config.RetryCount; attempt++ {
		if attempt > 0 {
			if config.LogVerbose && !config.Quiet {
				fmt.Printf("%s Retry %d for %s\n", yellow("DEBUG:"), attempt, url)
			}
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}

		lastErr = err
	}

	return nil, fmt.Errorf("all request attempts failed: %w", lastErr)
}

func extractServerInfo(resp *http.Response, result *Result) {
	result.ServerInfo.Server = resp.Header.Get("Server")
	result.ServerInfo.PoweredBy = resp.Header.Get("X-Powered-By")
	result.ServerInfo.ContentType = resp.Header.Get("Content-Type")
	result.ServerInfo.LastModified = resp.Header.Get("Last-Modified")

	if resp.ContentLength > 0 {
		result.ServerInfo.ResponseSize = resp.ContentLength
	}

	for k, v := range resp.Header {
		if len(v) > 0 {
			result.ServerInfo.Headers[k] = v[0]
		}
	}
}

func checkSecurityHeaders(resp *http.Response, result *Result) {

	result.SecurityInfo.HasHTTPS = strings.HasPrefix(resp.Request.URL.String(), "https://")

	securityFlags := []string{}

	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Feature-Policy",
		"Permissions-Policy",
	}

	for _, header := range securityHeaders {
		value := resp.Header.Get(header)
		if value != "" {
			result.SecurityInfo.SecurityHeaders[header] = value
			securityFlags = append(securityFlags, header)
		}
	}

	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
		result.SecurityInfo.HSTPEnabled = true
	}

	result.ServerInfo.SecurityFlags = securityFlags
}

func fetchCertificateInfo(domain string, result *Result) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true,
	})

	if err != nil {
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]
		result.SecurityInfo.ValidCert = time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore)
		result.SecurityInfo.CertIssuer = cert.Issuer.CommonName
		result.SecurityInfo.CertExpiry = cert.NotAfter

		tlsVersion := conn.ConnectionState().Version
		switch tlsVersion {
		case tls.VersionTLS10:
			result.SecurityInfo.TLSVersion = "TLS 1.0"
		case tls.VersionTLS11:
			result.SecurityInfo.TLSVersion = "TLS 1.1"
		case tls.VersionTLS12:
			result.SecurityInfo.TLSVersion = "TLS 1.2"
		case tls.VersionTLS13:
			result.SecurityInfo.TLSVersion = "TLS 1.3"
		default:
			result.SecurityInfo.TLSVersion = fmt.Sprintf("Unknown (%d)", tlsVersion)
		}
	}
}

func performBrowserCheck(ctx context.Context, url string, browserCtx context.Context, result *Result) bool {

	checkCtx, cancel := context.WithTimeout(browserCtx, config.BrowserTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return false
	default:

	}

	var title string
	var bodyContent string

	tasks := chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Title(&title),
	}

	if config.AnalyzeContent {
		tasks = append(tasks, chromedp.InnerHTML("body", &bodyContent))
	}

	if config.TakeScreenshots {
		var buf []byte
		screenshotTask := fullScreenshot(90, &buf)
		tasks = append(tasks, screenshotTask)

		err := chromedp.Run(checkCtx, tasks)

		if err == nil && len(buf) > 0 {

			filename := fmt.Sprintf("%s.png", result.Domain)
			screenshotPath := filepath.Join(config.OutputDir, config.ScreenshotDir, filename)

			if err := os.WriteFile(screenshotPath, buf, 0644); err == nil {
				result.ScreenshotPath = screenshotPath
			}
		} else if err != nil {
			if config.LogVerbose && !config.Quiet {
				fmt.Printf("%s Browser check failed for %s: %v\n",
					yellow("DEBUG:"), url, err)
			}
			return false
		}
	} else {

		err := chromedp.Run(checkCtx, tasks)
		if err != nil {
			if config.LogVerbose && !config.Quiet {
				fmt.Printf("%s Browser check failed for %s: %v\n",
					yellow("DEBUG:"), url, err)
			}
			return false
		}
	}

	result.Title = title

	if config.AnalyzeContent && bodyContent != "" {
		analyzePageContent(bodyContent, result)
	}

	if config.DetectTech && bodyContent != "" {

		headers := make(map[string][]string)
		for k, v := range result.ServerInfo.Headers {
			headers[k] = []string{v}
		}
		detectTechnologies(bodyContent, headers, result)
	}

	if title == "" {
		return false
	}

	errorKeywords := []string{
		"404", "not found", "error", "unavailable",
		"forbidden", "access denied", "bad gateway",
		"domain for sale", "parked domain",
	}

	lowerTitle := strings.ToLower(title)

	for _, keyword := range errorKeywords {
		if strings.Contains(lowerTitle, keyword) {
			if config.LogVerbose && !config.Quiet {
				fmt.Printf("%s Error page detected for %s: Contains '%s' in title\n",
					yellow("DEBUG:"), url, keyword)
			}
			return false
		}
	}

	return true
}

func fullScreenshot(quality int, res *[]byte) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {

		var buf []byte
		if err := chromedp.Run(ctx, chromedp.FullScreenshot(&buf, quality)); err != nil {
			return err
		}
		*res = buf
		return nil
	})
}

func analyzePageContent(content string, result *Result) {

	result.ContentInfo = ContentInfo{}

	result.ContentInfo.WordCount = len(strings.Fields(content))

	result.ContentInfo.HasLoginForm = strings.Contains(strings.ToLower(content), "password") &&
		(strings.Contains(strings.ToLower(content), "<form") ||
			strings.Contains(strings.ToLower(content), "login") ||
			strings.Contains(strings.ToLower(content), "sign in"))

	linkRegex := regexp.MustCompile(`<a\s+(?:[^>]*?\s+)?href=["']([^"']*)["']`)
	links := linkRegex.FindAllStringSubmatch(content, -1)
	result.ContentInfo.LinkCount = len(links)

	externalLinks := 0
	for _, link := range links {
		if len(link) > 1 && (strings.HasPrefix(link[1], "http://") || strings.HasPrefix(link[1], "https://")) {
			externalLinks++
		}
	}
	result.ContentInfo.ExternalLinks = externalLinks

	descRegex := regexp.MustCompile(`<meta\s+(?:[^>]*?\s+)?name=["']description["']\s+(?:[^>]*?\s+)?content=["']([^"']*)["']`)
	descMatches := descRegex.FindStringSubmatch(content)
	if len(descMatches) > 1 {
		result.ContentInfo.Description = descMatches[1]
	}

	keywordsRegex := regexp.MustCompile(`<meta\s+(?:[^>]*?\s+)?name=["']keywords["']\s+(?:[^>]*?\s+)?content=["']([^"']*)["']`)
	keywordsMatches := keywordsRegex.FindStringSubmatch(content)
	if len(keywordsMatches) > 1 {
		keywords := strings.Split(keywordsMatches[1], ",")
		for i, keyword := range keywords {
			keywords[i] = strings.TrimSpace(keyword)
		}
		result.ContentInfo.Keywords = keywords
	}

	result.ContentInfo.HasAnalytics = strings.Contains(content, "google-analytics.com") ||
		strings.Contains(content, "googletagmanager.com") ||
		strings.Contains(content, "gtag") ||
		strings.Contains(content, "analytics")

	result.ContentInfo.IsParked = strings.Contains(strings.ToLower(content), "domain is for sale") ||
		strings.Contains(strings.ToLower(content), "buy this domain") ||
		strings.Contains(strings.ToLower(content), "parked domain") ||
		strings.Contains(strings.ToLower(content), "domain parking")

	if strings.Contains(content, "lang=\"") {
		langRegex := regexp.MustCompile(`lang=["']([^"']*)["']`)
		langMatches := langRegex.FindStringSubmatch(content)
		if len(langMatches) > 1 {
			result.ContentInfo.PageLanguage = langMatches[1]
		}
	}

	socialPatterns := []string{
		"facebook.com", "twitter.com", "instagram.com", "linkedin.com",
		"youtube.com", "pinterest.com", "github.com", "tiktok.com",
	}

	var socialProfiles []string
	for _, pattern := range socialPatterns {
		if strings.Contains(content, pattern) {
			socialProfiles = append(socialProfiles, pattern)
		}
	}
	result.ContentInfo.SocialProfiles = socialProfiles
}

func detectTechnologies(content string, headers map[string][]string, result *Result) {
	var technologies []string

	techPatterns := map[string]string{
		"WordPress":          `wp-content|wp-includes|/wp-json/|wordpress`,
		"Joomla":             `joomla|J!(jQuery|Framework)`,
		"Drupal":             `Drupal|drupal|sites/all|sites/default`,
		"Magento":            `Mage.Cookies|Magento`,
		"Shopify":            `cdn.shopify.com|shopify.com|Shopify.theme`,
		"WooCommerce":        `woocommerce|WooCommerce`,
		"jQuery":             `jquery`,
		"React":              `react|reactjs|_reactRootContainer`,
		"Vue.js":             `vue|__vue__`,
		"Angular":            `ng-|angular|AngularJS|angular.js`,
		"Bootstrap":          `bootstrap`,
		"Tailwind CSS":       `tailwindcss|tailwind.css`,
		"Font Awesome":       `font-awesome|fontawesome`,
		"Google Analytics":   `google-analytics|gtag|UA-|G-`,
		"Google Tag Manager": `googletagmanager`,
		"Cloudflare":         `cloudflare`,
		"PHP":                `X-Powered-By: PHP`,
		"ASP.NET":            `ASP.NET|__VIEWSTATE|__EVENTTARGET`,
		"Google Fonts":       `fonts.googleapis.com`,
		"Google Maps":        `maps.google.com|maps.googleapis.com`,
		"Google reCAPTCHA":   `recaptcha`,
		"Modernizr":          `modernizr`,
		"Moment.js":          `moment.js|moment.min.js`,
		"Lodash":             `lodash|_.min.js|_.debounce|_.throttle`,
		"Axios":              `axios`,
		"Chart.js":           `chart.js|Chart.min.js`,
		"D3.js":              `d3.js|d3.min.js`,
		"Leaflet":            `leaflet.js|leaflet.css`,
		"Stripe":             `stripe.com|Stripe.setPublishableKey`,
		"PayPal":             `paypal.com|paypalobjects.com`,
		"Hotjar":             `hotjar.com|hjSetting`,
		"Intercom":           `intercom.io|intercomSettings`,
		"Drift":              `drift.com|driftt.com`,
	}

	for tech, pattern := range techPatterns {
		match, _ := regexp.MatchString(pattern, content)
		if match {
			technologies = append(technologies, tech)
			continue
		}

		for header, values := range headers {
			for _, value := range values {
				match, _ := regexp.MatchString(pattern, header+": "+value)
				if match {
					technologies = append(technologies, tech)
					break
				}
			}
		}
	}

	if server, ok := headers["Server"]; ok && len(server) > 0 {
		serverValue := strings.ToLower(server[0])

		if strings.Contains(serverValue, "apache") {
			technologies = append(technologies, "Apache")
		}
		if strings.Contains(serverValue, "nginx") {
			technologies = append(technologies, "Nginx")
		}
		if strings.Contains(serverValue, "microsoft-iis") {
			technologies = append(technologies, "IIS")
		}
		if strings.Contains(serverValue, "cloudflare") {
			technologies = append(technologies, "Cloudflare")
		}
		if strings.Contains(serverValue, "litespeed") {
			technologies = append(technologies, "LiteSpeed")
		}
	}

	if powered, ok := headers["X-Powered-By"]; ok && len(powered) > 0 {
		poweredValue := strings.ToLower(powered[0])

		if strings.Contains(poweredValue, "php") {
			technologies = append(technologies, "PHP")
		}
		if strings.Contains(poweredValue, "asp.net") {
			technologies = append(technologies, "ASP.NET")
		}
		if strings.Contains(poweredValue, "express") {
			technologies = append(technologies, "Express.js")
		}
	}

	seen := make(map[string]bool)
	var uniqueTechs []string
	for _, tech := range technologies {
		if !seen[tech] {
			seen[tech] = true
			uniqueTechs = append(uniqueTechs, tech)
		}
	}

	result.Technologies = uniqueTechs
}

func processResults(results []Result) {

	writeResultToFiles(results)

	var activeDomains, inactiveDomains int
	for _, result := range results {
		if result.Active {
			activeDomains++
		} else {
			inactiveDomains++
		}
	}

	if !config.Quiet {
		fmt.Printf("\n%s Results: %s active domains, %s inactive domains\n",
			blue("SUMMARY:"),
			green(activeDomains),
			red(inactiveDomains))

		if config.TakeScreenshots {
			fmt.Printf("%s Screenshots saved to: %s\n",
				blue("INFO:"),
				filepath.Join(config.OutputDir, config.ScreenshotDir))
		}
	}
}

func writeResultToFiles(results []Result) {
	activeFile := filepath.Join(config.OutputDir, "active_domains.txt")
	inactiveFile := filepath.Join(config.OutputDir, "inactive_domains.txt")
	logFile := filepath.Join(config.OutputDir, "domain_check_log.csv")
	jsonFile := filepath.Join(config.OutputDir, "scan_results.json")

	logFd, err := os.Create(logFile)
	if err == nil {
		defer logFd.Close()
		logFd.WriteString("Domain,Status,StatusCode,FinalURL,RedirectTo,ResponseTime,Title,Server,IPAddresses,Error\n")

		for _, result := range results {
			status := "inactive"
			if result.Active {
				status = "active"
			}

			errorMsg := ""
			if result.Error != nil {
				errorMsg = result.Error.Error()
			}

			title := strings.ReplaceAll(result.Title, ",", " ")
			title = strings.ReplaceAll(title, "\n", " ")

			finalURL := strings.ReplaceAll(result.FinalURL, ",", "%2C")
			redirectTo := strings.ReplaceAll(result.RedirectTo, ",", "%2C")
			server := strings.ReplaceAll(result.ServerInfo.Server, ",", " ")
			ips := strings.Join(result.IPAddresses, "|")

			logFd.WriteString(fmt.Sprintf(
				"%s,%s,%d,%s,%s,%dms,%s,%s,%s,%s\n",
				result.Domain,
				status,
				result.StatusCode,
				finalURL,
				redirectTo,
				result.ResponseTime.Milliseconds(),
				title,
				server,
				ips,
				errorMsg,
			))
		}
	}

	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err == nil {
		os.WriteFile(jsonFile, jsonData, 0644)
	}

	for _, result := range results {
		if result.Active {
			logLine := result.FinalURL
			if result.RedirectTo != "" {
				logLine += fmt.Sprintf(" (Redirected to: %s)", result.RedirectTo)
			}
			appendToFile(activeFile, logLine+"\n")
		} else {
			appendToFile(inactiveFile, result.Domain+"\n")
		}
	}
}

func generateReport(results []Result, outputPath, format string) {
	if !config.Quiet {
		fmt.Printf("%s Generating report in %s format: %s\n",
			blue("INFO:"), format, outputPath)
	}

	formats := strings.Split(format, ",")
	outputBase := strings.TrimSuffix(outputPath, filepath.Ext(outputPath))

	for _, fmt := range formats {
		switch strings.ToLower(strings.TrimSpace(fmt)) {
		case "json":
			jsonData, err := json.MarshalIndent(results, "", "  ")
			if err == nil {
				os.WriteFile(outputBase+".json", jsonData, 0644)
			}
		case "csv":
			generateCSVReport(results, outputBase+".csv")
		case "html":
			generateHTMLReport(results, outputBase+".html")
		case "markdown", "md":
			generateMarkdownReport(results, outputBase+".md")
		}
	}
}

func generateCSVReport(results []Result, outputPath string) {
	file, err := os.Create(outputPath)
	if err != nil {
		return
	}
	defer file.Close()

	file.WriteString("Domain,Status,StatusCode,FinalURL,IPAddresses,Server,Technologies,ResponseTime,Title,RedirectTo\n")

	for _, result := range results {
		status := "inactive"
		if result.Active {
			status = "active"
		}

		title := strings.ReplaceAll(result.Title, ",", " ")
		title = strings.ReplaceAll(title, "\n", " ")

		finalURL := strings.ReplaceAll(result.FinalURL, ",", "%2C")
		redirectTo := strings.ReplaceAll(result.RedirectTo, ",", "%2C")
		server := strings.ReplaceAll(result.ServerInfo.Server, ",", " ")
		ips := strings.Join(result.IPAddresses, "|")
		techs := strings.Join(result.Technologies, "|")

		file.WriteString(fmt.Sprintf(
			"%s,%s,%d,%s,%s,%s,%s,%dms,%s,%s\n",
			result.Domain,
			status,
			result.StatusCode,
			finalURL,
			ips,
			server,
			techs,
			result.ResponseTime.Milliseconds(),
			title,
			redirectTo,
		))
	}
}

func generateHTMLReport(results []Result, outputPath string) {

	activeCount, inactiveCount := 0, 0
	for _, result := range results {
		if result.Active {
			activeCount++
		} else {
			inactiveCount++
		}
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return
	}
	defer file.Close()

	file.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scanera Domain Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
        h1, h2, h3 { color: #2c3e50; }
        .container { max-width: 1200px; margin: 0 auto; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { flex: 1; padding: 15px; border-radius: 5px; text-align: center; }
        .active { background-color: #d4edda; color: #155724; }
        .inactive { background-color: #f8d7da; color: #721c24; }
        .total { background-color: #e2e3e5; color: #383d41; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .badge { display: inline-block; padding: 3px 7px; border-radius: 3px; font-size: 12px; margin-right: 5px; }
        .badge-success { background-color: #d4edda; color: #155724; }
        .badge-danger { background-color: #f8d7da; color: #721c24; }
        .badge-tech { background-color: #cce5ff; color: #004085; }
        .footer { margin-top: 30px; text-align: center; color: #6c757d; font-size: 14px; }
        .tab { overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1; }
        .tab button { background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 12px 16px; }
        .tab button:hover { background-color: #ddd; }
        .tab button.active { background-color: #ccc; }
        .tabcontent { display: none; padding: 6px 12px; border: 1px solid #ccc; border-top: none; }
        #ActiveDomains { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Scanera Domain Analysis Report</h1>
        <div class="summary">
            <p>Report generated on: ` + time.Now().Format("January 2, 2006 15:04:05") + `</p>
            <p>Total domains scanned: ` + strconv.Itoa(len(results)) + `</p>
        </div>

        <div class="stats">
            <div class="stat-box active">
                <h3>Active Domains</h3>
                <p>` + strconv.Itoa(activeCount) + `</p>
            </div>
            <div class="stat-box inactive">
                <h3>Inactive Domains</h3>
                <p>` + strconv.Itoa(inactiveCount) + `</p>
            </div>
            <div class="stat-box total">
                <h3>Total Domains</h3>
                <p>` + strconv.Itoa(len(results)) + `</p>
            </div>
        </div>

        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'ActiveDomains')">Active Domains</button>
            <button class="tablinks" onclick="openTab(event, 'InactiveDomains')">Inactive Domains</button>
            <button class="tablinks" onclick="openTab(event, 'AllDomains')">All Domains</button>
        </div>`)

	file.WriteString(`
        <div id="ActiveDomains" class="tabcontent">
            <h2>Active Domains</h2>
            <table>
                <tr>
                    <th>Domain</th>
                    <th>Final URL</th>
                    <th>Status</th>
                    <th>Technologies</th>
                    <th>Server</th>
                    <th>Response Time</th>
                </tr>`)

	for _, result := range results {
		if result.Active {
			techStr := ""
			for _, tech := range result.Technologies {
				techStr += `<span class="badge badge-tech">` + tech + `</span>`
			}

			file.WriteString(`
                <tr>
                    <td>` + result.Domain + `</td>
                    <td>` + result.FinalURL + `</td>
                    <td><span class="badge badge-success">Active</span></td>
                    <td>` + techStr + `</td>
                    <td>` + result.ServerInfo.Server + `</td>
                    <td>` + strconv.FormatInt(result.ResponseTime.Milliseconds(), 10) + `ms</td>
                </tr>`)
		}
	}

	file.WriteString(`
            </table>
        </div>`)

	file.WriteString(`
        <div id="InactiveDomains" class="tabcontent">
            <h2>Inactive Domains</h2>
            <table>
                <tr>
                    <th>Domain</th>
                    <th>Status</th>
                    <th>Status Code</th>
                    <th>Error</th>
                </tr>`)

	for _, result := range results {
		if !result.Active {
			errMsg := ""
			if result.Error != nil {
				errMsg = result.Error.Error()
			}

			file.WriteString(`
                <tr>
                    <td>` + result.Domain + `</td>
                    <td><span class="badge badge-danger">Inactive</span></td>
                    <td>` + strconv.Itoa(result.StatusCode) + `</td>
                    <td>` + errMsg + `</td>
                </tr>`)
		}
	}

	file.WriteString(`
            </table>
        </div>`)

	file.WriteString(`
        <div id="AllDomains" class="tabcontent">
            <h2>All Domains</h2>
            <table>
                <tr>
                    <th>Domain</th>
                    <th>Status</th>
                    <th>Final URL</th>
                    <th>Status Code</th>
                    <th>Server</th>
                    <th>Response Time</th>
                </tr>`)

	for _, result := range results {
		status := `<span class="badge badge-danger">Inactive</span>`
		if result.Active {
			status = `<span class="badge badge-success">Active</span>`
		}

		file.WriteString(`
                <tr>
                    <td>` + result.Domain + `</td>
                    <td>` + status + `</td>
                    <td>` + result.FinalURL + `</td>
                    <td>` + strconv.Itoa(result.StatusCode) + `</td>
                    <td>` + result.ServerInfo.Server + `</td>
                    <td>` + strconv.FormatInt(result.ResponseTime.Milliseconds(), 10) + `ms</td>
                </tr>`)
	}

	file.WriteString(`
            </table>
        </div>`)

	file.WriteString(`
        <div class="footer">
            <p>Generated by Scanera v` + AppVersion + ` - Created by Sla0ui</p>
            <p><a href="` + AppRepo + `" target="_blank">GitHub Repository</a></p>
        </div>
    </div>

    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
    </script>
</body>
</html>`)
}

func generateMarkdownReport(results []Result, outputPath string) {
	file, err := os.Create(outputPath)
	if err != nil {
		return
	}
	defer file.Close()

	file.WriteString("# Scanera Domain Analysis Report\n\n")
	file.WriteString("Report generated on: " + time.Now().Format("January 2, 2006 15:04:05") + "\n\n")

	activeCount, inactiveCount := 0, 0
	for _, result := range results {
		if result.Active {
			activeCount++
		} else {
			inactiveCount++
		}
	}

	file.WriteString("## Summary\n\n")
	file.WriteString("- Total domains scanned: " + strconv.Itoa(len(results)) + "\n")
	file.WriteString("- Active domains: " + strconv.Itoa(activeCount) + "\n")
	file.WriteString("- Inactive domains: " + strconv.Itoa(inactiveCount) + "\n\n")

	file.WriteString("## Active Domains\n\n")
	file.WriteString("| Domain | Final URL | Status Code | Server | Technologies |\n")
	file.WriteString("|--------|-----------|-------------|--------|-------------|\n")

	for _, result := range results {
		if result.Active {
			techs := strings.Join(result.Technologies, ", ")
			file.WriteString("| " + result.Domain + " | " + result.FinalURL + " | " + strconv.Itoa(result.StatusCode) + " | " + result.ServerInfo.Server + " | " + techs + " |\n")
		}
	}

	file.WriteString("\n")

	file.WriteString("## Inactive Domains\n\n")
	file.WriteString("| Domain | Status Code | Error |\n")
	file.WriteString("|--------|-------------|-------|\n")

	for _, result := range results {
		if !result.Active {
			errMsg := ""
			if result.Error != nil {
				errMsg = result.Error.Error()
			}
			file.WriteString("| " + result.Domain + " | " + strconv.Itoa(result.StatusCode) + " | " + errMsg + " |\n")
		}
	}

	file.WriteString("\n")

	file.WriteString("---\n\n")
	file.WriteString("Generated by Scanera v" + AppVersion + " - Created by Sla0ui\n")
	file.WriteString("GitHub Repository: " + AppRepo + "\n")
}

func sendResultsToWebhook(results []Result, webhookURL string) {
	if !config.Quiet {
		fmt.Printf("%s Sending results to webhook: %s\n", blue("INFO:"), webhookURL)
	}

	activeCount, inactiveCount := 0, 0
	for _, result := range results {
		if result.Active {
			activeCount++
		} else {
			inactiveCount++
		}
	}

	payload := map[string]interface{}{
		"scanCompleted": time.Now(),
		"summary": map[string]interface{}{
			"totalDomains":    len(results),
			"activeDomains":   activeCount,
			"inactiveDomains": inactiveCount,
		},
		"results": results,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		if config.LogVerbose && !config.Quiet {
			fmt.Printf("%s Failed to marshal webhook data: %v\n", red("ERROR:"), err)
		}
		return
	}

	resp, err := http.Post(webhookURL, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		if !config.Quiet {
			fmt.Printf("%s Failed to send webhook: %v\n", red("ERROR:"), err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if !config.Quiet {
			fmt.Printf("%s Webhook delivered successfully\n", green("SUCCESS:"))
		}
	} else {
		if !config.Quiet {
			fmt.Printf("%s Webhook delivery failed with status code: %d\n", red("ERROR:"), resp.StatusCode)
		}
	}
}

func runSingleDomain(cmd *cobra.Command, args []string) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loadConfig(cmd)

	if config.NoColor {
		color.NoColor = true
	}

	if !config.Quiet {
		if !config.NoColor {
			fmt.Println(logo)
		} else {
			fmt.Println(strings.Replace(logo, "By Sla0ui", "By Sla0ui - Version "+AppVersion, 1))
		}
	}

	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to create output directory: %v\n", red("ERROR:"), err)
		os.Exit(1)
	}

	if config.TakeScreenshots {
		screenshotPath := filepath.Join(config.OutputDir, config.ScreenshotDir)
		if err := os.MkdirAll(screenshotPath, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to create screenshots directory: %v\n", red("ERROR:"), err)
			os.Exit(1)
		}
	}

	domain := args[0]

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.Split(domain, "/")[0]

	if !config.Quiet {
		fmt.Printf("%s Checking domain: %s\n", blue("INFO:"), magenta(domain))
	}

	allocCtx, allocCancel := setupBrowserContext()
	defer allocCancel()

	browserCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	result := checkDomain(ctx, domain, browserCtx)

	if !config.Quiet {
		displaySingleResult(result)
	}

	writeResultToFiles([]Result{result})

	if config.ExportPath != "" {
		generateReport([]Result{result}, config.ExportPath, config.OutputFormat)
	}
}

func displaySingleResult(result Result) {
	fmt.Println("\n--------------------------------")

	if result.Active {
		fmt.Printf("%s Domain is %s\n", green("✓"), green("ACTIVE"))
	} else {
		fmt.Printf("%s Domain is %s\n", red("✗"), red("INACTIVE"))
	}

	fmt.Println("--------------------------------")
	fmt.Printf("Domain: %s\n", cyan(result.Domain))

	if len(result.IPAddresses) > 0 {
		fmt.Printf("IP Addresses: %s\n", strings.Join(result.IPAddresses, ", "))
	}

	if result.FinalURL != "" {
		fmt.Printf("Final URL: %s\n", result.FinalURL)
	}

	if result.RedirectTo != "" {
		fmt.Printf("Redirected to: %s\n", result.RedirectTo)
	}

	if result.StatusCode != 0 {
		fmt.Printf("Status Code: %d\n", result.StatusCode)
	}

	if result.ResponseTime != 0 {
		fmt.Printf("Response Time: %dms\n", result.ResponseTime.Milliseconds())
	}

	if result.Title != "" {
		fmt.Printf("Page Title: %s\n", result.Title)
	}

	if result.ServerInfo.Server != "" {
		fmt.Printf("Server: %s\n", result.ServerInfo.Server)
	}

	if result.ServerInfo.PoweredBy != "" {
		fmt.Printf("Powered By: %s\n", result.ServerInfo.PoweredBy)
	}

	if len(result.Technologies) > 0 {
		fmt.Printf("Technologies: %s\n", strings.Join(result.Technologies, ", "))
	}

	if result.SecurityInfo.HasHTTPS {
		fmt.Printf("HTTPS: %s\n", green("Enabled"))

		if result.SecurityInfo.TLSVersion != "" {
			fmt.Printf("TLS Version: %s\n", result.SecurityInfo.TLSVersion)
		}

		if result.SecurityInfo.CertIssuer != "" {
			fmt.Printf("Certificate Issuer: %s\n", result.SecurityInfo.CertIssuer)
			fmt.Printf("Certificate Expiry: %s\n", result.SecurityInfo.CertExpiry.Format("2006-01-02"))

			if result.SecurityInfo.ValidCert {
				fmt.Printf("Certificate Valid: %s\n", green("Yes"))
			} else {
				fmt.Printf("Certificate Valid: %s\n", red("No"))
			}
		}
	}

	if len(result.SecurityInfo.SecurityHeaders) > 0 {
		fmt.Printf("\nSecurity Headers:\n")
		for header, value := range result.SecurityInfo.SecurityHeaders {
			fmt.Printf("  %s: %s\n", header, value)
		}
	}

	if result.ScreenshotPath != "" {
		fmt.Printf("\nScreenshot saved to: %s\n", result.ScreenshotPath)
	}

	if result.Error != nil {
		fmt.Printf("\nError: %s\n", red(result.Error.Error()))
	}

	fmt.Println("--------------------------------")
}

func runList(cmd *cobra.Command, args []string) {

	outputDir, _ := cmd.Flags().GetString("output-dir")
	listType, _ := cmd.Flags().GetString("type")
	countOnly, _ := cmd.Flags().GetBool("count")

	outputPrefix := ""
	if len(args) > 0 {
		outputPrefix = args[0]
	}

	activeFile := filepath.Join(outputDir, outputPrefix+"active_domains.txt")
	inactiveFile := filepath.Join(outputDir, outputPrefix+"inactive_domains.txt")

	_, activeErr := os.Stat(activeFile)
	_, inactiveErr := os.Stat(inactiveFile)

	if activeErr != nil && inactiveErr != nil {
		fmt.Fprintf(os.Stderr, "%s No result files found in %s\n", red("ERROR:"), outputDir)
		os.Exit(1)
	}

	var activeDomains, inactiveDomains []string

	if (listType == "all" || listType == "active") && activeErr == nil {
		activeDomains = readLines(activeFile)
	}

	if (listType == "all" || listType == "inactive") && inactiveErr == nil {
		inactiveDomains = readLines(inactiveFile)
	}

	if !countOnly {
		fmt.Println(logo)
	}

	if countOnly {
		if listType == "all" || listType == "active" {
			fmt.Printf("Active domains: %s\n", green(len(activeDomains)))
		}
		if listType == "all" || listType == "inactive" {
			fmt.Printf("Inactive domains: %s\n", red(len(inactiveDomains)))
		}
		if listType == "all" {
			fmt.Printf("Total domains: %s\n", magenta(len(activeDomains)+len(inactiveDomains)))
		}
	} else {
		if listType == "all" || listType == "active" {
			fmt.Printf("%s Active domains (%d):\n", green("✓"), len(activeDomains))
			for _, domain := range activeDomains {
				fmt.Printf("  %s\n", domain)
			}
			fmt.Println()
		}

		if listType == "all" || listType == "inactive" {
			fmt.Printf("%s Inactive domains (%d):\n", red("✗"), len(inactiveDomains))
			for _, domain := range inactiveDomains {
				fmt.Printf("  %s\n", domain)
			}
		}
	}
}

func runTechDetection(cmd *cobra.Command, args []string) {

	domain := args[0]

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.Split(domain, "/")[0]

	timeout, _ := cmd.Flags().GetDuration("timeout")
	verbose, _ := cmd.Flags().GetBool("verbose")

	fmt.Println(logo)
	fmt.Printf("%s Detecting technologies for %s\n", blue("INFO:"), cyan(domain))

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.UserAgent("Mozilla/5.0 (compatible; Scanera/1.0; +https://github.com/Sla0ui/scanera)"),
		chromedp.NoSandbox,
		chromedp.DisableGPU,
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	browserCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel := context.WithTimeout(browserCtx, timeout)
	defer cancel()

	var html string
	var headers map[string][]string
	var title string

	httpsURL := "https://" + domain
	httpURL := "http://" + domain

	err := chromedp.Run(ctx,
		chromedp.Navigate(httpsURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Title(&title),
		chromedp.OuterHTML("html", &html),
		chromedp.ActionFunc(func(ctx context.Context) error {
			if verbose {
				fmt.Printf("Cookies might be present. Use a regular HTTP client to inspect them.\n")
			}
			return nil
		}),
	)

	if err != nil {
		if verbose {
			fmt.Printf("%s HTTPS connection failed, trying HTTP: %v\n", yellow("DEBUG:"), err)
		}

		err = chromedp.Run(ctx,
			chromedp.Navigate(httpURL),
			chromedp.WaitReady("body", chromedp.ByQuery),
			chromedp.Title(&title),
			chromedp.OuterHTML("html", &html),
		)

		if err != nil {
			fmt.Printf("%s Failed to connect to website: %v\n", red("ERROR:"), err)
			return
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	req, _ := http.NewRequest("GET", httpsURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Scanera/1.0; +https://github.com/Sla0ui/scanera)")

	resp, err := client.Do(req)
	if err == nil {
		headers = resp.Header
		resp.Body.Close()
	} else {

		req, _ = http.NewRequest("GET", httpURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Scanera/1.0; +https://github.com/Sla0ui/scanera)")

		resp, err = client.Do(req)
		if err == nil {
			headers = resp.Header
			resp.Body.Close()
		}
	}

	result := Result{
		Domain: domain,
		Title:  title,
	}

	if html != "" {
		detectTechnologies(html, headers, &result)
	}

	fmt.Println("\n--------------------------------")
	fmt.Printf("Domain: %s\n", cyan(domain))
	fmt.Printf("Title: %s\n", title)
	fmt.Println("--------------------------------")

	if len(result.Technologies) > 0 {
		fmt.Printf("%s Detected Technologies:\n", green("✓"))

		categories := map[string][]string{
			"CMS":           {},
			"JavaScript":    {},
			"CSS Framework": {},
			"Server":        {},
			"Analytics":     {},
			"Payment":       {},
			"Security":      {},
			"Framework":     {},
			"Programming":   {},
			"Miscellaneous": {},
		}

		for _, tech := range result.Technologies {
			switch tech {
			case "WordPress", "Joomla", "Drupal", "Magento", "Shopify", "WooCommerce":
				categories["CMS"] = append(categories["CMS"], tech)
			case "jQuery", "React", "Vue.js", "Angular", "Modernizr", "Moment.js", "Lodash", "Axios", "Chart.js", "D3.js":
				categories["JavaScript"] = append(categories["JavaScript"], tech)
			case "Bootstrap", "Tailwind CSS", "Font Awesome", "Leaflet":
				categories["CSS Framework"] = append(categories["CSS Framework"], tech)
			case "Apache", "Nginx", "IIS", "LiteSpeed", "Cloudflare":
				categories["Server"] = append(categories["Server"], tech)
			case "Google Analytics", "Google Tag Manager", "Hotjar", "Intercom", "Drift":
				categories["Analytics"] = append(categories["Analytics"], tech)
			case "Stripe", "PayPal":
				categories["Payment"] = append(categories["Payment"], tech)
			case "Google reCAPTCHA":
				categories["Security"] = append(categories["Security"], tech)
			case "Express.js", "ASP.NET":
				categories["Framework"] = append(categories["Framework"], tech)
			case "PHP":
				categories["Programming"] = append(categories["Programming"], tech)
			default:
				categories["Miscellaneous"] = append(categories["Miscellaneous"], tech)
			}
		}

		for category, techs := range categories {
			if len(techs) > 0 {
				fmt.Printf("  %s %s:\n", magenta("➤"), yellow(category))
				for _, tech := range techs {
					fmt.Printf("    - %s\n", tech)
				}
			}
		}
	} else {
		fmt.Printf("%s No technologies detected\n", red("✗"))
	}

	fmt.Println("--------------------------------")
}

func runScreenshot(cmd *cobra.Command, args []string) {

	domain := args[0]

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.Split(domain, "/")[0]

	outputFile, _ := cmd.Flags().GetString("output")
	width, _ := cmd.Flags().GetInt("width")
	height, _ := cmd.Flags().GetInt("height")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	fullpage, _ := cmd.Flags().GetBool("fullpage")

	if outputFile == "" {
		outputFile = domain + ".png"
	}

	fmt.Println(logo)
	fmt.Printf("%s Taking screenshot of %s\n", blue("INFO:"), cyan(domain))

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.UserAgent("Mozilla/5.0 (compatible; Scanera/1.0; +https://github.com/Sla0ui/scanera)"),
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.WindowSize(width, height),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	browserCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel := context.WithTimeout(browserCtx, timeout)
	defer cancel()

	urls := []string{
		"https://" + domain,
		"http://" + domain,
	}

	var buf []byte
	var err error
	var succeeded bool

	for _, url := range urls {
		fmt.Printf("%s Trying %s\n", blue("INFO:"), url)

		if fullpage {

			err = chromedp.Run(ctx,
				chromedp.Navigate(url),
				chromedp.WaitReady("body", chromedp.ByQuery),
				chromedp.ActionFunc(func(ctx context.Context) error {

					err := emulation.SetDeviceMetricsOverride(int64(width), int64(height), 1, false).Do(ctx)
					if err != nil {
						return err
					}

					var height int64
					err = chromedp.Evaluate(`
						Math.max(
							document.body.scrollHeight, 
							document.documentElement.scrollHeight,
							document.body.offsetHeight, 
							document.documentElement.offsetHeight
						)
					`, &height).Do(ctx)
					if err != nil {
						return err
					}

					return emulation.SetDeviceMetricsOverride(int64(width), int64(height), 1, false).Do(ctx)
				}),
				chromedp.CaptureScreenshot(&buf),
			)
		} else {

			err = chromedp.Run(ctx,
				chromedp.Navigate(url),
				chromedp.WaitReady("body", chromedp.ByQuery),
				chromedp.CaptureScreenshot(&buf),
			)
		}

		if err == nil {
			succeeded = true
			break
		}

		fmt.Printf("%s Failed to take screenshot: %v\n", yellow("DEBUG:"), err)
	}

	if !succeeded {
		fmt.Printf("%s Could not take screenshot of %s\n", red("ERROR:"), domain)
		os.Exit(1)
	}

	if err := os.WriteFile(outputFile, buf, 0644); err != nil {
		fmt.Printf("%s Failed to save screenshot: %v\n", red("ERROR:"), err)
		os.Exit(1)
	}

	fmt.Printf("%s Screenshot saved to %s\n", green("SUCCESS:"), outputFile)
}

func runSecurityCheck(cmd *cobra.Command, args []string) {

	domain := args[0]

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.Split(domain, "/")[0]

	timeout, _ := cmd.Flags().GetDuration("timeout")
	verbose, _ := cmd.Flags().GetBool("verbose")

	fmt.Println(logo)
	fmt.Printf("%s Checking security for %s\n", blue("INFO:"), cyan(domain))

	httpsURL := "https://" + domain
	httpURL := "http://" + domain

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	result := Result{
		Domain: domain,
		SecurityInfo: SecurityInfo{
			SecurityHeaders: make(map[string]string),
		},
	}

	req, _ := http.NewRequest("GET", httpsURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Scanera/1.0; +https://github.com/Sla0ui/scanera)")

	resp, err := client.Do(req)
	if err == nil {
		result.SecurityInfo.HasHTTPS = true
		checkSecurityHeaders(resp, &result)
		fetchCertificateInfo(domain, &result)
		resp.Body.Close()
	} else if verbose {
		fmt.Printf("%s HTTPS connection failed: %v\n", yellow("DEBUG:"), err)
	}

	req, _ = http.NewRequest("GET", httpURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Scanera/1.0; +https://github.com/Sla0ui/scanera)")

	resp, err = client.Do(req)
	if err == nil {

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if strings.HasPrefix(location, "https://") {
				result.SecurityInfo.HTTPSRedirect = true
			}
		}
		resp.Body.Close()
	}

	fmt.Println("\n--------------------------------")
	fmt.Printf("Domain: %s\n", cyan(domain))
	fmt.Println("--------------------------------")

	fmt.Println("HTTPS Availability:")
	if result.SecurityInfo.HasHTTPS {
		fmt.Printf("  %s HTTPS: %s\n", green("✓"), "Available")

		if result.SecurityInfo.TLSVersion != "" {
			fmt.Printf("  %s TLS Version: %s\n", green("✓"), result.SecurityInfo.TLSVersion)
		}

		if result.SecurityInfo.CertIssuer != "" {
			fmt.Printf("  %s Certificate Issuer: %s\n", green("✓"), result.SecurityInfo.CertIssuer)
			fmt.Printf("  %s Certificate Expiry: %s\n", green("✓"), result.SecurityInfo.CertExpiry.Format("2006-01-02"))

			if result.SecurityInfo.ValidCert {
				fmt.Printf("  %s Certificate Valid: %s\n", green("✓"), "Yes")
			} else {
				fmt.Printf("  %s Certificate Valid: %s\n", red("✗"), "No")
			}
		}
	} else {
		fmt.Printf("  %s HTTPS: %s\n", red("✗"), "Not available")
	}

	if result.SecurityInfo.HTTPSRedirect {
		fmt.Printf("  %s HTTP to HTTPS Redirect: %s\n", green("✓"), "Yes")
	} else {
		fmt.Printf("  %s HTTP to HTTPS Redirect: %s\n", red("✗"), "No")
	}

	fmt.Println("\nSecurity Headers:")
	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Feature-Policy",
		"Permissions-Policy",
	}

	headersFound := false
	for _, header := range securityHeaders {
		value, exists := result.SecurityInfo.SecurityHeaders[header]
		if exists {
			headersFound = true
			fmt.Printf("  %s %s: %s\n", green("✓"), header, value)
		} else {
			fmt.Printf("  %s %s: %s\n", red("✗"), header, "Not set")
		}
	}

	if !headersFound {
		fmt.Println("  No security headers found")
	}

	fmt.Println("\nSecurity Assessment:")

	if result.SecurityInfo.HasHTTPS {
		fmt.Printf("  %s Site uses HTTPS\n", green("✓"))
	} else {
		fmt.Printf("  %s Site does not use HTTPS\n", red("✗"))
	}

	if result.SecurityInfo.HasHTTPS && result.SecurityInfo.ValidCert {
		fmt.Printf("  %s Valid SSL/TLS certificate\n", green("✓"))
	} else if result.SecurityInfo.HasHTTPS {
		fmt.Printf("  %s Invalid SSL/TLS certificate\n", red("✗"))
	}

	if result.SecurityInfo.HTTPSRedirect {
		fmt.Printf("  %s HTTP redirects to HTTPS\n", green("✓"))
	} else {
		fmt.Printf("  %s HTTP does not redirect to HTTPS\n", red("✗"))
	}

	if result.SecurityInfo.HSTPEnabled {
		fmt.Printf("  %s HSTS is enabled\n", green("✓"))
	} else {
		fmt.Printf("  %s HSTS is not enabled\n", red("✗"))
	}

	if result.SecurityInfo.TLSVersion == "TLS 1.2" || result.SecurityInfo.TLSVersion == "TLS 1.3" {
		fmt.Printf("  %s Modern TLS version (%s)\n", green("✓"), result.SecurityInfo.TLSVersion)
	} else if result.SecurityInfo.TLSVersion != "" {
		fmt.Printf("  %s Outdated TLS version (%s)\n", red("✗"), result.SecurityInfo.TLSVersion)
	}

	if _, exists := result.SecurityInfo.SecurityHeaders["Content-Security-Policy"]; exists {
		fmt.Printf("  %s Content Security Policy is set\n", green("✓"))
	} else {
		fmt.Printf("  %s Content Security Policy is not set\n", red("✗"))
	}

	if _, exists := result.SecurityInfo.SecurityHeaders["X-Frame-Options"]; exists {
		fmt.Printf("  %s X-Frame-Options is set\n", green("✓"))
	} else {
		fmt.Printf("  %s X-Frame-Options is not set\n", red("✗"))
	}

	fmt.Println("--------------------------------")
}

func runReportGeneration(cmd *cobra.Command, args []string) {

	inputFile, _ := cmd.Flags().GetString("input")
	outputPrefix, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")

	if inputFile == "" && len(args) > 0 {
		inputFile = args[0]
	}

	if inputFile == "" {
		fmt.Fprintf(os.Stderr, "%s No input file specified\n", red("ERROR:"))
		os.Exit(1)
	}

	data, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to read input file: %v\n", red("ERROR:"), err)
		os.Exit(1)
	}

	var results []Result
	if err := json.Unmarshal(data, &results); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to parse input file: %v\n", red("ERROR:"), err)
		os.Exit(1)
	}

	fmt.Println(logo)
	fmt.Printf("%s Generating %s report from %s\n", blue("INFO:"), format, inputFile)
	fmt.Printf("%s Output prefix: %s\n", blue("INFO:"), outputPrefix)

	switch strings.ToLower(format) {
	case "html":
		generateHTMLReport(results, outputPrefix+".html")
		fmt.Printf("%s HTML report saved to %s\n", green("SUCCESS:"), outputPrefix+".html")
	case "csv":
		generateCSVReport(results, outputPrefix+".csv")
		fmt.Printf("%s CSV report saved to %s\n", green("SUCCESS:"), outputPrefix+".csv")
	case "json":
		jsonData, _ := json.MarshalIndent(results, "", "  ")
		os.WriteFile(outputPrefix+".json", jsonData, 0644)
		fmt.Printf("%s JSON report saved to %s\n", green("SUCCESS:"), outputPrefix+".json")
	case "markdown", "md":
		generateMarkdownReport(results, outputPrefix+".md")
		fmt.Printf("%s Markdown report saved to %s\n", green("SUCCESS:"), outputPrefix+".md")
	case "pdf":

		htmlFile := outputPrefix + "_temp.html"
		generateHTMLReport(results, htmlFile)

		cmd := exec.Command("wkhtmltopdf", htmlFile, outputPrefix+".pdf")
		if err := cmd.Run(); err != nil {
			fmt.Printf("%s Failed to convert to PDF: %v\n", red("ERROR:"), err)
			fmt.Printf("%s HTML report saved instead at %s\n", yellow("WARNING:"), htmlFile)
		} else {
			os.Remove(htmlFile)
			fmt.Printf("%s PDF report saved to %s\n", green("SUCCESS:"), outputPrefix+".pdf")
		}
	default:
		fmt.Printf("%s Unsupported format: %s\n", red("ERROR:"), format)
		os.Exit(1)
	}
}

func runBatchProcessing(cmd *cobra.Command, args []string) {

	domainsDir := args[0]
	pattern, _ := cmd.Flags().GetString("pattern")
	outputDir, _ := cmd.Flags().GetString("output-dir")
	concurrentFiles, _ := cmd.Flags().GetInt("concurrent-files")

	loadConfig(cmd)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to create output directory: %v\n", red("ERROR:"), err)
		os.Exit(1)
	}

	matches, err := filepath.Glob(filepath.Join(domainsDir, pattern))
	if err != nil || len(matches) == 0 {
		fmt.Fprintf(os.Stderr, "%s No matching files found: %v\n", red("ERROR:"), err)
		os.Exit(1)
	}

	fmt.Println(logo)
	fmt.Printf("%s Found %d files to process\n", blue("INFO:"), len(matches))

	sem := make(chan struct{}, concurrentFiles)
	var wg sync.WaitGroup

	for _, file := range matches {
		wg.Add(1)
		sem <- struct{}{}

		go func(file string) {
			defer func() {
				<-sem
				wg.Done()
			}()

			fileName := filepath.Base(file)
			fileOutputDir := filepath.Join(outputDir, strings.TrimSuffix(fileName, filepath.Ext(fileName)))

			if err := os.MkdirAll(fileOutputDir, 0755); err != nil {
				fmt.Printf("%s Failed to create output directory for %s: %v\n", red("ERROR:"), fileName, err)
				return
			}

			fmt.Printf("%s Processing %s\n", blue("INFO:"), fileName)

			domains, err := readDomainsFromFile(file)
			if err != nil {
				fmt.Printf("%s Failed to read domains from %s: %v\n", red("ERROR:"), fileName, err)
				return
			}

			allocCtx, allocCancel := setupBrowserContext()
			defer allocCancel()

			config.OutputDir = fileOutputDir

			if config.TakeScreenshots {
				screenshotPath := filepath.Join(config.OutputDir, config.ScreenshotDir)
				if err := os.MkdirAll(screenshotPath, 0755); err != nil {
					fmt.Printf("%s Failed to create screenshots directory for %s: %v\n", red("ERROR:"), fileName, err)
				}
			}

			results := processDomainsWithPool(context.Background(), domains, allocCtx)

			processResults(results)

			if config.ExportPath != "" {
				exportPath := filepath.Join(fileOutputDir, filepath.Base(config.ExportPath))
				generateReport(results, exportPath, config.OutputFormat)
			}

			fmt.Printf("%s Completed processing %s\n", green("SUCCESS:"), fileName)
		}(file)
	}

	wg.Wait()
	fmt.Printf("%s Batch processing completed\n", green("SUCCESS:"))
}

func readLines(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		return []string{}
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	return lines
}

func appendToFile(filename, text string) {
	fileMutex.Lock()
	defer fileMutex.Unlock()

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		if !config.Quiet {
			fmt.Fprintf(os.Stderr, "%s Error opening file for append: %v\n",
				red("ERROR:"), err)
		}
		return
	}
	defer file.Close()

	if _, err := file.WriteString(text); err != nil {
		if !config.Quiet {
			fmt.Fprintf(os.Stderr, "%s Error writing to file: %v\n",
				red("ERROR:"), err)
		}
	}
}

func contains(slice []int, item int) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
