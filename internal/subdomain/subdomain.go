// Package subdomain discovers subdomains of a domain via passive certificate
// transparency (crt.sh) and an optional DNS brute-force over a wordlist.
package subdomain

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sla0ui/scanera/internal/dnsx"
	"github.com/Sla0ui/scanera/internal/netx"
	"github.com/Sla0ui/scanera/internal/ratelimit"
)

//go:embed wordlist.txt
var embeddedWordlist string

// DefaultWordlist returns the built-in subdomain label list.
func DefaultWordlist() []string {
	var words []string
	sc := bufio.NewScanner(strings.NewReader(embeddedWordlist))
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	return words
}

// Options controls enumeration.
type Options struct {
	PassiveOnly bool
	Wordlist    []string
	Concurrency int
	Timeout     time.Duration
	Client      *http.Client
	Limiter     *ratelimit.Limiter
}

// Passive source endpoints; variables so tests can point them at a local server.
var (
	crtshURL       = "https://crt.sh/"
	certspotterURL = "https://api.certspotter.com/v1/issuances"
)

// passiveTimeout is the floor for passive source requests; certificate
// transparency APIs regularly take far longer than a normal page load.
const passiveTimeout = 60 * time.Second

// Enumerate discovers subdomains of domain. Passive sources always run; the
// brute-force runs unless PassiveOnly is set or the domain has wildcard DNS
// (which would make every guess "resolve" and produce noise). Whatever was
// found is returned even when a source fails; the error describes failures.
func Enumerate(ctx context.Context, domain string, opts Options) ([]string, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 20
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	set := make(map[string]struct{})
	var errs []error
	for _, src := range []struct {
		name string
		fn   func(context.Context, string, Options) ([]string, error)
	}{
		{"crt.sh", crtsh},
		{"certspotter", certspotter},
	} {
		names, err := src.fn(ctx, domain, opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src.name, err))
		}
		for _, n := range names {
			set[n] = struct{}{}
		}
	}

	if !opts.PassiveOnly && ctx.Err() == nil && !dnsx.HasWildcard(ctx, domain, opts.Timeout) {
		for _, s := range bruteforce(ctx, domain, opts) {
			set[s] = struct{}{}
		}
	}

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, errors.Join(errs...)
}

func passiveClient(opts Options) *http.Client {
	if opts.Client == nil {
		return &http.Client{Timeout: passiveTimeout}
	}
	if opts.Client.Timeout != 0 && opts.Client.Timeout < passiveTimeout {
		return netx.WithTimeout(opts.Client, passiveTimeout)
	}
	return opts.Client
}

func getJSON(ctx context.Context, opts Options, rawURL string, v any) error {
	if opts.Limiter != nil {
		if err := opts.Limiter.Wait(ctx); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "scanera")
	req.Header.Set("Accept", "application/json")

	resp, err := passiveClient(opts).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(v)
}

func crtsh(ctx context.Context, domain string, opts Options) ([]string, error) {
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	u := crtshURL + "?q=" + url.QueryEscape("%."+domain) + "&output=json"
	if err := getJSON(ctx, opts, u, &entries); err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		names = append(names, strings.Split(e.NameValue, "\n")...)
	}
	return filterNames(domain, names), nil
}

func certspotter(ctx context.Context, domain string, opts Options) ([]string, error) {
	var issuances []struct {
		DNSNames []string `json:"dns_names"`
	}
	u := certspotterURL + "?domain=" + url.QueryEscape(domain) +
		"&include_subdomains=true&expand=dns_names"
	if err := getJSON(ctx, opts, u, &issuances); err != nil {
		return nil, err
	}
	var names []string
	for _, is := range issuances {
		names = append(names, is.DNSNames...)
	}
	return filterNames(domain, names), nil
}

// filterNames keeps well-formed names under domain, lowercased, with any
// leading wildcard label dropped.
func filterNames(domain string, names []string) []string {
	set := make(map[string]struct{})
	suffix := "." + domain
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "*.")))
		name = strings.TrimSuffix(name, ".")
		if name == "" || !validHostname(name) {
			continue
		}
		if name == domain || strings.HasSuffix(name, suffix) {
			set[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func validHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

func bruteforce(ctx context.Context, domain string, opts Options) []string {
	words := opts.Wordlist
	if len(words) == 0 {
		words = DefaultWordlist()
	}

	jobs := make(chan string)
	results := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for label := range jobs {
				host := label + "." + domain
				if dnsx.Resolves(ctx, host, opts.Timeout) {
					results <- host
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, w := range words {
			select {
			case jobs <- w:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var found []string
	for h := range results {
		found = append(found, h)
	}
	return found
}
