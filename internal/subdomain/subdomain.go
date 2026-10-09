// Package subdomain discovers subdomains of a domain via passive certificate
// transparency (crt.sh) and an optional DNS brute-force over a wordlist.
package subdomain

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sla0ui/scanera/internal/dnsx"
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

// Enumerate discovers subdomains of domain. Passive sources always run; the
// brute-force runs unless PassiveOnly is set or the domain has wildcard DNS
// (which would make every guess "resolve" and produce noise).
func Enumerate(ctx context.Context, domain string, opts Options) []string {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 20
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}

	set := make(map[string]struct{})
	for _, s := range crtsh(ctx, domain, opts) {
		set[s] = struct{}{}
	}

	if !opts.PassiveOnly && !dnsx.HasWildcard(ctx, domain, opts.Timeout) {
		for _, s := range bruteforce(ctx, domain, opts) {
			set[s] = struct{}{}
		}
	}

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func crtsh(ctx context.Context, domain string, opts Options) []string {
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	if opts.Limiter != nil {
		_ = opts.Limiter.Wait(ctx)
	}

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "scanera")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil
	}

	set := make(map[string]struct{})
	suffix := "." + domain
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "*.")))
			if name == "" || strings.ContainsAny(name, " *") {
				continue
			}
			if name == domain || strings.HasSuffix(name, suffix) {
				set[name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out
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
