// Package signature is a small, data-driven detection engine in the spirit of
// nuclei: YAML templates describe HTTP requests and matchers, and the engine
// emits findings. Built-in templates are embedded; users can add their own
// directory. This replaces scattered hardcoded checks with extensible data.
package signature

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Sla0ui/scanera/internal/models"
	"github.com/Sla0ui/scanera/internal/ratelimit"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*.yaml
var builtinFS embed.FS

// Template is a single detection definition.
type Template struct {
	ID       string    `yaml:"id"`
	Info     Info      `yaml:"info"`
	Requests []Request `yaml:"requests"`

	source string // file the template came from, for error messages
}

// Info holds template metadata.
type Info struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Reference   []string `yaml:"reference"`
	Tags        []string `yaml:"tags"`
}

// Request is one HTTP request and its matchers. Path, header values and body
// may use the placeholders {{BaseURL}}, {{RootURL}}, {{Scheme}}, {{Hostname}}
// (host with port) and {{Host}} (host without port).
type Request struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Headers           map[string]string `yaml:"headers"`
	Body              string            `yaml:"body"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Matchers          []Matcher         `yaml:"matchers"`
}

// Matcher evaluates part of a response.
type Matcher struct {
	Type            string   `yaml:"type"` // status | word | regex
	Part            string   `yaml:"part"` // body | header | all
	Status          []int    `yaml:"status"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Condition       string   `yaml:"condition"` // and | or (within this matcher)
	Negative        bool     `yaml:"negative"`  // invert the result
	CaseInsensitive bool     `yaml:"case-insensitive"`

	compiled []*regexp.Regexp
}

// Engine holds loaded templates.
type Engine struct {
	templates []*Template
}

// Load reads the embedded built-in templates plus any *.yaml/*.yml under
// userDir. A userDir that doesn't exist is an error, as is any template that
// fails to parse or validate, or an ID that appears twice.
func Load(userDir string) (*Engine, error) {
	e := &Engine{}
	seen := make(map[string]string)
	add := func(t *Template) error {
		if prev, ok := seen[t.ID]; ok {
			return fmt.Errorf("duplicate template id %q in %s (already defined in %s)", t.ID, t.source, prev)
		}
		seen[t.ID] = t.source
		e.templates = append(e.templates, t)
		return nil
	}

	entries, err := builtinFS.ReadDir("templates")
	if err != nil {
		return nil, fmt.Errorf("reading built-in templates: %w", err)
	}
	for _, en := range entries {
		data, err := builtinFS.ReadFile("templates/" + en.Name())
		if err != nil {
			return nil, fmt.Errorf("built-in template %s: %w", en.Name(), err)
		}
		t, err := parse(data)
		if err != nil {
			return nil, fmt.Errorf("built-in template %s: %w", en.Name(), err)
		}
		t.source = "built-in " + en.Name()
		if err := add(t); err != nil {
			return nil, err
		}
	}

	if userDir == "" {
		return e, nil
	}
	info, err := os.Stat(userDir)
	if err != nil {
		return nil, fmt.Errorf("templates dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("templates dir %q is not a directory", userDir)
	}
	err = filepath.WalkDir(userDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // operator-supplied dir
		if err != nil {
			return err
		}
		t, err := parse(data)
		if err != nil {
			return fmt.Errorf("template %s: %w", path, err)
		}
		t.source = path
		return add(t)
	})
	if err != nil {
		return nil, err
	}
	return e, nil
}

func parse(data []byte) (*Template, error) {
	var t Template
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("empty template")
		}
		return nil, err
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// validate rejects templates that would silently never match, and compiles
// regexes once up front.
func (t *Template) validate() error {
	if t.ID == "" {
		return fmt.Errorf("missing id")
	}
	if t.Info.Name == "" {
		t.Info.Name = t.ID
	}
	if t.Info.Severity == "" {
		t.Info.Severity = string(models.SeverityInfo)
	}
	if !models.Severity(t.Info.Severity).Valid() {
		return fmt.Errorf("unknown severity %q", t.Info.Severity)
	}
	if len(t.Requests) == 0 {
		return fmt.Errorf("no requests")
	}
	for ri := range t.Requests {
		req := &t.Requests[ri]
		if len(req.Path) == 0 {
			return fmt.Errorf("request %d: no path", ri+1)
		}
		if len(req.Matchers) == 0 {
			return fmt.Errorf("request %d: no matchers", ri+1)
		}
		if !oneOf(req.MatchersCondition, "", "and", "or") {
			return fmt.Errorf("request %d: matchers-condition must be and/or, got %q", ri+1, req.MatchersCondition)
		}
		for mi := range req.Matchers {
			m := &req.Matchers[mi]
			where := fmt.Sprintf("request %d matcher %d", ri+1, mi+1)
			if !oneOf(m.Part, "", "body", "header", "all") {
				return fmt.Errorf("%s: unknown part %q", where, m.Part)
			}
			if !oneOf(m.Condition, "", "and", "or") {
				return fmt.Errorf("%s: condition must be and/or, got %q", where, m.Condition)
			}
			switch strings.ToLower(m.Type) {
			case "status":
				if len(m.Status) == 0 {
					return fmt.Errorf("%s: status matcher without status codes", where)
				}
			case "word":
				if len(m.Words) == 0 {
					return fmt.Errorf("%s: word matcher without words", where)
				}
			case "regex":
				if len(m.Regex) == 0 {
					return fmt.Errorf("%s: regex matcher without patterns", where)
				}
				for _, rx := range m.Regex {
					if m.CaseInsensitive && !strings.HasPrefix(rx, "(?i)") {
						rx = "(?i)" + rx
					}
					re, err := regexp.Compile(rx)
					if err != nil {
						return fmt.Errorf("%s: bad regex %q: %w", where, rx, err)
					}
					m.compiled = append(m.compiled, re)
				}
			default:
				return fmt.Errorf("%s: unknown type %q (want status, word or regex)", where, m.Type)
			}
		}
	}
	return nil
}

func oneOf(v string, allowed ...string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// Templates returns the loaded templates sorted by ID.
func (e *Engine) Templates() []*Template {
	out := append([]*Template(nil), e.templates...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RunOptions configures a run.
type RunOptions struct {
	Client    *http.Client
	UserAgent string
	Limiter   *ratelimit.Limiter
	// Allow, when set, must approve a request's host before it is sent. It
	// stops templates with absolute URLs from reaching unauthorized hosts.
	Allow func(host string) bool
}

// Run evaluates every template against baseURL (scheme://host) and returns the
// findings for those that match.
func (e *Engine) Run(ctx context.Context, baseURL string, opts RunOptions) []models.Finding {
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	vars := placeholders(strings.TrimRight(baseURL, "/"))

	var findings []models.Finding
	for _, t := range e.templates {
		if ctx.Err() != nil {
			break
		}
		if f, ok := e.runTemplate(ctx, t, vars, client, opts); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

func placeholders(baseURL string) *strings.Replacer {
	scheme, hostname, host := "", "", ""
	if u, err := url.Parse(baseURL); err == nil {
		scheme, hostname, host = u.Scheme, u.Host, u.Hostname()
	}
	return strings.NewReplacer(
		"{{BaseURL}}", baseURL,
		"{{RootURL}}", baseURL,
		"{{Scheme}}", scheme,
		"{{Hostname}}", hostname,
		"{{Host}}", host,
	)
}

func (e *Engine) runTemplate(ctx context.Context, t *Template, vars *strings.Replacer, client *http.Client, opts RunOptions) (models.Finding, bool) {
	for _, req := range t.Requests {
		method := strings.ToUpper(req.Method)
		if method == "" {
			method = http.MethodGet
		}
		for _, rawPath := range req.Path {
			target := vars.Replace(rawPath)
			if opts.Allow != nil {
				u, err := url.Parse(target)
				if err != nil || !opts.Allow(u.Host) {
					continue
				}
			}
			if opts.Limiter != nil {
				if err := opts.Limiter.Wait(ctx); err != nil {
					return models.Finding{}, false
				}
			}
			status, body, header, err := do(ctx, client, method, target, vars.Replace(req.Body), req.Headers, vars, opts.UserAgent)
			if err != nil {
				continue
			}
			if matchRequest(req, status, body, header) {
				return models.Finding{
					ID:          t.ID,
					Title:       t.Info.Name,
					Severity:    models.Severity(t.Info.Severity),
					Source:      "template",
					Description: t.Info.Description,
					Location:    target,
					References:  t.Info.Reference,
					Tags:        t.Info.Tags,
				}, true
			}
		}
	}
	return models.Finding{}, false
}

func do(ctx context.Context, client *http.Client, method, target, body string, headers map[string]string, vars *strings.Replacer, ua string) (int, string, string, error) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return 0, "", "", err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	for k, v := range headers {
		v = vars.Replace(v)
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))

	var hb strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			hb.WriteString(k)
			hb.WriteString(": ")
			hb.WriteString(v)
			hb.WriteString("\n")
		}
	}
	return resp.StatusCode, string(respBody), hb.String(), nil
}

// matchRequest applies the request's matchers. matchers-condition defaults to
// "and" (every matcher must pass), which keeps false positives low.
func matchRequest(req Request, status int, body, header string) bool {
	if len(req.Matchers) == 0 {
		return false
	}
	orCond := strings.EqualFold(strings.TrimSpace(req.MatchersCondition), "or")
	for _, m := range req.Matchers {
		ok := evalMatcher(m, status, body, header)
		if orCond && ok {
			return true
		}
		if !orCond && !ok {
			return false
		}
	}
	return !orCond
}

func evalMatcher(m Matcher, status int, body, header string) bool {
	var ok bool
	switch strings.ToLower(m.Type) {
	case "status":
		for _, s := range m.Status {
			if s == status {
				ok = true
				break
			}
		}
	case "word":
		text := partText(m.Part, body, header)
		if m.CaseInsensitive {
			text = strings.ToLower(text)
		}
		ok = reduce(m.Condition, len(m.Words), func(i int) bool {
			w := m.Words[i]
			if m.CaseInsensitive {
				w = strings.ToLower(w)
			}
			return strings.Contains(text, w)
		})
	case "regex":
		text := partText(m.Part, body, header)
		ok = reduce(m.Condition, len(m.compiled), func(i int) bool {
			return m.compiled[i].MatchString(text)
		})
	default:
		return false
	}
	if m.Negative {
		return !ok
	}
	return ok
}

func partText(part, body, header string) string {
	switch strings.ToLower(part) {
	case "header":
		return header
	case "all":
		return header + "\n" + body
	default:
		return body
	}
}

// reduce applies cond ("and"/"or", default "or") across n items.
func reduce(cond string, n int, pred func(int) bool) bool {
	if n == 0 {
		return false
	}
	and := strings.EqualFold(strings.TrimSpace(cond), "and")
	for i := 0; i < n; i++ {
		ok := pred(i)
		if and && !ok {
			return false
		}
		if !and && ok {
			return true
		}
	}
	return and
}
