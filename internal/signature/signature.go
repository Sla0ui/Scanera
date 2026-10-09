// Package signature is a small, data-driven detection engine in the spirit of
// nuclei: YAML templates describe HTTP requests and matchers, and the engine
// emits findings. Built-in templates are embedded; users can add their own
// directory. This replaces scattered hardcoded checks with extensible data.
package signature

import (
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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
}

// Info holds template metadata.
type Info struct {
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Reference   []string `yaml:"reference"`
	Tags        []string `yaml:"tags"`
}

// Request is one HTTP request and its matchers.
type Request struct {
	Method            string    `yaml:"method"`
	Path              []string  `yaml:"path"`
	MatchersCondition string    `yaml:"matchers-condition"`
	Matchers          []Matcher `yaml:"matchers"`
}

// Matcher evaluates part of a response.
type Matcher struct {
	Type      string   `yaml:"type"` // status | word | regex
	Part      string   `yaml:"part"` // body | header | all
	Status    []int    `yaml:"status"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Condition string   `yaml:"condition"` // and | or (within this matcher)

	compiled []*regexp.Regexp
}

// Engine holds loaded templates.
type Engine struct {
	templates []*Template
}

// Load reads the embedded built-in templates plus any *.yaml under userDir.
func Load(userDir string) (*Engine, error) {
	e := &Engine{}

	entries, err := builtinFS.ReadDir("templates")
	if err != nil {
		return nil, fmt.Errorf("reading built-in templates: %w", err)
	}
	for _, en := range entries {
		data, err := builtinFS.ReadFile("templates/" + en.Name())
		if err != nil {
			continue
		}
		t, err := parse(data)
		if err != nil {
			return nil, fmt.Errorf("built-in template %s: %w", en.Name(), err)
		}
		e.templates = append(e.templates, t)
	}

	if userDir != "" {
		err := filepath.WalkDir(userDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
				return nil
			}
			data, err := os.ReadFile(path) //nolint:gosec // operator-supplied dir
			if err != nil {
				return nil
			}
			t, err := parse(data)
			if err != nil {
				return fmt.Errorf("template %s: %w", path, err)
			}
			e.templates = append(e.templates, t)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return e, nil
}

func parse(data []byte) (*Template, error) {
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	if t.ID == "" {
		return nil, fmt.Errorf("missing id")
	}
	for ri := range t.Requests {
		for mi := range t.Requests[ri].Matchers {
			m := &t.Requests[ri].Matchers[mi]
			for _, rx := range m.Regex {
				re, err := regexp.Compile(rx)
				if err != nil {
					return nil, fmt.Errorf("bad regex %q: %w", rx, err)
				}
				m.compiled = append(m.compiled, re)
			}
		}
	}
	return &t, nil
}

// Templates returns the loaded templates.
func (e *Engine) Templates() []*Template { return e.templates }

// RunOptions configures a run.
type RunOptions struct {
	Client    *http.Client
	UserAgent string
	Limiter   *ratelimit.Limiter
}

// Run evaluates every template against baseURL (scheme://host) and returns the
// findings for those that match.
func (e *Engine) Run(ctx context.Context, baseURL string, opts RunOptions) []models.Finding {
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	baseURL = strings.TrimRight(baseURL, "/")

	var findings []models.Finding
	for _, t := range e.templates {
		if f, ok := e.runTemplate(ctx, t, baseURL, client, opts); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

func (e *Engine) runTemplate(ctx context.Context, t *Template, baseURL string, client *http.Client, opts RunOptions) (models.Finding, bool) {
	for _, req := range t.Requests {
		method := req.Method
		if method == "" {
			method = http.MethodGet
		}
		for _, rawPath := range req.Path {
			select {
			case <-ctx.Done():
				return models.Finding{}, false
			default:
			}
			if opts.Limiter != nil {
				if err := opts.Limiter.Wait(ctx); err != nil {
					return models.Finding{}, false
				}
			}

			target := strings.ReplaceAll(rawPath, "{{BaseURL}}", baseURL)
			status, body, header, err := do(ctx, client, method, target, opts.UserAgent)
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

func do(ctx context.Context, client *http.Client, method, url, ua string) (int, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, "", "", err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))

	var hb strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			hb.WriteString(k)
			hb.WriteString(": ")
			hb.WriteString(v)
			hb.WriteString("\n")
		}
	}
	return resp.StatusCode, string(body), hb.String(), nil
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
	switch strings.ToLower(m.Type) {
	case "status":
		for _, s := range m.Status {
			if s == status {
				return true
			}
		}
		return false
	case "word":
		text := partText(m.Part, body, header)
		return reduce(m.Condition, len(m.Words), func(i int) bool {
			return strings.Contains(text, m.Words[i])
		})
	case "regex":
		text := partText(m.Part, body, header)
		return reduce(m.Condition, len(m.compiled), func(i int) bool {
			return m.compiled[i].MatchString(text)
		})
	default:
		return false
	}
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
