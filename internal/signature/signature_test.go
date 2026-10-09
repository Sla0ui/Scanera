package signature

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoadBuiltins(t *testing.T) {
	e, err := Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(e.Templates()) == 0 {
		t.Fatal("expected built-in templates to load")
	}
	for _, tpl := range e.Templates() {
		if tpl.ID == "" || tpl.Info.Severity == "" {
			t.Errorf("template %q missing id or severity", tpl.ID)
		}
	}
}

func TestRunMatchesDirectoryListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html><head><title>Index of /</title></head><body>Index of /</body></html>"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	e, err := Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings := e.Run(ctx, srv.URL, RunOptions{Client: srv.Client(), UserAgent: "test"})

	var got bool
	for _, f := range findings {
		if f.ID == "directory-listing" {
			got = true
		}
	}
	if !got {
		t.Fatalf("expected directory-listing finding, got %+v", findings)
	}
}

func TestMatchersConditionAndDefault(t *testing.T) {
	// status matches but word does not -> with default "and", no match.
	req := Request{
		Matchers: []Matcher{
			{Type: "status", Status: []int{200}},
			{Type: "word", Part: "body", Words: []string{"nope"}},
		},
	}
	if matchRequest(req, 200, "this body lacks the word", "") {
		t.Fatal("expected no match when one matcher fails under and-condition")
	}
}

func TestRunSendsHeadersAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			if o := r.Header.Get("Origin"); o != "" {
				w.Header().Set("Access-Control-Allow-Origin", o)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			_, _ = w.Write([]byte("home"))
		case "/graphql":
			b, _ := io.ReadAll(r.Body)
			if r.Method == http.MethodPost && strings.Contains(string(b), "__schema") {
				_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
				return
			}
			w.WriteHeader(400)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	e, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := map[string]bool{}
	for _, f := range e.Run(ctx, srv.URL, RunOptions{Client: srv.Client()}) {
		got[f.ID] = true
	}
	if !got["cors-reflected-origin"] || !got["graphql-introspection"] {
		t.Fatalf("expected cors and graphql findings, got %v", got)
	}
	if got["directory-listing"] {
		t.Fatal("directory-listing should not match a plain page")
	}
}

func TestPlaceholdersAndNegativeMatcher(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Header.Get("X-Target")
		_, _ = w.Write([]byte("maintenance page"))
	}))
	defer srv.Close()

	tpl, err := parse([]byte(`
id: not-maintenance
info:
  severity: info
requests:
  - path: ["{{BaseURL}}/x"]
    headers:
      X-Target: "{{Host}}|{{Hostname}}|{{Scheme}}"
    matchers:
      - type: word
        words: ["MAINTENANCE"]
        case-insensitive: true
        negative: true
`))
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{templates: []*Template{tpl}}
	if fs := e.Run(context.Background(), srv.URL, RunOptions{Client: srv.Client()}); len(fs) != 0 {
		t.Fatalf("negative matcher should suppress the finding, got %+v", fs)
	}
	u, _ := url.Parse(srv.URL)
	if want := u.Hostname() + "|" + u.Host + "|http"; gotHost != want {
		t.Errorf("placeholders expanded to %q, want %q", gotHost, want)
	}
}

func TestParseRejectsBrokenTemplates(t *testing.T) {
	cases := map[string]string{
		"unknown key":     "id: a\nrequests:\n  - path: [x]\n    matcher: []\n",
		"no requests":     "id: a\n",
		"bad severity":    "id: a\ninfo: {severity: hgih}\nrequests:\n  - path: [x]\n    matchers: [{type: status, status: [200]}]\n",
		"unknown type":    "id: a\nrequests:\n  - path: [x]\n    matchers: [{type: words, words: [y]}]\n",
		"empty word list": "id: a\nrequests:\n  - path: [x]\n    matchers: [{type: word}]\n",
		"bad regex":       "id: a\nrequests:\n  - path: [x]\n    matchers: [{type: regex, regex: ['(']}]\n",
		"bad part":        "id: a\nrequests:\n  - path: [x]\n    matchers: [{type: word, part: cookie, words: [y]}]\n",
		"missing id":      "requests:\n  - path: [x]\n    matchers: [{type: status, status: [200]}]\n",
		"no path":         "id: a\nrequests:\n  - matchers: [{type: status, status: [200]}]\n",
		"bad mcondition":  "id: a\nrequests:\n  - path: [x]\n    matchers-condition: xor\n    matchers: [{type: status, status: [200]}]\n",
	}
	for name, src := range cases {
		if _, err := parse([]byte(src)); err == nil {
			t.Errorf("%s: expected parse error", name)
		}
	}
}

func TestLoadUserDir(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing templates dir should be an error")
	}

	dir := t.TempDir()
	dup := "id: directory-listing\nrequests:\n  - path: [x]\n    matchers: [{type: status, status: [200]}]\n"
	if err := os.WriteFile(filepath.Join(dir, "dup.yaml"), []byte(dup), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("duplicate template id should be an error")
	}

	if _, err := Load("../../examples/templates"); err != nil {
		t.Errorf("example templates should load: %v", err)
	}
}

func TestRunAllowBlocksOtherHosts(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tpl, err := parse([]byte("id: abs\nrequests:\n  - path: [\"" + srv.URL + "/x\"]\n    matchers: [{type: status, status: [200]}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{templates: []*Template{tpl}}
	fs := e.Run(context.Background(), "http://in-scope.example", RunOptions{
		Client: srv.Client(),
		Allow:  func(host string) bool { return host == "in-scope.example" },
	})
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 || len(fs) != 0 {
		t.Fatalf("template reached a host Allow rejected (hits=%d findings=%d)", hits, len(fs))
	}
}
