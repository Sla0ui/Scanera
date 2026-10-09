package signature

import (
	"context"
	"net/http"
	"net/http/httptest"
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
