package crawler

import "testing"

func TestExtractLinksSameHostOnly(t *testing.T) {
	body := `<a href="/a">a</a><a href="page2.html">b</a>
	<a href="https://other.com/x">ext</a><a href="https://ex.com/c">same</a>
	<script src="/js/app.js"></script><a href="mailto:x@ex.com">m</a>`
	links := extractLinks(body, "https://ex.com/dir/index.html", "ex.com")
	set := map[string]bool{}
	for _, l := range links {
		set[l] = true
	}
	if !set["https://ex.com/a"] {
		t.Errorf("expected absolute /a, got %v", links)
	}
	if !set["https://ex.com/dir/page2.html"] {
		t.Errorf("expected relative resolution, got %v", links)
	}
	if !set["https://ex.com/js/app.js"] {
		t.Errorf("expected script src, got %v", links)
	}
	for _, l := range links {
		if l == "https://other.com/x" {
			t.Errorf("must not include cross-host link")
		}
	}
}
