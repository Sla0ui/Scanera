package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchHost(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "sub.example.com", false},
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "evil.com", false},
		{"*.example.com", "badexample.com", false},
	}
	for _, c := range cases {
		if got := matchHost(c.pattern, c.host); got != c.want {
			t.Errorf("matchHost(%q,%q)=%v want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestInScopeAndAuthorized(t *testing.T) {
	var nilScope *Scope
	if nilScope.InScope("x") {
		t.Error("nil scope should deny")
	}
	if !Authorized().InScope("anything.tld") {
		t.Error("authorized scope should allow all")
	}
	s, err := FromEntries("*.test.com")
	if err != nil {
		t.Fatal(err)
	}
	if !s.InScope("a.test.com") || s.InScope("a.other.com") {
		t.Error("scope matching failed")
	}
}

func TestInScopeEntries(t *testing.T) {
	s, err := FromEntries(
		"# engagement scope",
		"*.example.com",
		"https://Portal.Partner.org:8443/login",
		"203.0.113.0/24",
		"198.51.100.7",
		"2001:db8::/32",
		"!dev.example.com",
		"!203.0.113.13",
	)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"WWW.Example.com.", true},
		{"api.example.com:8080", true},
		{"dev.example.com", false},
		{"x.dev.example.com", true}, // exclusion is exact, not a wildcard
		{"portal.partner.org", true},
		{"partner.org", false},
		{"203.0.113.1", true},
		{"203.0.113.13", false},
		{"203.0.114.1", false},
		{"198.51.100.7:22", true},
		{"198.51.100.8", false},
		{"[2001:db8::1]:443", true},
		{"2001:db9::1", false},
		{"", false},
	}
	for _, c := range cases {
		if got := s.InScope(c.host); got != c.want {
			t.Errorf("InScope(%q)=%v want %v", c.host, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range [][]string{
		{"# only comments"},
		{"!example.com"}, // exclusions alone allow nothing
		{"*."},
		{"a.*.example.com"},
	} {
		if _, err := FromEntries(bad...); err == nil {
			t.Errorf("FromEntries(%q) should fail", bad)
		}
	}
}

func TestAuditLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	s, err := FromEntries("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AttachAudit(path); err != nil {
		t.Fatal(err)
	}
	s.Log("probe", "example.com", "https://example.com")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s.Log("after-close", "example.com", "") // must not panic
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); !strings.Contains(got, "audit-start") || !strings.Contains(got, "\tprobe\texample.com\t") {
		t.Errorf("unexpected audit log:\n%s", got)
	}
}
