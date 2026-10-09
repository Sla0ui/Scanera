package scope

import "testing"

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
	s := &Scope{allowed: []string{"*.test.com"}}
	if !s.InScope("a.test.com") || s.InScope("a.other.com") {
		t.Error("scope matching failed")
	}
}
