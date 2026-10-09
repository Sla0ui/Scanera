package posture

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func respFor(rawURL string, h http.Header) *http.Response {
	u, _ := url.Parse(rawURL)
	return &http.Response{Header: h, Request: &http.Request{URL: u}}
}

func idSet(t *testing.T, resp *http.Response) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range Headers(resp) {
		out[f.ID] = f.Evidence
	}
	return out
}

func TestHeadersMissingOnHTML(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Server", "nginx/1.18.0")
	got := idSet(t, respFor("https://example.com/", h))
	for _, id := range []string{"missing-hsts", "missing-csp", "missing-clickjacking-protection", "missing-x-content-type-options", "version-disclosure"} {
		if _, ok := got[id]; !ok {
			t.Errorf("expected %s, got %v", id, got)
		}
	}
	if got["version-disclosure"] != "Server: nginx/1.18.0" {
		t.Errorf("unexpected disclosure evidence %q", got["version-disclosure"])
	}
}

func TestHeadersHardenedSite(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Server", "nginx")
	if got := idSet(t, respFor("https://example.com/", h)); len(got) != 0 {
		t.Errorf("hardened site should have no findings, got %v", got)
	}
}

func TestHeadersSkipsBrowserHeadersOnAPIsAndHSTSOnHTTP(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	if got := idSet(t, respFor("https://api.example.com/", h)); len(got) != 0 {
		t.Errorf("JSON responses shouldn't need browser headers, got %v", got)
	}
	h.Set("Content-Type", "text/html")
	if _, ok := idSet(t, respFor("http://example.com/", h))["missing-hsts"]; ok {
		t.Error("HSTS is meaningless on a plain-HTTP response")
	}
}

func TestCookieFlags(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Add("Set-Cookie", "PHPSESSID=abc; Path=/")
	h.Add("Set-Cookie", "theme=dark; Path=/; Secure")
	h.Add("Set-Cookie", "csrftoken=x; Path=/; Secure")
	h.Add("Set-Cookie", "auth=y; Path=/; Secure; HttpOnly")
	h.Add("Set-Cookie", "old=; Max-Age=0")
	got := idSet(t, respFor("https://example.com/", h))
	if got["cookie-without-secure"] != "PHPSESSID" {
		t.Errorf("Secure evidence = %q", got["cookie-without-secure"])
	}
	if got["session-cookie-without-httponly"] != "PHPSESSID" {
		t.Errorf("HttpOnly evidence = %q", got["session-cookie-without-httponly"])
	}
}

func TestInspectTLSAgainstTestServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	now := time.Now()
	d, ok := InspectTLS(resp.TLS, "127.0.0.1", now)
	if !ok {
		t.Fatal("expected TLS details")
	}
	if d.Valid {
		t.Error("httptest certificate isn't in the system roots and must not verify")
	}
	if d.Version == "" || d.NotAfter.IsZero() {
		t.Errorf("missing details: %+v", d)
	}
	found := false
	for _, f := range TLSFindings(d, srv.URL, now) {
		if f.ID == "tls-cert-invalid" {
			found = true
		}
	}
	if !found {
		t.Error("expected tls-cert-invalid for an untrusted certificate")
	}
}

func TestTLSFindingsExpiryAndVersion(t *testing.T) {
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		d    TLSDetails
		want []string
	}{
		{"healthy", TLSDetails{Version: "TLS 1.3", NotAfter: now.AddDate(0, 6, 0), Valid: true}, nil},
		{"expiring", TLSDetails{Version: "TLS 1.2", NotAfter: now.AddDate(0, 0, 10), Valid: true}, []string{"tls-cert-expiring"}},
		{"expired", TLSDetails{Version: "TLS 1.2", NotAfter: now.AddDate(0, 0, -1),
			VerifyErr: x509.CertificateInvalidError{Reason: x509.Expired}}, []string{"tls-cert-expired"}},
		{"legacy", TLSDetails{Version: "TLS 1.0", NotAfter: now.AddDate(1, 0, 0), Valid: true}, []string{"tls-legacy-version"}},
	}
	for _, c := range cases {
		var got []string
		for _, f := range TLSFindings(c.d, "https://example.com", now) {
			got = append(got, f.ID)
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestCertErrorFinding(t *testing.T) {
	wrapped := fmt.Errorf("Get https://x: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})
	if _, ok := CertErrorFinding(wrapped, "https://x"); !ok {
		t.Error("certificate verification errors should produce a finding")
	}
	if _, ok := CertErrorFinding(errors.New("connection refused"), "https://x"); ok {
		t.Error("network errors are not certificate findings")
	}
}
