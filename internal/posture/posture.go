// Package posture derives passive security findings from responses the scanner
// already has: security headers, cookie flags, and the negotiated TLS session.
// Nothing here sends extra requests, so it needs no authorization scope.
package posture

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
)

// expiryWarning is how far ahead an expiring certificate is reported.
const expiryWarning = 30 * 24 * time.Hour

var versionInHeader = regexp.MustCompile(`\d+\.\d+`)

// Headers reports missing security headers, version disclosure and weak cookie
// flags on the final response of a page load.
func Headers(resp *http.Response) []models.Finding {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return nil
	}
	loc := resp.Request.URL.String()
	https := resp.Request.URL.Scheme == "https"
	h := resp.Header
	var out []models.Finding

	add := func(id, title string, sev models.Severity, desc, evidence string) {
		out = append(out, models.Finding{
			ID: id, Title: title, Severity: sev, Source: "headers",
			Description: desc, Evidence: evidence, Location: loc,
			Tags: []string{"headers", "misconfig"},
		})
	}

	// Browser-enforced headers only matter for documents a browser renders.
	if isHTML(h.Get("Content-Type")) {
		if https && h.Get("Strict-Transport-Security") == "" {
			add("missing-hsts", "Missing Strict-Transport-Security header", models.SeverityLow,
				"Without HSTS a network attacker can downgrade first visits to plain HTTP.", "")
		}
		csp := h.Get("Content-Security-Policy")
		if csp == "" {
			add("missing-csp", "Missing Content-Security-Policy header", models.SeverityLow,
				"No CSP is set, so injected scripts run with no second line of defence.", "")
		}
		if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			add("missing-clickjacking-protection", "No clickjacking protection", models.SeverityLow,
				"Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the page can be framed by other sites.", "")
		}
		if !strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
			add("missing-x-content-type-options", "Missing X-Content-Type-Options: nosniff", models.SeverityInfo,
				"Browsers may MIME-sniff responses into an executable type.", "")
		}
	}

	var disclosed []string
	for _, name := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if v := h.Get(name); v != "" && versionInHeader.MatchString(v) {
			disclosed = append(disclosed, name+": "+v)
		}
	}
	if len(disclosed) > 0 {
		add("version-disclosure", "Software version disclosed in headers", models.SeverityInfo,
			"Exact versions make it easier to match the server against known vulnerabilities.",
			strings.Join(disclosed, "; "))
	}

	out = append(out, cookieFindings(resp.Cookies(), https, loc)...)
	return out
}

func isHTML(contentType string) bool {
	ct := strings.ToLower(contentType)
	return ct == "" || strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

var sessionCookie = regexp.MustCompile(`(?i)sess|sid$|^sid|auth|token|jwt|login|remember`)

func cookieFindings(cookies []*http.Cookie, https bool, loc string) []models.Finding {
	var noSecure, noHTTPOnly []string
	for _, c := range cookies {
		if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())) {
			continue // a deletion, not a live cookie
		}
		if https && !c.Secure {
			noSecure = append(noSecure, c.Name)
		}
		// Plenty of cookies are meant to be script-readable (CSRF tokens,
		// preferences); only flag ones that look like session credentials.
		if !c.HttpOnly && sessionCookie.MatchString(c.Name) && !strings.Contains(strings.ToLower(c.Name), "csrf") && !strings.Contains(strings.ToLower(c.Name), "xsrf") {
			noHTTPOnly = append(noHTTPOnly, c.Name)
		}
	}
	var out []models.Finding
	if len(noSecure) > 0 {
		out = append(out, models.Finding{
			ID: "cookie-without-secure", Title: "Cookie set without the Secure flag", Severity: models.SeverityLow,
			Source: "cookie", Location: loc, Evidence: joinSorted(noSecure),
			Description: "These cookies would also be sent over plain HTTP if the site is ever reached that way.",
			Tags:        []string{"cookies"},
		})
	}
	if len(noHTTPOnly) > 0 {
		out = append(out, models.Finding{
			ID: "session-cookie-without-httponly", Title: "Session cookie readable by JavaScript", Severity: models.SeverityLow,
			Source: "cookie", Location: loc, Evidence: joinSorted(noHTTPOnly),
			Description: "Session-like cookies without HttpOnly can be stolen by any XSS on the site.",
			Tags:        []string{"cookies"},
		})
	}
	return out
}

func joinSorted(names []string) string {
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// TLSDetails summarizes a negotiated TLS session.
type TLSDetails struct {
	Version   string
	Issuer    string
	Subject   string
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
	Valid     bool  // chain verifies against system roots for host
	VerifyErr error // why it doesn't, when Valid is false
}

// InspectTLS reads certificate details from a connection state and checks the
// chain against the system roots for host.
func InspectTLS(state *tls.ConnectionState, host string, now time.Time) (TLSDetails, bool) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return TLSDetails{}, false
	}
	leaf := state.PeerCertificates[0]
	d := TLSDetails{
		Version:   tls.VersionName(state.Version),
		Issuer:    nonEmpty(leaf.Issuer.CommonName, leaf.Issuer.String()),
		Subject:   nonEmpty(leaf.Subject.CommonName, leaf.Subject.String()),
		DNSNames:  leaf.DNSNames,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, d.VerifyErr = leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter, CurrentTime: now})
	d.Valid = d.VerifyErr == nil
	return d, true
}

// TLSFindings turns TLS details into findings: expired or soon-expiring
// certificates, untrusted or mismatched certificates, and legacy protocol
// versions.
func TLSFindings(d TLSDetails, location string, now time.Time) []models.Finding {
	var out []models.Finding
	add := func(id, title string, sev models.Severity, desc, evidence string) {
		out = append(out, models.Finding{
			ID: id, Title: title, Severity: sev, Source: "tls",
			Description: desc, Evidence: evidence, Location: location,
			Tags: []string{"tls"},
		})
	}

	switch {
	case now.After(d.NotAfter):
		add("tls-cert-expired", "TLS certificate has expired", models.SeverityHigh,
			"Browsers reject the certificate and users get a full-page warning.",
			"expired "+d.NotAfter.UTC().Format("2006-01-02"))
	case d.NotAfter.Sub(now) < expiryWarning:
		days := int(d.NotAfter.Sub(now).Hours() / 24)
		add("tls-cert-expiring", "TLS certificate expires soon", models.SeverityLow,
			"Renew the certificate before it lapses.",
			fmt.Sprintf("expires %s (%d days)", d.NotAfter.UTC().Format("2006-01-02"), days))
	}

	if !d.Valid && d.VerifyErr != nil && !isExpiryError(d.VerifyErr) {
		add("tls-cert-invalid", "TLS certificate is not trusted for this host", models.SeverityMedium,
			"The certificate chain doesn't verify for this hostname (self-signed, unknown issuer or name mismatch).",
			d.VerifyErr.Error())
	}

	if d.Version == "TLS 1.0" || d.Version == "TLS 1.1" || d.Version == "SSLv3" {
		add("tls-legacy-version", "Legacy TLS version negotiated", models.SeverityMedium,
			"The server agreed to a deprecated protocol version even though a modern client offered TLS 1.2+.",
			d.Version)
	}
	return out
}

// CertErrorFinding reports a certificate failure that made an HTTPS request
// fail outright (TLS verification on), so it isn't lost when the scan falls
// back to plain HTTP.
func CertErrorFinding(err error, location string) (models.Finding, bool) {
	var (
		verr     *tls.CertificateVerificationError
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
	)
	if !errors.As(err, &verr) && !errors.As(err, &unknown) && !errors.As(err, &hostname) && !errors.As(err, &invalid) {
		return models.Finding{}, false
	}
	return models.Finding{
		ID: "tls-cert-invalid", Title: "TLS certificate is not trusted for this host", Severity: models.SeverityMedium,
		Source: "tls", Location: location, Evidence: err.Error(), Tags: []string{"tls"},
		Description: "The HTTPS request failed certificate verification.",
	}, true
}

func isExpiryError(err error) bool {
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid) && invalid.Reason == x509.Expired
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
