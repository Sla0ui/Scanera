package secrets

import (
	"strings"
	"testing"

	"github.com/Sla0ui/scanera/internal/models"
)

// Test values are assembled at runtime so the source never contains a string
// that real secret scanners would flag.
func fake(parts ...string) string { return strings.Join(parts, "") }

func hasID(findings []models.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestScanPatterns(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	b64key := strings.Repeat("AbCd", 21) + "Ef=="

	tests := []struct {
		id       string
		positive string
		negative string
	}{
		{"stripe-key", fake("sk_", "live_", strings.Repeat("a1B2", 25)), fake("sk_", "test_", strings.Repeat("a1B2", 6))},
		{"stripe-restricted-key", fake("rk_", "live_", strings.Repeat("Z9y8", 6)), fake("rk_", "test_", strings.Repeat("Z9y8", 6))},
		{"gitlab-token", fake("glpat", "-", strings.Repeat("a1B2", 5)), fake("glpat", "-short")},
		{"slack-webhook", fake("https://hooks.", "slack.com/services/", "T0000FAKE/B0000FAKE/", "XXXXfakefakefakeXXXX"), "https://hooks.slack.com/services/"},
		{"sendgrid-key", fake("SG", ".", strings.Repeat("a", 22), ".", strings.Repeat("b", 43)), fake("SG", ".short.short")},
		{"npm-token", fake("npm", "_", strings.Repeat("a1B2", 9)), fake("npm", "_", "abc123")},
		{"google-oauth-secret", fake("GOCSPX", "-", strings.Repeat("a1B2", 7)), fake("GOCSPX", "-tooShort")},
		{"shopify-token", fake("shpat", "_", strings.Repeat("0a1b", 8)), fake("shpat", "_", strings.Repeat("zzzz", 8))},
		{"digitalocean-token", fake("dop_", "v1_", hex64), fake("dop_", "v1_", hex64[:63], " ")},
		{"pypi-token", fake("pypi-", "AgEIcHlwaS5vcmc", strings.Repeat("Xy_9", 15)), fake("pypi-", "AgEIcHlwaS5vcmc", "short")},
		{"azure-storage-key", fake("DefaultEndpointsProtocol=https;AccountName=demo;Account", "Key=", b64key), fake("Account", "Key=", "tooShort")},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if f := Scan("const cfg = '"+tt.positive+"';", "https://example.com/app.js"); !hasID(f, tt.id) {
				t.Errorf("expected %s for %q, got %+v", tt.id, tt.positive, f)
			}
			if tt.negative != "" {
				if f := Scan("const cfg = '"+tt.negative+"';", "https://example.com/app.js"); hasID(f, tt.id) {
					t.Errorf("did not expect %s for %q", tt.id, tt.negative)
				}
			}
		})
	}
}

func TestScanRedactsEvidence(t *testing.T) {
	token := fake("glpat", "-", strings.Repeat("a1B2", 5))
	f := Scan(token, "https://example.com/")
	if len(f) == 0 {
		t.Fatal("expected a finding")
	}
	if strings.Contains(f[0].Evidence, token) || !strings.Contains(f[0].Evidence, "****") {
		t.Fatalf("evidence not redacted: %q", f[0].Evidence)
	}
	if f[0].Location != "https://example.com/" || f[0].Source != "secret" {
		t.Fatalf("unexpected finding metadata: %+v", f[0])
	}
}

func TestScanCleanContent(t *testing.T) {
	if f := Scan(`<html><body><p>Nothing to see here.</p></body></html>`, "x"); len(f) != 0 {
		t.Fatalf("expected no findings, got %+v", f)
	}
}
