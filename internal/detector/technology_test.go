package detector

import (
	"testing"

	"github.com/Sla0ui/scanera/internal/models"
)

func TestDetectTechnologies(t *testing.T) {
	tests := []struct {
		name            string
		content         string
		headers         map[string][]string
		expectedTechs   []string
		unexpectedTechs []string
	}{
		{
			name:          "WordPress detection",
			content:       `<script src="/wp-content/themes/mytheme/script.js"></script>`,
			headers:       map[string][]string{},
			expectedTechs: []string{"WordPress"},
		},
		{
			name:          "jQuery detection",
			content:       `<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>`,
			headers:       map[string][]string{},
			expectedTechs: []string{"jQuery"},
		},
		{
			name:          "Multiple technologies",
			content:       `<script src="jquery.min.js"></script><script src="bootstrap.min.js"></script>`,
			headers:       map[string][]string{},
			expectedTechs: []string{"jQuery", "Bootstrap"},
		},
		{
			name:    "Server from headers",
			content: "",
			headers: map[string][]string{
				"Server": {"nginx/1.18.0"},
			},
			expectedTechs: []string{"Nginx"},
		},
		{
			name:    "X-Powered-By header",
			content: "",
			headers: map[string][]string{
				"X-Powered-By": {"PHP/7.4.3"},
			},
			expectedTechs: []string{"PHP"},
		},
		{
			name:            "No technologies",
			content:         `<html><body>Plain HTML</body></html>`,
			headers:         map[string][]string{},
			unexpectedTechs: []string{"WordPress", "jQuery", "React"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.Result{}
			DetectTechnologies(tt.content, tt.headers, result)

			// Check expected technologies are present
			for _, expected := range tt.expectedTechs {
				found := false
				for _, tech := range result.Technologies {
					if tech == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected technology %s not found in %v", expected, result.Technologies)
				}
			}

			// Check unexpected technologies are not present
			for _, unexpected := range tt.unexpectedTechs {
				for _, tech := range result.Technologies {
					if tech == unexpected {
						t.Errorf("Unexpected technology %s found in %v", unexpected, result.Technologies)
					}
				}
			}
		})
	}
}

func TestGetTechnologyCategories(t *testing.T) {
	technologies := []string{"WordPress", "jQuery", "Nginx", "Google Analytics"}

	categories := GetTechnologyCategories(technologies)

	// Check CMS category
	if len(categories["CMS"]) != 1 || categories["CMS"][0] != "WordPress" {
		t.Errorf("Expected WordPress in CMS category, got %v", categories["CMS"])
	}

	// Check JavaScript category
	if len(categories["JavaScript"]) != 1 || categories["JavaScript"][0] != "jQuery" {
		t.Errorf("Expected jQuery in JavaScript category, got %v", categories["JavaScript"])
	}

	// Check Server category
	if len(categories["Server"]) != 1 || categories["Server"][0] != "Nginx" {
		t.Errorf("Expected Nginx in Server category, got %v", categories["Server"])
	}

	// Check Analytics category
	if len(categories["Analytics"]) != 1 || categories["Analytics"][0] != "Google Analytics" {
		t.Errorf("Expected Google Analytics in Analytics category, got %v", categories["Analytics"])
	}
}

func TestDetectTechnologiesNoFalsePositives(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		headers    map[string][]string
		unexpected string
	}{
		{
			name:       "X-UA-Compatible is not Google Analytics",
			content:    `<meta http-equiv="X-UA-Compatible" content="IE=edge"><p>G-force and UA-style text</p>`,
			unexpected: "Google Analytics",
		},
		{
			name:       "CSS padding-left is not Angular",
			content:    `<style>.x{padding-left:4px}.loading-spinner{margin-left:0}</style>`,
			unexpected: "Angular",
		},
		{
			name:       "prose about reactions is not React",
			content:    `<p>The reaction to our reactive design was positive.</p>`,
			unexpected: "React",
		},
		{
			name:       "preact is not React",
			content:    `<script src="/js/preact.min.js"></script>`,
			unexpected: "React",
		},
		{
			name:       "mentioning bootstrap in prose is not Bootstrap",
			content:    `<p>We bootstrap new projects in a day.</p>`,
			unexpected: "Bootstrap",
		},
		{
			name:       "cdnjs link is not Cloudflare hosting",
			content:    `<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>`,
			unexpected: "Cloudflare",
		},
		{
			name:       "CSP allowlist is not usage",
			headers:    map[string][]string{"Content-Security-Policy": {"script-src https://js.stripe.com https://www.google-analytics.com/analytics.js"}},
			unexpected: "Stripe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.Result{}
			DetectTechnologies(tt.content, tt.headers, result)
			for _, tech := range result.Technologies {
				if tech == tt.unexpected {
					t.Fatalf("unexpected %s in %v", tt.unexpected, result.Technologies)
				}
			}
		})
	}
}

func TestDetectTechnologiesRealSignals(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		headers  map[string][]string
		expected string
	}{
		{"GA4 gtag", `<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABCDEF1234"></script>`, nil, "Google Analytics"},
		{"Universal Analytics id", `ga('create', 'UA-12345678-1', 'auto');`, nil, "Google Analytics"},
		{"Angular app", `<app-root ng-version="17.0.0"></app-root>`, nil, "Angular"},
		{"React root", `<div id="root" data-reactroot=""></div>`, nil, "React"},
		{"Next.js data", `<script id="__NEXT_DATA__" type="application/json">{}</script>`, nil, "Next.js"},
		{"Vue scoped styles", `<div data-v-1a2b3c4d class="card"></div>`, nil, "Vue.js"},
		{"Cloudflare ray header", "", map[string][]string{"Cf-Ray": {"8a1b2c3d4e5f-AMS"}}, "Cloudflare"},
		{"Drupal generator header", "", map[string][]string{"X-Generator": {"Drupal 10 (https://www.drupal.org)"}}, "Drupal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.Result{}
			DetectTechnologies(tt.content, tt.headers, result)
			for _, tech := range result.Technologies {
				if tech == tt.expected {
					return
				}
			}
			t.Fatalf("expected %s in %v", tt.expected, result.Technologies)
		})
	}
}

func TestDetectTechnologiesSorted(t *testing.T) {
	content := `<script src="/wp-content/x.js"></script><script src="jquery.min.js"></script><link href="bootstrap.min.css">`
	for i := 0; i < 5; i++ {
		result := &models.Result{}
		DetectTechnologies(content, map[string][]string{"Server": {"nginx"}}, result)
		for j := 1; j < len(result.Technologies); j++ {
			if result.Technologies[j-1] > result.Technologies[j] {
				t.Fatalf("technologies not sorted: %v", result.Technologies)
			}
		}
	}
}
