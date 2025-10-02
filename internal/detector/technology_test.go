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
			name:    "jQuery detection",
			content: `<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>`,
			headers: map[string][]string{},
			expectedTechs: []string{"jQuery"},
		},
		{
			name:    "Multiple technologies",
			content: `<script src="jquery.min.js"></script><script src="bootstrap.min.js"></script>`,
			headers: map[string][]string{},
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
