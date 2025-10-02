package analyzer

import (
	"strings"
	"testing"

	"github.com/Sla0ui/scanera/internal/models"
)

func TestAnalyzePageContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		validate func(*testing.T, *models.Result)
	}{
		{
			name:    "Word count",
			content: "This is a test page with some words",
			validate: func(t *testing.T, r *models.Result) {
				if r.ContentInfo.WordCount != 8 {
					t.Errorf("Expected 8 words, got %d", r.ContentInfo.WordCount)
				}
			},
		},
		{
			name:    "Login form detection",
			content: `<form><input type="password" name="pass"><input type="text" name="login"></form>`,
			validate: func(t *testing.T, r *models.Result) {
				if !r.ContentInfo.HasLoginForm {
					t.Error("Expected login form to be detected")
				}
			},
		},
		{
			name:    "No login form",
			content: `<form><input type="text" name="search"></form>`,
			validate: func(t *testing.T, r *models.Result) {
				if r.ContentInfo.HasLoginForm {
					t.Error("Expected no login form")
				}
			},
		},
		{
			name:    "Link count",
			content: `<a href="/page1">Link 1</a><a href="/page2">Link 2</a><a href="https://external.com">External</a>`,
			validate: func(t *testing.T, r *models.Result) {
				if r.ContentInfo.LinkCount != 3 {
					t.Errorf("Expected 3 links, got %d", r.ContentInfo.LinkCount)
				}
				if r.ContentInfo.ExternalLinks != 1 {
					t.Errorf("Expected 1 external link, got %d", r.ContentInfo.ExternalLinks)
				}
			},
		},
		{
			name:    "Meta description",
			content: `<meta name="description" content="This is a test description">`,
			validate: func(t *testing.T, r *models.Result) {
				expected := "This is a test description"
				if r.ContentInfo.Description != expected {
					t.Errorf("Expected description %q, got %q", expected, r.ContentInfo.Description)
				}
			},
		},
		{
			name:    "Meta keywords",
			content: `<meta name="keywords" content="test, keywords, seo">`,
			validate: func(t *testing.T, r *models.Result) {
				if len(r.ContentInfo.Keywords) != 3 {
					t.Errorf("Expected 3 keywords, got %d", len(r.ContentInfo.Keywords))
				}
			},
		},
		{
			name:    "Analytics detection",
			content: `<script src="https://www.google-analytics.com/analytics.js"></script>`,
			validate: func(t *testing.T, r *models.Result) {
				if !r.ContentInfo.HasAnalytics {
					t.Error("Expected analytics to be detected")
				}
			},
		},
		{
			name:    "Parked domain detection",
			content: `This domain is for sale. Buy this domain now!`,
			validate: func(t *testing.T, r *models.Result) {
				if !r.ContentInfo.IsParked {
					t.Error("Expected parked domain to be detected")
				}
			},
		},
		{
			name:    "Language detection",
			content: `<html lang="en-US">`,
			validate: func(t *testing.T, r *models.Result) {
				if r.ContentInfo.PageLanguage != "en-US" {
					t.Errorf("Expected language en-US, got %s", r.ContentInfo.PageLanguage)
				}
			},
		},
		{
			name:    "Social profiles",
			content: `<a href="https://facebook.com/page">Facebook</a><a href="https://twitter.com/user">Twitter</a>`,
			validate: func(t *testing.T, r *models.Result) {
				if len(r.ContentInfo.SocialProfiles) < 2 {
					t.Errorf("Expected at least 2 social profiles, got %d", len(r.ContentInfo.SocialProfiles))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.Result{}
			AnalyzePageContent(tt.content, result)
			tt.validate(t, result)
		})
	}
}

func TestAnalyzePageContent_NoRegexErrors(t *testing.T) {
	// Test with malformed HTML to ensure regex doesn't panic
	malformed := []string{
		`<a href="`,
		`<meta name="description`,
		`lang="`,
		strings.Repeat("a", 100000), // Very long content
	}

	for i, content := range malformed {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			result := &models.Result{}
			// Should not panic
			AnalyzePageContent(content, result)
		})
	}
}
