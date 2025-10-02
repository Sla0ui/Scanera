package analyzer

import (
	"regexp"
	"strings"
	"sync"

	"github.com/Sla0ui/scanera/internal/models"
)

var (
	linkRegex     *regexp.Regexp
	descRegex     *regexp.Regexp
	keywordsRegex *regexp.Regexp
	langRegex     *regexp.Regexp
	regexOnce     sync.Once
)

func initRegexes() {
	linkRegex = regexp.MustCompile(`<a\s+(?:[^>]*?\s+)?href=["']([^"']*)["']`)
	descRegex = regexp.MustCompile(`<meta\s+(?:[^>]*?\s+)?name=["']description["']\s+(?:[^>]*?\s+)?content=["']([^"']*)["']`)
	keywordsRegex = regexp.MustCompile(`<meta\s+(?:[^>]*?\s+)?name=["']keywords["']\s+(?:[^>]*?\s+)?content=["']([^"']*)["']`)
	langRegex = regexp.MustCompile(`lang=["']([^"']*)["']`)
}

// AnalyzePageContent performs content analysis on HTML content
func AnalyzePageContent(content string, result *models.Result) {
	regexOnce.Do(initRegexes)

	result.ContentInfo = models.ContentInfo{}

	// Word count
	result.ContentInfo.WordCount = len(strings.Fields(content))

	// Login form detection
	lowerContent := strings.ToLower(content)
	result.ContentInfo.HasLoginForm = strings.Contains(lowerContent, "password") &&
		(strings.Contains(lowerContent, "<form") ||
			strings.Contains(lowerContent, "login") ||
			strings.Contains(lowerContent, "sign in"))

	// Link analysis
	links := linkRegex.FindAllStringSubmatch(content, -1)
	result.ContentInfo.LinkCount = len(links)

	externalLinks := 0
	for _, link := range links {
		if len(link) > 1 && (strings.HasPrefix(link[1], "http://") || strings.HasPrefix(link[1], "https://")) {
			externalLinks++
		}
	}
	result.ContentInfo.ExternalLinks = externalLinks

	// Meta description
	descMatches := descRegex.FindStringSubmatch(content)
	if len(descMatches) > 1 {
		result.ContentInfo.Description = descMatches[1]
	}

	// Meta keywords
	keywordsMatches := keywordsRegex.FindStringSubmatch(content)
	if len(keywordsMatches) > 1 {
		keywords := strings.Split(keywordsMatches[1], ",")
		for i, keyword := range keywords {
			keywords[i] = strings.TrimSpace(keyword)
		}
		result.ContentInfo.Keywords = keywords
	}

	// Analytics detection
	result.ContentInfo.HasAnalytics = strings.Contains(content, "google-analytics.com") ||
		strings.Contains(content, "googletagmanager.com") ||
		strings.Contains(content, "gtag") ||
		strings.Contains(content, "analytics")

	// Parked domain detection
	result.ContentInfo.IsParked = strings.Contains(lowerContent, "domain is for sale") ||
		strings.Contains(lowerContent, "buy this domain") ||
		strings.Contains(lowerContent, "parked domain") ||
		strings.Contains(lowerContent, "domain parking")

	// Language detection
	if strings.Contains(content, "lang=\"") {
		langMatches := langRegex.FindStringSubmatch(content)
		if len(langMatches) > 1 {
			result.ContentInfo.PageLanguage = langMatches[1]
		}
	}

	// Social media profile detection
	socialPatterns := []string{
		"facebook.com", "twitter.com", "instagram.com", "linkedin.com",
		"youtube.com", "pinterest.com", "github.com", "tiktok.com",
	}

	var socialProfiles []string
	for _, pattern := range socialPatterns {
		if strings.Contains(content, pattern) {
			socialProfiles = append(socialProfiles, pattern)
		}
	}
	result.ContentInfo.SocialProfiles = socialProfiles
}
