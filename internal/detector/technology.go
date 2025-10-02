package detector

import (
	"regexp"
	"strings"
	"sync"

	"github.com/Sla0ui/scanera/internal/models"
)

// Pre-compiled regex patterns for performance
var (
	techPatterns     map[string]*regexp.Regexp
	techPatternsOnce sync.Once
)

func initTechPatterns() {
	techPatterns = make(map[string]*regexp.Regexp)

	patterns := map[string]string{
		"WordPress":          `wp-content|wp-includes|/wp-json/|wordpress`,
		"Joomla":             `joomla|J!(jQuery|Framework)`,
		"Drupal":             `Drupal|drupal|sites/all|sites/default`,
		"Magento":            `Mage\.Cookies|Magento`,
		"Shopify":            `cdn\.shopify\.com|shopify\.com|Shopify\.theme`,
		"WooCommerce":        `woocommerce|WooCommerce`,
		"jQuery":             `jquery`,
		"React":              `react|reactjs|_reactRootContainer`,
		"Vue.js":             `vue|__vue__`,
		"Angular":            `ng-|angular|AngularJS|angular\.js`,
		"Bootstrap":          `bootstrap`,
		"Tailwind CSS":       `tailwindcss|tailwind\.css`,
		"Font Awesome":       `font-awesome|fontawesome`,
		"Google Analytics":   `google-analytics|gtag|UA-|G-`,
		"Google Tag Manager": `googletagmanager`,
		"Cloudflare":         `cloudflare`,
		"PHP":                `X-Powered-By: PHP`,
		"ASP.NET":            `ASP\.NET|__VIEWSTATE|__EVENTTARGET`,
		"Google Fonts":       `fonts\.googleapis\.com`,
		"Google Maps":        `maps\.google\.com|maps\.googleapis\.com`,
		"Google reCAPTCHA":   `recaptcha`,
		"Modernizr":          `modernizr`,
		"Moment.js":          `moment\.js|moment\.min\.js`,
		"Lodash":             `lodash|_\.min\.js|_\.debounce|_\.throttle`,
		"Axios":              `axios`,
		"Chart.js":           `chart\.js|Chart\.min\.js`,
		"D3.js":              `d3\.js|d3\.min\.js`,
		"Leaflet":            `leaflet\.js|leaflet\.css`,
		"Stripe":             `stripe\.com|Stripe\.setPublishableKey`,
		"PayPal":             `paypal\.com|paypalobjects\.com`,
		"Hotjar":             `hotjar\.com|hjSetting`,
		"Intercom":           `intercom\.io|intercomSettings`,
		"Drift":              `drift\.com|driftt\.com`,
	}

	for tech, pattern := range patterns {
		techPatterns[tech] = regexp.MustCompile(pattern)
	}
}

// DetectTechnologies identifies technologies used by a website
func DetectTechnologies(content string, headers map[string][]string, result *models.Result) {
	techPatternsOnce.Do(initTechPatterns)

	var technologies []string
	seen := make(map[string]bool)

	// Check content
	for tech, pattern := range techPatterns {
		if pattern.MatchString(content) {
			if !seen[tech] {
				technologies = append(technologies, tech)
				seen[tech] = true
			}
		}
	}

	// Check headers
	for tech, pattern := range techPatterns {
		for header, values := range headers {
			for _, value := range values {
				headerLine := header + ": " + value
				if pattern.MatchString(headerLine) {
					if !seen[tech] {
						technologies = append(technologies, tech)
						seen[tech] = true
					}
				}
			}
		}
	}

	// Server detection from headers
	if server, ok := headers["Server"]; ok && len(server) > 0 {
		serverValue := strings.ToLower(server[0])

		serverTechs := map[string]string{
			"Apache":     "apache",
			"Nginx":      "nginx",
			"IIS":        "microsoft-iis",
			"Cloudflare": "cloudflare",
			"LiteSpeed":  "litespeed",
		}

		for tech, keyword := range serverTechs {
			if strings.Contains(serverValue, keyword) && !seen[tech] {
				technologies = append(technologies, tech)
				seen[tech] = true
			}
		}
	}

	// X-Powered-By header
	if powered, ok := headers["X-Powered-By"]; ok && len(powered) > 0 {
		poweredValue := strings.ToLower(powered[0])

		poweredTechs := map[string]string{
			"PHP":        "php",
			"ASP.NET":    "asp.net",
			"Express.js": "express",
		}

		for tech, keyword := range poweredTechs {
			if strings.Contains(poweredValue, keyword) && !seen[tech] {
				technologies = append(technologies, tech)
				seen[tech] = true
			}
		}
	}

	result.Technologies = technologies
}

// GetTechnologyCategories categorizes detected technologies
func GetTechnologyCategories(technologies []string) map[string][]string {
	categories := map[string][]string{
		"CMS":           {},
		"JavaScript":    {},
		"CSS Framework": {},
		"Server":        {},
		"Analytics":     {},
		"Payment":       {},
		"Security":      {},
		"Framework":     {},
		"Programming":   {},
		"Miscellaneous": {},
	}

	techCategories := map[string]string{
		"WordPress":          "CMS",
		"Joomla":             "CMS",
		"Drupal":             "CMS",
		"Magento":            "CMS",
		"Shopify":            "CMS",
		"WooCommerce":        "CMS",
		"jQuery":             "JavaScript",
		"React":              "JavaScript",
		"Vue.js":             "JavaScript",
		"Angular":            "JavaScript",
		"Modernizr":          "JavaScript",
		"Moment.js":          "JavaScript",
		"Lodash":             "JavaScript",
		"Axios":              "JavaScript",
		"Chart.js":           "JavaScript",
		"D3.js":              "JavaScript",
		"Bootstrap":          "CSS Framework",
		"Tailwind CSS":       "CSS Framework",
		"Font Awesome":       "CSS Framework",
		"Leaflet":            "CSS Framework",
		"Apache":             "Server",
		"Nginx":              "Server",
		"IIS":                "Server",
		"LiteSpeed":          "Server",
		"Cloudflare":         "Server",
		"Google Analytics":   "Analytics",
		"Google Tag Manager": "Analytics",
		"Hotjar":             "Analytics",
		"Intercom":           "Analytics",
		"Drift":              "Analytics",
		"Stripe":             "Payment",
		"PayPal":             "Payment",
		"Google reCAPTCHA":   "Security",
		"Express.js":         "Framework",
		"ASP.NET":            "Framework",
		"PHP":                "Programming",
	}

	for _, tech := range technologies {
		category, exists := techCategories[tech]
		if !exists {
			category = "Miscellaneous"
		}
		categories[category] = append(categories[category], tech)
	}

	return categories
}
