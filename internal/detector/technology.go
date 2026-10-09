package detector

import (
	"regexp"
	"sort"
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

	// Patterns look for asset paths, globals, and markup a product actually
	// emits, not its name: a page that merely mentions "react" or "bootstrap"
	// in prose is not using it.
	patterns := map[string]string{
		"WordPress":          `wp-content/|wp-includes/|/wp-json/|(?i:<meta name="generator" content="WordPress)`,
		"Joomla":             `(?i:<meta name="generator" content="Joomla)|/media/jui/|/media/system/js/core\.js|/components/com_`,
		"Drupal":             `Drupal\.settings|drupal-settings-json|data-drupal-|/sites/(?:all|default)/(?:themes|modules|files)/|(?i:content="Drupal|^x-generator: drupal|^x-drupal-)`,
		"Magento":            `Mage\.Cookies|text/x-magento-init|data-mage-init|/skin/frontend/|/static/version\d+/frontend/`,
		"Shopify":            `cdn\.shopify\.com|Shopify\.theme|\.myshopify\.com`,
		"WooCommerce":        `/plugins/woocommerce/|wc_add_to_cart_params|class="[^"]*\bwoocommerce`,
		"jQuery":             `jquery[\w.\-]*\.js|code\.jquery\.com|jQuery\.fn`,
		"React":              `data-reactroot|_reactRootContainer|__REACT_DEVTOOLS_GLOBAL_HOOK__|\breact(?:-dom)?(?:\.production|\.development)?(?:\.min)?\.js`,
		"Next.js":            `__NEXT_DATA__|/_next/static/`,
		"Vue.js":             `data-v-[0-9a-f]{8}|__vue__|\bvue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js`,
		"Nuxt.js":            `__NUXT__|/_nuxt/`,
		"Angular":            `ng-version=|_ngcontent-|\bng-(?:app|controller)\b|\bangular(?:\.min)?\.js`,
		"Bootstrap":          `bootstrap[\w.\-]*\.(?:js|css)\b`,
		"Tailwind CSS":       `tailwindcss|tailwind\.css`,
		"Font Awesome":       `font-awesome|fontawesome`,
		"Google Analytics":   `google-analytics\.com/(?:analytics|ga|urchin)\.js|googletagmanager\.com/gtag/js|gtag\(\s*['"]config['"]\s*,\s*['"](?:UA|G)-|\bUA-\d{4,10}-\d{1,4}\b`,
		"Google Tag Manager": `googletagmanager\.com/gtm\.js|\bGTM-[A-Z0-9]{4,8}\b`,
		"Cloudflare":         `/cdn-cgi/|__cf_bm|(?i:^cf-ray:|^server: cloudflare)`,
		"PHP":                `(?i:^x-powered-by: php)|PHPSESSID`,
		"ASP.NET":            `__VIEWSTATE|__EVENTVALIDATION|ASP\.NET_SessionId|(?i:^x-aspnet-version:|^x-powered-by: asp\.net)`,
		"Google Fonts":       `fonts\.googleapis\.com`,
		"Google Maps":        `maps\.google\.com|maps\.googleapis\.com`,
		"Google reCAPTCHA":   `google\.com/recaptcha|grecaptcha|g-recaptcha`,
		"Modernizr":          `modernizr`,
		"Moment.js":          `moment(?:-with-locales)?(?:\.min)?\.js`,
		"Lodash":             `\blodash(?:\.min)?\.js|/lodash[@/]|(?i:@license lodash)`,
		"Axios":              `\baxios(?:\.min)?\.js|/axios[@/]`,
		"Chart.js":           `(?i:[/"']chart(?:\.umd|\.bundle)?(?:\.min)?\.js|chart\.js@\d)`,
		"D3.js":              `\bd3(?:\.v\d)?(?:\.min)?\.js|/d3@\d|d3js\.org`,
		"Leaflet":            `leaflet\.js|leaflet\.css`,
		"Stripe":             `js\.stripe\.com|Stripe\.setPublishableKey|\bStripe\(\s*['"]pk_`,
		"PayPal":             `paypalobjects\.com|paypal\.com/sdk/js|paypal\.com/cgi-bin/webscr|paypal\.com/donate`,
		"Hotjar":             `static\.hotjar\.com|_hjSettings|hjSetting`,
		"Intercom":           `widget\.intercom\.io|js\.intercomcdn\.com|intercomSettings`,
		"Drift":              `js\.driftt\.com|\bdrift\.load\(`,
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
			// A CSP lists sources the site may load, not ones it does, so
			// matching it would report every allowlisted CDN as in use.
			if strings.HasPrefix(strings.ToLower(header), "content-security-policy") {
				continue
			}
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

	sort.Strings(technologies)
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
		"Next.js":            "Framework",
		"Vue.js":             "JavaScript",
		"Nuxt.js":            "Framework",
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
