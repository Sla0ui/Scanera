package detector

import (
	"regexp"
	"strings"
	"sync"

	"github.com/Sla0ui/scanera/internal/models"
)

type versionFP struct {
	name       string
	categories []string
	inHeaders  bool
	re         *regexp.Regexp
}

var (
	versionFPs []versionFP
	vfpOnce    sync.Once
)

func initVersionFPs() {
	add := func(name, cat string, inHeaders bool, pattern string) {
		versionFPs = append(versionFPs, versionFP{
			name: name, categories: []string{cat}, inHeaders: inHeaders,
			re: regexp.MustCompile(pattern),
		})
	}
	// Body-based (version optional via capture group 1).
	add("jQuery", "JavaScript", false, `(?i)jquery[/\-@](\d+\.\d+(?:\.\d+)?)`)
	add("Bootstrap", "CSS Framework", false, `(?i)bootstrap[/\-@](\d+\.\d+(?:\.\d+)?)`)
	add("WordPress", "CMS", false, `(?i)<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)`)
	add("Drupal", "CMS", false, `(?i)Drupal[ /](\d+(?:\.\d+)?)`)
	// Header-based.
	add("nginx", "Server", true, `(?i)nginx/(\d+\.\d+(?:\.\d+)?)`)
	add("Apache", "Server", true, `(?i)Apache/(\d+\.\d+(?:\.\d+)?)`)
	add("PHP", "Programming", true, `(?i)PHP/(\d+\.\d+(?:\.\d+)?)`)
	add("OpenSSL", "Library", true, `(?i)OpenSSL/(\d+\.\d+\.\d+[a-z]?)`)
	add("IIS", "Server", true, `(?i)Microsoft-IIS/(\d+\.\d+)`)
}

// DetectWithVersions extracts technologies and, where possible, their versions,
// from response content and headers. Intended to feed the vulnerability matcher.
func DetectWithVersions(content string, headers map[string][]string) []models.Tech {
	vfpOnce.Do(initVersionFPs)

	var hb strings.Builder
	for k, vs := range headers {
		for _, v := range vs {
			hb.WriteString(k)
			hb.WriteString(": ")
			hb.WriteString(v)
			hb.WriteString("\n")
		}
	}
	headerText := hb.String()

	var techs []models.Tech
	seen := make(map[string]struct{})
	for _, fp := range versionFPs {
		text := content
		if fp.inHeaders {
			text = headerText
		}
		m := fp.re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		if _, ok := seen[fp.name]; ok {
			continue
		}
		seen[fp.name] = struct{}{}
		version := ""
		if len(m) > 1 {
			version = m[1]
		}
		techs = append(techs, models.Tech{Name: fp.name, Version: version, Categories: fp.categories})
	}
	return techs
}
