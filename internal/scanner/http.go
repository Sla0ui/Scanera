package scanner

import (
	"html"
	"net/http"
	"regexp"
	"strings"

	"github.com/Sla0ui/scanera/internal/models"
)

// ExtractServerInfo extracts server information from HTTP response
func ExtractServerInfo(resp *http.Response, result *models.Result) {
	result.ServerInfo.Server = resp.Header.Get("Server")
	result.ServerInfo.PoweredBy = resp.Header.Get("X-Powered-By")
	result.ServerInfo.ContentType = resp.Header.Get("Content-Type")
	result.ServerInfo.LastModified = resp.Header.Get("Last-Modified")

	if resp.ContentLength > 0 {
		result.ServerInfo.ResponseSize = resp.ContentLength
	}

	if result.ServerInfo.Headers == nil {
		result.ServerInfo.Headers = make(map[string]string)
	}

	for k, v := range resp.Header {
		if len(v) > 0 {
			result.ServerInfo.Headers[k] = v[0]
		}
	}
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// extractTitle returns the page <title>, unescaped and with whitespace
// collapsed, so a title is available even when the browser check is skipped.
func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(html.UnescapeString(m[1])), " ")
	if len(t) > 300 {
		t = t[:300]
	}
	return t
}
