// Package netx builds shared HTTP clients with optional proxy support.
package netx

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
)

// NewHTTPClient builds an *http.Client honoring TLS verification, timeout, the
// redirect cap, and an optional proxy. The proxy URL may use http, https, or
// socks5 schemes (net/http supports socks5 proxies natively).
func NewHTTPClient(cfg *models.Config) (*http.Client, error) {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: !cfg.VerifyTLS}, //nolint:gosec // controlled by config
		DisableKeepAlives: false,
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
	}

	if cfg.ProxyURL != "" {
		pu, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy url %q: %w", cfg.ProxyURL, err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}

	maxRedirects := cfg.MaxRedirects
	return &http.Client{
		Timeout:   cfg.Timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, nil
}
