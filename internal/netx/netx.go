// Package netx builds shared HTTP clients with optional proxy support.
package netx

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
)

// NewHTTPClient builds an *http.Client honoring TLS verification, timeout, the
// redirect cap, and an optional proxy. The proxy URL may use http, https, or
// socks5 schemes (net/http supports socks5 proxies natively). Without an
// explicit proxy the usual HTTP_PROXY/HTTPS_PROXY/NO_PROXY variables apply.
func NewHTTPClient(cfg *models.Config) (*http.Client, error) {
	dialer := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: !cfg.VerifyTLS, //nolint:gosec // controlled by config
		// Go clients default to TLS 1.2+, which makes legacy-only servers look
		// dead. Accept older versions so they're scanned and reported instead.
		MinVersion: tls.VersionTLS10,
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
	}

	if cfg.ProxyURL != "" {
		pu, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy url %q: %w", cfg.ProxyURL, err)
		}
		switch pu.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https or socks5)", pu.Scheme)
		}
		if pu.Host == "" {
			return nil, fmt.Errorf("invalid proxy url %q: missing host", cfg.ProxyURL)
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

// WithTimeout returns a shallow copy of client with a different overall
// timeout, sharing the same transport and connection pool.
func WithTimeout(client *http.Client, timeout time.Duration) *http.Client {
	c := *client
	c.Timeout = timeout
	return &c
}
