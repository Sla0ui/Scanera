package scanner

import (
	"crypto/tls"
	"fmt"
	"github.com/Sla0ui/scanera/internal/models"
	"net/http"
	"time"
)

// TryHTTPRequest attempts to make an HTTP request with retries
func TryHTTPRequest(url string, config *models.Config) (*http.Response, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifyTLS,
		},
		DisableKeepAlives: false,
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
	}

	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("User-Agent", config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")

	var lastErr error
	for attempt := 0; attempt < config.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}

		lastErr = err
	}

	return nil, fmt.Errorf("all request attempts failed: %w", lastErr)
}

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

// FetchCertificateInfo retrieves TLS certificate information for a domain
func FetchCertificateInfo(domain string, result *models.Result) error {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true,
	})

	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", domain, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]
		result.SecurityInfo.ValidCert = time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore)
		result.SecurityInfo.CertIssuer = cert.Issuer.CommonName
		result.SecurityInfo.CertExpiry = cert.NotAfter

		tlsVersion := conn.ConnectionState().Version
		switch tlsVersion {
		case tls.VersionTLS10:
			result.SecurityInfo.TLSVersion = "TLS 1.0"
		case tls.VersionTLS11:
			result.SecurityInfo.TLSVersion = "TLS 1.1"
		case tls.VersionTLS12:
			result.SecurityInfo.TLSVersion = "TLS 1.2"
		case tls.VersionTLS13:
			result.SecurityInfo.TLSVersion = "TLS 1.3"
		default:
			result.SecurityInfo.TLSVersion = fmt.Sprintf("Unknown (%d)", tlsVersion)
		}
	}

	return nil
}
