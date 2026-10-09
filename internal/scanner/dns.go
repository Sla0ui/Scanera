package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ResolveDomain resolves a domain name to IP addresses, honoring the caller's
// timeout (previously hardcoded to 5s and ignoring the configured timeout).
func ResolveDomain(domain string, timeout time.Duration) ([]string, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var resolver net.Resolver
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s: %w", domain, err)
	}

	return ips, nil
}
