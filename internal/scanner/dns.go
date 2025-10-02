package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ResolveDomain resolves a domain name to IP addresses
func ResolveDomain(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var resolver net.Resolver
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s: %w", domain, err)
	}

	return ips, nil
}
