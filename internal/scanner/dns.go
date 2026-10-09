package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ResolveDomain resolves a host name to IP addresses within timeout. IP
// literals resolve to themselves.
func ResolveDomain(ctx context.Context, host string, timeout time.Duration) ([]string, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var resolver net.Resolver
	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s: %w", host, err)
	}

	return ips, nil
}

// hostOnly strips a :port suffix and IPv6 brackets.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	if len(hostport) > 1 && hostport[0] == '[' && hostport[len(hostport)-1] == ']' {
		return hostport[1 : len(hostport)-1]
	}
	return hostport
}
