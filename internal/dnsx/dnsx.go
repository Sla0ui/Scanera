// Package dnsx resolves a fuller set of DNS records than the basic host lookup
// and detects wildcard DNS.
package dnsx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
)

// Lookup resolves A, AAAA, CNAME, MX, NS, and TXT records for host. Missing
// record types are simply left empty.
func Lookup(ctx context.Context, host string, timeout time.Duration) *models.DNSRecords {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var r net.Resolver
	rec := &models.DNSRecords{}

	if ips, err := r.LookupIP(c, "ip4", host); err == nil {
		for _, ip := range ips {
			rec.A = append(rec.A, ip.String())
		}
	}
	if ips, err := r.LookupIP(c, "ip6", host); err == nil {
		for _, ip := range ips {
			rec.AAAA = append(rec.AAAA, ip.String())
		}
	}
	if cname, err := r.LookupCNAME(c, host); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && !strings.EqualFold(cname, host) {
			rec.CNAME = append(rec.CNAME, cname)
		}
	}
	if mx, err := r.LookupMX(c, host); err == nil {
		for _, m := range mx {
			rec.MX = append(rec.MX, strings.TrimSuffix(m.Host, "."))
		}
	}
	if ns, err := r.LookupNS(c, host); err == nil {
		for _, n := range ns {
			rec.NS = append(rec.NS, strings.TrimSuffix(n.Host, "."))
		}
	}
	if txt, err := r.LookupTXT(c, host); err == nil {
		rec.TXT = append(rec.TXT, txt...)
	}

	rec.Wildcard = HasWildcard(ctx, host, timeout)
	return rec
}

// HasWildcard reports whether domain has wildcard DNS, by resolving a random
// label that should not otherwise exist.
func HasWildcard(ctx context.Context, domain string, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var r net.Resolver
	probe := fmt.Sprintf("scanera-wildcard-probe-%d.%s", time.Now().UnixNano(), domain)
	ips, err := r.LookupHost(c, probe)
	return err == nil && len(ips) > 0
}

// Resolves reports whether host resolves to any address.
func Resolves(ctx context.Context, host string, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var r net.Resolver
	ips, err := r.LookupHost(c, host)
	return err == nil && len(ips) > 0
}
