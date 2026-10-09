// Package scope enforces which hosts may be actively scanned and records an
// audit trail of active actions, keeping Scanera usable in authorized
// engagements without doubling as an untargeted weapon.
package scope

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// rule is one scope entry: a hostname pattern or an IP prefix.
type rule struct {
	host   string // exact host, or "*.base" for base and its subdomains
	prefix netip.Prefix
}

func (r rule) match(host string, ip netip.Addr) bool {
	if r.prefix.IsValid() {
		return ip.IsValid() && r.prefix.Contains(ip)
	}
	return matchHost(r.host, host)
}

// Scope defines the set of hosts permitted for active scanning.
type Scope struct {
	allowed    []rule
	excluded   []rule
	authorized bool

	mu    sync.Mutex
	audit *os.File
}

// Load reads a scope file. One entry per line; blank lines and lines starting
// with '#' are ignored. Supported entries:
//
//	example.com        exactly this host
//	*.example.com      the domain and all of its subdomains
//	203.0.113.7        a single IP address
//	203.0.113.0/24     an IP range (IPv4 or IPv6 CIDR)
//	!dev.example.com   an exclusion; exclusions win over any allow entry
//
// URL-style entries such as https://example.com:8443/app are reduced to their
// host, so scope lists pasted from engagement documents work as-is.
func Load(path string) (*Scope, error) {
	f, err := os.Open(path) //nolint:gosec // path is operator-supplied
	if err != nil {
		return nil, fmt.Errorf("failed to open scope file: %w", err)
	}
	defer f.Close()
	s, err := parse(f)
	if err != nil {
		return nil, fmt.Errorf("scope file %q: %w", path, err)
	}
	return s, nil
}

// FromEntries builds a scope from entries in the same syntax as a scope file.
func FromEntries(entries ...string) (*Scope, error) {
	return parse(strings.NewReader(strings.Join(entries, "\n")))
}

func parse(r io.Reader) (*Scope, error) {
	s := &Scope{}
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		exclude := strings.HasPrefix(line, "!")
		if exclude {
			line = strings.TrimSpace(line[1:])
		}
		ru, err := parseRule(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if exclude {
			s.excluded = append(s.excluded, ru)
		} else {
			s.allowed = append(s.allowed, ru)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error reading scope: %w", err)
	}
	if len(s.allowed) == 0 {
		return nil, fmt.Errorf("no allow entries")
	}
	return s, nil
}

func parseRule(entry string) (rule, error) {
	if strings.Contains(entry, "/") && !strings.Contains(entry, "://") {
		if p, err := netip.ParsePrefix(entry); err == nil {
			return rule{prefix: p.Masked()}, nil
		}
	}
	host := normalizeHost(entry)
	if host == "" {
		return rule{}, fmt.Errorf("invalid entry %q", entry)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return rule{prefix: netip.PrefixFrom(ip, ip.BitLen())}, nil
	}
	base := strings.TrimPrefix(host, "*.")
	if base == "" || strings.Contains(base, "*") || strings.ContainsAny(base, " \t/") {
		return rule{}, fmt.Errorf("invalid host pattern %q", entry)
	}
	return rule{host: host}, nil
}

// normalizeHost lowercases a host and strips any scheme, path, port, IPv6
// brackets, and trailing dot.
func normalizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Host
		}
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(strings.Trim(s, "[]"), ".")
	return s
}

// Authorized returns a scope that permits every host, representing an explicit
// operator acknowledgement (--authorize) that all targets are in scope.
func Authorized() *Scope {
	return &Scope{authorized: true}
}

// InScope reports whether host may be actively scanned. host may carry a port
// or be an IP literal.
func (s *Scope) InScope(host string) bool {
	if s == nil {
		return false
	}
	if s.authorized {
		return true
	}
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	ip, _ := netip.ParseAddr(host)
	ip = ip.Unmap()
	for _, r := range s.excluded {
		if r.match(host, ip) {
			return false
		}
	}
	for _, r := range s.allowed {
		if r.match(host, ip) {
			return true
		}
	}
	return false
}

func matchHost(pattern, host string) bool {
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return host == pattern
}

// AttachAudit opens (appending) an audit log that records active actions.
func (s *Scope) AttachAudit(path string) error {
	if s == nil || path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) //nolint:gosec // operator-supplied path
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	s.audit = f
	s.Log("audit-start", "", "scanera audit log opened")
	return nil
}

// Log appends a timestamped line to the audit log, if one is attached.
func (s *Scope) Log(action, target, detail string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.audit == nil {
		return
	}
	fmt.Fprintf(s.audit, "%s\t%s\t%s\t%s\n",
		time.Now().UTC().Format(time.RFC3339), action, target, detail)
}

// Close closes the audit log.
func (s *Scope) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.audit == nil {
		return nil
	}
	err := s.audit.Close()
	s.audit = nil
	return err
}
