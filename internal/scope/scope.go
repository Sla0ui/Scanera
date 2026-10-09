// Package scope enforces which hosts may be actively scanned and records an
// audit trail of active actions, keeping Scanera usable in authorized
// engagements without doubling as an untargeted weapon.
package scope

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Scope defines the set of hosts permitted for active scanning.
type Scope struct {
	allowed    []string
	authorized bool

	mu    sync.Mutex
	audit *os.File
}

// Load reads a scope file: one host or pattern per line; blank lines and lines
// beginning with '#' are ignored. A leading "*." matches a domain and all of
// its subdomains (e.g. "*.example.com").
func Load(path string) (*Scope, error) {
	f, err := os.Open(path) //nolint:gosec // path is operator-supplied
	if err != nil {
		return nil, fmt.Errorf("failed to open scope file: %w", err)
	}
	defer f.Close()

	s := &Scope{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s.allowed = append(s.allowed, strings.ToLower(line))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error reading scope file: %w", err)
	}
	if len(s.allowed) == 0 {
		return nil, fmt.Errorf("scope file %q contains no entries", path)
	}
	return s, nil
}

// Authorized returns a scope that permits every host, representing an explicit
// operator acknowledgement (--authorize) that all targets are in scope.
func Authorized() *Scope {
	return &Scope{authorized: true}
}

// InScope reports whether host may be actively scanned.
func (s *Scope) InScope(host string) bool {
	if s == nil {
		return false
	}
	if s.authorized {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))
	for _, p := range s.allowed {
		if matchHost(p, host) {
			return true
		}
	}
	return false
}

func matchHost(pattern, host string) bool {
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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) //nolint:gosec
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	s.audit = f
	s.Log("audit-start", "", "scanera audit log opened")
	return nil
}

// Log appends a timestamped line to the audit log, if one is attached.
func (s *Scope) Log(action, target, detail string) {
	if s == nil || s.audit == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.audit, "%s\t%s\t%s\t%s\n",
		time.Now().UTC().Format(time.RFC3339), action, target, detail)
}

// Close closes the audit log.
func (s *Scope) Close() error {
	if s == nil || s.audit == nil {
		return nil
	}
	return s.audit.Close()
}
