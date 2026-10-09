package models

import "strings"

// Severity ranks the impact of a Finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rank returns a sortable integer for a severity (higher = worse).
func (s Severity) Rank() int {
	switch Severity(strings.ToLower(string(s))) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Normalize returns a known severity, defaulting to info.
func (s Severity) Normalize() Severity {
	switch Severity(strings.ToLower(strings.TrimSpace(string(s)))) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// Finding is a single security-relevant observation produced by any module
// (templates, probes, secret scanning, vulnerability matching, port scanning).
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Source      string   `json:"source"` // template|probe|secret|vuln|port|tls
	Description string   `json:"description,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Location    string   `json:"location,omitempty"` // URL, path, or host:port
	References  []string `json:"references,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
}

// Tech is a detected technology, optionally with a version.
type Tech struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories,omitempty"`
}

// DNSRecords holds a fuller set of resolved DNS records for a host.
type DNSRecords struct {
	A        []string `json:"a,omitempty"`
	AAAA     []string `json:"aaaa,omitempty"`
	CNAME    []string `json:"cname,omitempty"`
	MX       []string `json:"mx,omitempty"`
	NS       []string `json:"ns,omitempty"`
	TXT      []string `json:"txt,omitempty"`
	Wildcard bool     `json:"wildcard,omitempty"`
}

// Port describes an open TCP port and its identified service.
type Port struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
}
