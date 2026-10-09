// Package portscan performs a TCP connect scan and identifies common services.
package portscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sla0ui/scanera/internal/models"
)

var topPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993,
	995, 1433, 1521, 1723, 2049, 2082, 2083, 2222, 3000, 3306, 3389, 5000, 5432,
	5601, 5900, 5985, 5986, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
	9092, 9200, 9300, 11211, 15672, 27017, 27018, 6443,
}

var serviceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
	443: "https", 445: "smb", 465: "smtps", 587: "submission", 993: "imaps",
	995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
	2082: "cpanel", 2083: "cpanel-ssl", 2222: "ssh-alt", 3000: "http-dev",
	3306: "mysql", 3389: "rdp", 5000: "http-alt", 5432: "postgresql",
	5601: "kibana", 5900: "vnc", 5985: "winrm", 5986: "winrm-ssl", 6379: "redis",
	7001: "weblogic", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
	8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
	9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch", 11211: "memcached",
	15672: "rabbitmq", 27017: "mongodb", 27018: "mongodb", 6443: "kubernetes",
}

// ParsePorts turns a spec into a port list. Accepts "top", "top1000",
// comma lists ("80,443"), and ranges ("8000-8100"). Unknown specs fall back to
// the top-ports set.
func ParsePorts(spec string) []int {
	spec = strings.ToLower(strings.TrimSpace(spec))
	switch spec {
	case "", "top", "top50", "common":
		return append([]int(nil), topPorts...)
	case "top1000", "1000":
		ports := make([]int, 0, 1024)
		for p := 1; p <= 1024; p++ {
			ports = append(ports, p)
		}
		return ports
	case "full", "all", "65535":
		ports := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		return ports
	}

	seen := make(map[int]struct{})
	var ports []int
	add := func(p int) {
		if p < 1 || p > 65535 {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 == nil && err2 == nil && lo <= hi {
				for p := lo; p <= hi; p++ {
					add(p)
				}
			}
			continue
		}
		if p, err := strconv.Atoi(part); err == nil {
			add(p)
		}
	}
	if len(ports) == 0 {
		return append([]int(nil), topPorts...)
	}
	return ports
}

// Scan performs a TCP connect scan of ports against host.
func Scan(ctx context.Context, host string, ports []int, concurrency int, timeout time.Duration, grabBanner bool) []models.Port {
	if concurrency <= 0 {
		concurrency = 100
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	jobs := make(chan int)
	results := make(chan models.Port)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			for port := range jobs {
				addr := net.JoinHostPort(host, strconv.Itoa(port))
				conn, err := d.DialContext(ctx, "tcp", addr)
				if err != nil {
					continue
				}
				p := models.Port{Port: port, Protocol: "tcp", Service: serviceNames[port]}
				if grabBanner {
					p.Banner = grab(conn, timeout)
				}
				conn.Close()
				results <- p
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, port := range ports {
			select {
			case jobs <- port:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var open []models.Port
	for p := range results {
		open = append(open, p)
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

func grab(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%q", string(buf[:n])))
}
