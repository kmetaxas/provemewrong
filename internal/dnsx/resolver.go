// Package dnsx is a small, fully-controllable DNS resolver.
//
// The standard library's net.Resolver (pure-Go resolver) imposes its own
// internal per-query timeout — hardcoded 5s, overridable only via
// /etc/resolv.conf `options timeout:N` — plus a 2-attempt retry, neither of
// which is exposed through its public API. A caller's context deadline is
// intersected with that hidden 5s, so a non-responding nameserver produces a
// ~5s "timeout" regardless of what timeout the caller asked for.
//
// dnsx sends DNS queries directly (via miekg/dns) with an explicit deadline
// equal to the caller's timeout and a caller-controlled attempt count. This
// makes the measured DNS time reflect real resolution work, not the resolver's
// built-in retry/timeout policy.
package dnsx

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// Result is the outcome of a Lookup, with observability for latency diagnosis.
type Result struct {
	Addrs    []netip.Addr
	RCode    string   // DNS response code ("NOERROR", "SERVFAIL", "NXDOMAIN", ...); "" if no response
	Server   string   // nameserver that produced the (last) response or was last tried
	TTL      uint32   // minimum TTL across returned records; 0 if none
	CNAMEs   []string // CNAME chain, in order of encounter
	Attempts int      // number of query attempts made (1 == no retry)
}

// Config configures one Resolver.
type Config struct {
	Servers  []string      // nameservers (host[:port]); empty -> read /etc/resolv.conf
	Timeout  time.Duration // per-query deadline (no hidden resolver timeout)
	Attempts int           // max query rounds; <= 0 means 1 (no retry)
	Family   string        // "any", "v4", "v6": which records to query
	TCP      bool          // send queries over TCP only (default: UDP)
}

// Resolver resolves hostnames with an explicit timeout and attempt count.
type Resolver struct {
	servers  []string
	timeout  time.Duration
	attempts int
	family   string
	tcp      bool
}

// New builds a Resolver. When cfg.Servers is empty, nameservers are read from
// /etc/resolv.conf (search domains and the file's own timeout/attempts are
// deliberately ignored — only the nameserver list is used).
func New(cfg Config) (*Resolver, error) {
	servers := append([]string(nil), cfg.Servers...)
	if len(servers) == 0 {
		cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, fmt.Errorf("dnsx: read /etc/resolv.conf: %w", err)
		}
		for _, s := range cc.Servers {
			servers = append(servers, net.JoinHostPort(s, cc.Port))
		}
	}
	for i, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			servers[i] = net.JoinHostPort(s, "53")
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("dnsx: no nameservers configured")
	}
	attempts := cfg.Attempts
	if attempts <= 0 {
		attempts = 1
	}
	family := cfg.Family
	if family == "" {
		family = "any"
	}
	return &Resolver{
		servers:  servers,
		timeout:  cfg.Timeout,
		attempts: attempts,
		family:   family,
		tcp:      cfg.TCP,
	}, nil
}

// Lookup resolves host to its A/AAAA addresses (subject to the configured
// family). It returns a Result with observability even on failure (RCode,
// Server, Attempts), alongside a non-nil error.
func (r *Resolver) Lookup(ctx context.Context, host string) (Result, error) {
	res := Result{}

	// An IP literal needs no resolution; return it directly (matches the
	// stdlib resolver's behavior of not querying DNS for literal addresses).
	if addr, err := netip.ParseAddr(host); err == nil {
		res.Addrs = []netip.Addr{addr}
		return res, nil
	}

	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	switch r.family {
	case "v4":
		qtypes = []uint16{dns.TypeA}
	case "v6":
		qtypes = []uint16{dns.TypeAAAA}
	}

	// Timeout of 0 means "no deadline"; use the context's own deadline then.
	client := &dns.Client{}
	if r.tcp {
		// Force TCP: avoids UDP entirely, for networks that drop UDP packets.
		client.Net = "tcp"
	}
	if r.timeout > 0 {
		client.Timeout = r.timeout
	}

	var lastErr error
	for attempt := 1; attempt <= r.attempts; attempt++ {
		res.Attempts = attempt
		for _, server := range r.servers {
			res.Server = server
			for _, qtype := range qtypes {
				msg := new(dns.Msg)
				msg.SetQuestion(dns.Fqdn(host), qtype)
				msg.RecursionDesired = true
				msg.SetEdns0(4096, false)

				resp, _, err := client.ExchangeContext(ctx, msg, server)
				if err != nil {
					lastErr = err
					continue
				}
				if resp == nil {
					lastErr = fmt.Errorf("dnsx: empty response from %s", server)
					continue
				}
				res.RCode = dns.RcodeToString[resp.Rcode]
				if resp.Rcode != dns.RcodeSuccess {
					lastErr = fmt.Errorf("dnsx: server %s returned %s", server, res.RCode)
					continue
				}
				for _, rr := range resp.Answer {
					switch a := rr.(type) {
					case *dns.A:
						res.Addrs = append(res.Addrs, netip.AddrFrom4([4]byte(a.A)))
					case *dns.AAAA:
						res.Addrs = append(res.Addrs, netip.AddrFrom16([16]byte(a.AAAA)))
					case *dns.CNAME:
						res.CNAMEs = append(res.CNAMEs, a.Target)
					}
					if ttl := rr.Header().Ttl; ttl != 0 && (res.TTL == 0 || ttl < res.TTL) {
						res.TTL = ttl
					}
				}
			}
			// Success as soon as any server returned at least one address.
			if len(res.Addrs) > 0 {
				return res, nil
			}
		}
	}

	if lastErr != nil {
		return res, lastErr
	}
	return res, fmt.Errorf("dnsx: no addresses for %s", host)
}
