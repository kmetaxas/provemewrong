// Package probe performs one TCP (optionally TLS, optionally HTTP) connectivity
// test against an endpoint and records high-resolution, strictly separated
// per-phase timings.
//
// Phase boundaries are exact by construction:
//
//   - dns_ms:      only name resolution. Measured around dnsx.Resolver.Lookup.
//   - tcp_connect_ms: only the TCP handshake (SYN/SYN-ACK). The dial is made
//     to the already-resolved IP literal, so no DNS work can sneak in.
//   - tls_handshake_ms: only the TLS handshake, performed over an
//     already-established TCP connection.
//   - ttfb_ms / http_read_ms: the optional HTTP probe (request write start to
//     first response byte, and to end of response).
//   - close_ms:    only conn.Close().
//   - total_ms:    wall clock for the whole test, including all phases.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"provemewrong/internal/dnsx"
)

// Scheme selects the protocol layered on top of TCP.
type Scheme string

const (
	SchemeTCP Scheme = "tcp"
	SchemeTLS Scheme = "tls"
)

// DNSResolver resolves a hostname with an explicit, caller-controlled timeout.
// It exists so tests can inject a resolver with a controlled delay or failure.
// *dnsx.Resolver is the production implementation.
type DNSResolver interface {
	Lookup(ctx context.Context, host string) (dnsx.Result, error)
}

// Timeouts bound each phase independently. Zero means "no explicit bound"
// (the test-level context still applies).
type Timeouts struct {
	DNS     time.Duration
	Connect time.Duration
	TLS     time.Duration
	Probe   time.Duration // read/write deadlines for the HTTP probe
	Test    time.Duration // total budget for one test
}

// DefaultTimeouts returns the timeout defaults used when a value is left
// unset. They are deliberately generous so slow-but-real phases are recorded
// rather than truncated.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		DNS:     3 * time.Second,
		Connect: 3 * time.Second,
		TLS:     5 * time.Second,
		Probe:   10 * time.Second,
		Test:    20 * time.Second,
	}
}

// Config configures one Probe.
type Config struct {
	Host       string // hostname to resolve, or an IP literal
	Port       string // port number (kept as a string; validated numeric)
	Scheme     Scheme
	ServerName string // TLS SNI; defaults to Host when Host is not an IP literal
	Insecure   bool   // skip TLS certificate verification (diagnostics only)
	Family     string // "any", "v4" or "v6": filter resolved addresses
	HTTP       bool   // send an HTTP/1.1 HEAD request and measure TTFB etc.
	IPs        []netip.Addr
	// IPs, when non-empty, bypasses DNS resolution entirely
	// (dns_* columns are then null in the dataset).
	Timeouts     Timeouts
	Resolver     DNSResolver // optional override; nil -> selected by ResolverKind
	ResolverKind string      // "dnsx" (default, controlled) or "system" (Go stdlib)
	DNSServer    string      // pin DNS to this server (host[:port]); empty -> /etc/resolv.conf
	DNSAttempts  int         // max query rounds; <= 0 means 1 (no retry); dnsx only
}

// Result is the outcome of one test. Each IP that was actually dialed gets
// its own Attempt; if DNS fails, Attempts is empty.
type Result struct {
	TestID    int64
	StartedAt time.Time
	Host      string
	Port      string
	Scheme    Scheme
	DNSServer string

	DNSRan      bool
	DNSMS       float64
	DNSError    string
	DNSRCode    string // response code ("NOERROR", "SERVFAIL", ...); "" if no response
	DNSAttempts int    // query rounds actually made (1 == no retry)
	ResolvedIPs []netip.Addr

	Attempts []Attempt

	Total time.Duration
}

// Attempt is the outcome of dialing one IP within a test.
type Attempt struct {
	Seq int
	IP  netip.Addr

	TCPMS    float64
	TCPError string

	TLSMS      float64
	TLSError   string
	TLSVersion string
	TLSCipher  string
	TLSALPN    string

	ProbeSent  bool
	TTFBMS     float64
	HTTPStatus int
	HTTPReadMS float64
	ProbeError string

	LocalAddr  string
	Closed     bool
	CloseMS    float64
	CloseError string
}

// OK reports whether this attempt reached the point the test considers
// success: TCP connected, TLS (if enabled) completed, and the HTTP probe (if
// enabled) got a complete response.
func (a Attempt) OK() bool {
	return a.TCPError == "" && a.TLSError == "" && a.ProbeError == ""
}

// Probe runs connectivity tests according to a fixed Config.
type Probe struct {
	cfg      Config
	resolver DNSResolver
}

// New validates cfg and returns a Probe. Zero timeouts are replaced with
// DefaultTimeouts values.
func New(cfg Config) (*Probe, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("probe: empty host")
	}
	if _, err := net.LookupPort("tcp", cfg.Port); err != nil {
		return nil, fmt.Errorf("probe: invalid port %q: %w", cfg.Port, err)
	}
	switch cfg.Scheme {
	case SchemeTCP, SchemeTLS:
	default:
		return nil, fmt.Errorf("probe: invalid scheme %q", cfg.Scheme)
	}
	switch cfg.Family {
	case "", "any", "v4", "v6":
	default:
		return nil, fmt.Errorf("probe: invalid family %q", cfg.Family)
	}
	if cfg.Timeouts.DNS == 0 {
		cfg.Timeouts.DNS = DefaultTimeouts().DNS
	}
	if cfg.Timeouts.Connect == 0 {
		cfg.Timeouts.Connect = DefaultTimeouts().Connect
	}
	if cfg.Timeouts.TLS == 0 {
		cfg.Timeouts.TLS = DefaultTimeouts().TLS
	}
	if cfg.Timeouts.Probe == 0 {
		cfg.Timeouts.Probe = DefaultTimeouts().Probe
	}
	if cfg.Timeouts.Test == 0 {
		cfg.Timeouts.Test = DefaultTimeouts().Test
	}

	p := &Probe{cfg: cfg, resolver: cfg.Resolver}
	if p.resolver == nil {
		kind := cfg.ResolverKind
		if kind == "" {
			kind = "dnsx"
		}
		switch kind {
		case "dnsx":
			var servers []string
			if cfg.DNSServer != "" {
				servers = []string{cfg.DNSServer}
			}
			r, err := dnsx.New(dnsx.Config{
				Servers:  servers,
				Timeout:  cfg.Timeouts.DNS,
				Attempts: cfg.DNSAttempts,
				Family:   cfg.Family,
			})
			if err != nil {
				return nil, err
			}
			p.resolver = r
		case "system":
			p.resolver = &dnsx.StdlibResolver{}
			if cfg.DNSServer != "" {
				// Pin the stdlib resolver to the requested server (note: it
				// still applies its own internal 5s timeout per query).
				server := cfg.DNSServer
				if _, _, err := net.SplitHostPort(server); err != nil {
					server = net.JoinHostPort(server, "53")
				}
				d := &net.Dialer{Timeout: cfg.Timeouts.DNS}
				p.resolver = &dnsx.StdlibResolver{
					Resolver: &net.Resolver{
						PreferGo: true,
						Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
							return d.DialContext(ctx, network, server)
						},
					},
					Server: server,
				}
			}
		default:
			return nil, fmt.Errorf("probe: invalid resolver kind %q", cfg.ResolverKind)
		}
	}
	return p, nil
}

// Run executes one test. ctx bounds the whole test (via TestTimeout).
func (p *Probe) Run(ctx context.Context, testID int64) *Result {
	cfg := p.cfg
	if cfg.Timeouts.Test > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeouts.Test)
		defer cancel()
	}

	res := &Result{
		TestID:    testID,
		StartedAt: time.Now(),
		Host:      cfg.Host,
		Port:      cfg.Port,
		Scheme:    cfg.Scheme,
	}
	defer func() { res.Total = time.Since(res.StartedAt) }()

	ips := cfg.IPs
	if len(ips) == 0 {
		ips = p.resolve(ctx, res)
		if len(ips) == 0 {
			return res
		}
		res.ResolvedIPs = ips
	}

	for i, ip := range ips {
		att := p.dial(ctx, ip, i+1)
		res.Attempts = append(res.Attempts, att)
		if att.OK() {
			break
		}
	}
	return res
}

// resolve performs (and times) DNS resolution only.
func (p *Probe) resolve(ctx context.Context, res *Result) []netip.Addr {
	dctx := ctx
	if p.cfg.Timeouts.DNS > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, p.cfg.Timeouts.DNS)
		defer cancel()
	}
	t0 := time.Now()
	lr, err := p.resolver.Lookup(dctx, p.cfg.Host)
	res.DNSMS = ms(time.Since(t0))
	res.DNSRan = true
	res.DNSRCode = lr.RCode
	res.DNSAttempts = lr.Attempts
	res.DNSServer = lr.Server
	if err != nil {
		res.DNSError = err.Error()
		return nil
	}
	ips := filterFamily(lr.Addrs, p.cfg.Family)
	if len(ips) == 0 {
		res.DNSError = "no usable addresses resolved"
		return nil
	}
	return ips
}

// dial connects to one IP and runs the layered phases (TLS, HTTP probe).
// The dial uses the IP literal, so tcp_connect_ms never contains DNS time.
func (p *Probe) dial(ctx context.Context, ip netip.Addr, seq int) (att Attempt) {
	cfg := p.cfg
	att = Attempt{Seq: seq, IP: ip}

	d := &net.Dialer{Timeout: cfg.Timeouts.Connect, KeepAlive: -1}
	t0 := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), cfg.Port))
	att.TCPMS = ms(time.Since(t0))
	if err != nil {
		att.TCPError = err.Error()
		return att
	}
	att.LocalAddr = conn.LocalAddr().String()
	defer func() {
		t0 := time.Now()
		cerr := conn.Close()
		att.CloseMS = ms(time.Since(t0))
		att.Closed = true
		if cerr != nil {
			att.CloseError = cerr.Error()
		}
	}()

	c := net.Conn(conn)
	if cfg.Scheme == SchemeTLS {
		sni := cfg.ServerName
		if sni == "" {
			if _, err := netip.ParseAddr(cfg.Host); err != nil {
				sni = cfg.Host
			}
		}
		tc := tls.Client(conn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: cfg.Insecure,
			MinVersion:         tls.VersionTLS12,
		})
		hctx := ctx
		if cfg.Timeouts.TLS > 0 {
			var cancel context.CancelFunc
			hctx, cancel = context.WithTimeout(ctx, cfg.Timeouts.TLS)
			defer cancel()
		}
		t0 := time.Now()
		if err := tc.HandshakeContext(hctx); err != nil {
			att.TLSError = err.Error()
			return att
		}
		att.TLSMS = ms(time.Since(t0))
		cs := tc.ConnectionState()
		att.TLSVersion = tlsVersionName(cs.Version)
		att.TLSCipher = tls.CipherSuiteName(cs.CipherSuite)
		att.TLSALPN = cs.NegotiatedProtocol
		c = tc
	}

	if cfg.HTTP {
		p.httpProbe(c, &att)
	}
	return att
}

// httpProbe writes an HTTP/1.1 HEAD request and measures time-to-first-byte
// and time-to-end-of-response.
func (p *Probe) httpProbe(conn net.Conn, att *Attempt) {
	att.ProbeSent = true
	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: provemewrong\r\nAccept: */*\r\nConnection: close\r\n\r\n", p.cfg.Host)

	deadline := time.Time{}
	if p.cfg.Timeouts.Probe > 0 {
		deadline = time.Now().Add(p.cfg.Timeouts.Probe)
		_ = conn.SetWriteDeadline(deadline)
		defer conn.SetDeadline(time.Time{}) //nolint:errcheck
	}

	t0 := time.Now()
	if _, err := io.WriteString(conn, req); err != nil {
		att.ProbeError = err.Error()
		return
	}
	if !deadline.IsZero() {
		_ = conn.SetReadDeadline(deadline)
	}

	br := bufio.NewReader(conn)
	_, err := br.ReadByte()
	att.TTFBMS = ms(time.Since(t0))
	if err != nil {
		att.ProbeError = err.Error()
		return
	}
	_ = br.UnreadByte()

	statusLine, err := br.ReadString('\n')
	att.HTTPStatus = parseStatus(statusLine)
	_, rerr := io.ReadAll(br) // drain to EOF (Connection: close)
	att.HTTPReadMS = ms(time.Since(t0))
	if err != nil && err != io.EOF {
		att.ProbeError = err.Error()
		return
	}
	if rerr != nil && rerr != io.EOF {
		att.ProbeError = rerr.Error()
	}
}

func parseStatus(line string) int {
	fields := strings.Fields(line)
	if len(fields) >= 2 && strings.HasPrefix(fields[0], "HTTP/") {
		if code, err := strconv.Atoi(fields[1]); err == nil {
			return code
		}
	}
	return 0
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case 0:
		return ""
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func filterFamily(addrs []netip.Addr, family string) []netip.Addr {
	out := addrs[:0:0]
	for _, a := range addrs {
		switch family {
		case "v4":
			if !a.Is4() {
				continue
			}
		case "v6":
			if !a.Is6() || a.Is4In6() {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// ms converts a duration to fractional milliseconds.
func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
