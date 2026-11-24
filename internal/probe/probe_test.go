package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"provemewrong/internal/dnsx"
)

// fakeResolver returns fixed addresses after a fixed delay.
type fakeResolver struct {
	addrs []netip.Addr
	delay time.Duration
	err   error
}

func (f *fakeResolver) Lookup(ctx context.Context, host string) (dnsx.Result, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return dnsx.Result{}, ctx.Err()
		}
	}
	if f.err != nil {
		return dnsx.Result{}, f.err
	}
	return dnsx.Result{Addrs: f.addrs, RCode: "NOERROR", Server: "127.0.0.1:53", Attempts: 1}, nil
}

func tcpListener(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func TestPhaseSeparationDNSvsTCP(t *testing.T) {
	// The TCP connect must never include DNS time: we inject a resolver with
	// a large, deterministic delay and a local listener, then assert
	// dns_ms ≈ delay and tcp_connect_ms << dns_ms.
	const dnsDelay = 100 * time.Millisecond
	laddr := tcpListener(t)

	p, err := New(Config{
		Host:     "fake.invalid",
		Port:     strconv.Itoa(int(laddr.Port())),
		Scheme:   SchemeTCP,
		Resolver: &fakeResolver{addrs: []netip.Addr{laddr.Addr()}, delay: dnsDelay},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res := p.Run(context.Background(), 1)
	if res.DNSError != "" {
		t.Fatalf("dns error: %s", res.DNSError)
	}
	if len(res.Attempts) != 1 {
		t.Fatalf("attempts = %d, want 1", len(res.Attempts))
	}
	att := res.Attempts[0]
	if att.TCPError != "" {
		t.Fatalf("tcp error: %s", att.TCPError)
	}
	if !att.Closed {
		t.Fatal("conn not closed")
	}

	// DNS time includes the injected delay.
	if res.DNSMS < ms(dnsDelay)*0.5 {
		t.Errorf("dns_ms = %.3f, want >= %.3f (half the injected delay)", res.DNSMS, ms(dnsDelay)/2)
	}
	// TCP connect to localhost must be far below the DNS delay: proves DNS
	// time did not leak into the TCP phase.
	if att.TCPMS > ms(dnsDelay)/2 {
		t.Errorf("tcp_connect_ms = %.3f, want < %.3f (DNS time leaked into TCP phase?)", att.TCPMS, ms(dnsDelay)/2)
	}
	// Total is dominated by DNS.
	if res.Total < dnsDelay {
		t.Errorf("total = %v, want >= %v", res.Total, dnsDelay)
	}
	if got := res.ResolvedIPs[0]; got != laddr.Addr() {
		t.Errorf("resolved ip = %v, want %v", got, laddr.Addr())
	}
}

func TestDNSFailureProducesNoAttempts(t *testing.T) {
	p, err := New(Config{
		Host:     "fake.invalid",
		Port:     "443",
		Scheme:   SchemeTLS,
		Resolver: &fakeResolver{err: errors.New("no such host")},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := p.Run(context.Background(), 2)
	if !strings.Contains(res.DNSError, "no such host") {
		t.Errorf("dns_error = %q", res.DNSError)
	}
	if len(res.Attempts) != 0 {
		t.Fatalf("attempts = %d, want 0", len(res.Attempts))
	}
	if !res.DNSRan {
		t.Error("DNSRan = false, want true")
	}
}

func TestTCPFailureRecordsError(t *testing.T) {
	// A closed port on loopback: connect must fail fast.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr).AddrPort()
	ln.Close() // nothing listening now

	p, err := New(Config{
		Host:   "127.0.0.1",
		Port:   strconv.Itoa(int(addr.Port())),
		Scheme: SchemeTCP,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := p.Run(context.Background(), 3)
	if len(res.Attempts) != 1 {
		t.Fatalf("attempts = %d, want 1", len(res.Attempts))
	}
	att := res.Attempts[0]
	if att.TCPError == "" {
		t.Fatal("tcp_error empty, want connection refused")
	}
	if att.Closed {
		t.Error("Closed = true but no connection was established")
	}
	if att.TLSVersion != "" {
		t.Errorf("tls_version = %q on tcp scheme, want empty", att.TLSVersion)
	}
}

func TestTLSHandshakeTiming(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	laddr, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if err != nil {
		t.Fatal(err)
	}

	p, err := New(Config{
		Host:     "127.0.0.1",
		Port:     port,
		Scheme:   SchemeTLS,
		IPs:      []netip.Addr{laddr.Addr()},
		Insecure: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res := p.Run(context.Background(), 4)
	if res.DNSRan {
		t.Error("DNSRan = true, want false (IPs were pre-resolved)")
	}
	att := res.Attempts[0]
	if att.TLSError != "" {
		t.Fatalf("tls error: %s", att.TLSError)
	}
	if att.TLSMS <= 0 {
		t.Errorf("tls_handshake_ms = %v, want > 0", att.TLSMS)
	}
	if att.TLSVersion == "" || att.TLSCipher == "" {
		t.Errorf("tls metadata missing: version=%q cipher=%q", att.TLSVersion, att.TLSCipher)
	}
	if att.LocalAddr == "" {
		t.Error("local_addr empty")
	}
}

func TestHTTPProbeTTFB(t *testing.T) {
	const serverDelay = 150 * time.Millisecond
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(serverDelay)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	laddr, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if err != nil {
		t.Fatal(err)
	}

	p, err := New(Config{
		Host:     "127.0.0.1",
		Port:     port,
		Scheme:   SchemeTLS,
		IPs:      []netip.Addr{laddr.Addr()},
		Insecure: true,
		HTTP:     true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res := p.Run(context.Background(), 5)
	att := res.Attempts[0]
	if att.ProbeError != "" {
		t.Fatalf("probe error: %s", att.ProbeError)
	}
	if !att.ProbeSent {
		t.Fatal("probe_sent = false, want true")
	}
	if att.HTTPStatus != http.StatusTeapot {
		t.Errorf("http_status = %d, want %d", att.HTTPStatus, http.StatusTeapot)
	}
	// TTFB covers at least the server-side delay (with some tolerance).
	if att.TTFBMS < ms(serverDelay)*0.6 {
		t.Errorf("ttfb_ms = %.3f, want >= %.3f", att.TTFBMS, ms(serverDelay)*0.6)
	}
	if att.HTTPReadMS < att.TTFBMS {
		t.Errorf("http_read_ms = %.3f < ttfb_ms = %.3f", att.HTTPReadMS, att.TTFBMS)
	}
}

func TestMultiIPFailover(t *testing.T) {
	laddr := tcpListener(t)
	dead := netip.MustParseAddr("127.0.0.2") // loopback, nothing listening

	p, err := New(Config{
		Host:   "fake.invalid",
		Port:   strconv.Itoa(int(laddr.Port())),
		Scheme: SchemeTCP,
		IPs:    []netip.Addr{dead, laddr.Addr()},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := p.Run(context.Background(), 6)
	if len(res.Attempts) != 2 {
		t.Fatalf("attempts = %d, want 2 (failover)", len(res.Attempts))
	}
	first, second := res.Attempts[0], res.Attempts[1]
	if first.Seq != 1 || second.Seq != 2 {
		t.Errorf("seqs = %d,%d want 1,2", first.Seq, second.Seq)
	}
	if first.TCPError == "" {
		t.Error("first attempt tcp_error empty, want failure")
	}
	if second.TCPError != "" || !second.OK() {
		t.Errorf("second attempt not OK: err=%q", second.TCPError)
	}
}

func TestFamilyFilter(t *testing.T) {
	v4 := netip.MustParseAddr("127.0.0.1")
	v6 := netip.MustParseAddr("::1")
	got := filterFamily([]netip.Addr{v4, v6}, "v4")
	if len(got) != 1 || got[0] != v4 {
		t.Errorf("v4 filter = %v, want [%v]", got, v4)
	}
	got = filterFamily([]netip.Addr{v4, v6}, "v6")
	if len(got) != 1 || got[0] != v6 {
		t.Errorf("v6 filter = %v, want [%v]", got, v6)
	}
}

func TestValidation(t *testing.T) {
	for _, cfg := range []Config{
		{},
		{Host: "x", Port: "nope"},
		{Host: "x", Port: "443", Scheme: "bad"},
		{Host: "x", Port: "443", Scheme: SchemeTCP, Family: "nope"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) = nil error, want validation error", cfg)
		}
	}
}
