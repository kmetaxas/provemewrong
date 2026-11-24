package dnsx

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// serve runs a UDP DNS server and returns its bound address.
func serve(t *testing.T, handler dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go srv.ActivateAndServe() //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestLookupSuccess(t *testing.T) {
	addr := serve(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(1, 2, 3, 4),
		})
		_ = w.WriteMsg(m)
	}))

	r, err := New(Config{Servers: []string{addr}, Timeout: 2 * time.Second, Attempts: 1, Family: "v4"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(res.Addrs) != 1 || res.Addrs[0].String() != "1.2.3.4" {
		t.Errorf("addrs = %v, want [1.2.3.4]", res.Addrs)
	}
	if res.RCode != "NOERROR" {
		t.Errorf("rcode = %q, want NOERROR", res.RCode)
	}
	if res.Server != addr {
		t.Errorf("server = %q, want %q", res.Server, addr)
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", res.Attempts)
	}
}

func TestLookupNXDOMAIN(t *testing.T) {
	addr := serve(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
	}))

	r, err := New(Config{Servers: []string{addr}, Timeout: 2 * time.Second, Attempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Lookup(context.Background(), "does-not-exist.invalid")
	if err == nil {
		t.Fatal("expected error for NXDOMAIN")
	}
	if res.RCode != "NXDOMAIN" {
		t.Errorf("rcode = %q, want NXDOMAIN", res.RCode)
	}
	if !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Errorf("error = %q, want it to mention NXDOMAIN", err)
	}
}

// TestLookupTimeoutRespectsTimeout is the core guarantee: our timeout is the
// authoritative deadline, not the stdlib's hidden 5s. A nameserver that never
// answers must fail at ~our timeout, far below 5s.
func TestStdlibResolverIPLiteral(t *testing.T) {
	r := &StdlibResolver{}
	res, err := r.Lookup(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(res.Addrs) != 1 || res.Addrs[0].Unmap().String() != "192.0.2.1" {
		t.Errorf("addrs = %v, want [192.0.2.1]", res.Addrs)
	}
	if res.Server != "system" {
		t.Errorf("server = %q, want system", res.Server)
	}
	// The stdlib resolver exposes no per-query observability.
	if res.RCode != "" || res.Attempts != 0 {
		t.Errorf("rcode=%q attempts=%d, want empty/0", res.RCode, res.Attempts)
	}
}

func TestLookupTimeoutRespectsTimeout(t *testing.T) {
	// A UDP socket that accepts (and drops) packets: it never replies.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	blackhole := pc.LocalAddr().String()

	const timeout = 150 * time.Millisecond
	r, err := New(Config{Servers: []string{blackhole}, Timeout: timeout, Attempts: 1})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	res, err := r.Lookup(context.Background(), "example.com")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("error = %q, want a timeout/deadline error", err)
	}
	if res.RCode != "" {
		t.Errorf("rcode = %q, want empty (no response)", res.RCode)
	}
	// Must complete near our timeout, and provably not at the stdlib's 5s.
	if elapsed < timeout/2 {
		t.Errorf("elapsed = %v, want >= %v", elapsed, timeout/2)
	}
	if elapsed > 3*time.Second {
		t.Errorf("elapsed = %v, want < 3s (must NOT be the stdlib 5s timeout)", elapsed)
	}
}
