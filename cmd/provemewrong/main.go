// Command provemewrong continuously probes TCP/TLS endpoints, measures each
// connection phase with strict separation (DNS ≠ TCP ≠ TLS), and writes a
// CSV/Parquet dataset for offline analysis.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"

	"provemewrong/internal/daemon"
	"provemewrong/internal/dataset"
	"provemewrong/internal/probe"
)

// version is overridable via -ldflags "-X main.version=...".
var version = "0.1.0"

var cli struct {
	Endpoints []string      `name:"endpoint" help:"Endpoint to monitor: [tcp://|tls://]HOST:PORT. Repeatable and comma-separable."`
	Scheme    string        `help:"Default scheme when an endpoint has no scheme prefix" enum:"tcp,tls" default:"tls"`
	HTTP      bool          `help:"After connect/handshake send an HTTP/1.1 HEAD request; measures ttfb_ms, http_read_ms and http_status"`
	Interval  time.Duration `help:"Time between tests per endpoint" default:"1s"`
	Jitter    time.Duration `help:"Random extra delay in [0,J) added to each interval (avoids lockstep sampling)" default:"0"`
	Duration  time.Duration `help:"Stop after this long (0 = run until stopped)" default:"0"`
	Once      bool          `help:"Run one test per endpoint and exit (cron-friendly)"`

	OutputDir   string   `name:"output" help:"Directory for dataset files" default:"./data" type:"path"`
	Format      []string `help:"Output format(s); may be given multiple times" enum:"csv,parquet" default:"csv"`
	BatchSize   int      `help:"Rows buffered in memory before flushing to disk" default:"256"`
	MaxFileSize int64    `help:"Rotate the output file after this many bytes (0 = never rotate)" default:"0"`

	DNSServer  string `help:"Send DNS queries to this server (host[:port]) instead of the system resolver"`
	Family     string `help:"IP family to connect over" enum:"any,v4,v6" default:"any"`
	ServerName string `help:"TLS SNI override (default: the endpoint host)"`
	Insecure   bool   `help:"Skip TLS certificate verification (diagnostics only)"`

	DNSTimeout     time.Duration `help:"Per-test DNS resolution budget" default:"3s"`
	ConnectTimeout time.Duration `help:"Per-attempt TCP connect budget" default:"3s"`
	TLSTimeout     time.Duration `help:"Per-attempt TLS handshake budget" default:"5s"`
	ProbeTimeout   time.Duration `help:"HTTP probe read/write budget" default:"10s"`
	TestTimeout    time.Duration `help:"Total budget for one test" default:"20s"`

	Verbose bool `help:"Log every test to stderr"`
	Version bool `help:"Print version and exit"`
}

type endpoint struct {
	host, port string
	scheme     probe.Scheme
}

func parseEndpoint(s string, defaultScheme probe.Scheme) (endpoint, error) {
	scheme := defaultScheme
	rest := s
	if i := strings.Index(s, "://"); i >= 0 {
		switch strings.ToLower(s[:i]) {
		case "tcp":
			scheme = probe.SchemeTCP
		case "tls", "https":
			scheme = probe.SchemeTLS
		default:
			return endpoint{}, fmt.Errorf("endpoint %q: unknown scheme %q", s, s[:i])
		}
		rest = s[i+3:]
	}
	host, port, err := net.SplitHostPort(rest)
	if err != nil {
		return endpoint{}, fmt.Errorf("endpoint %q: expected HOST:PORT: %w", s, err)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return endpoint{}, fmt.Errorf("endpoint %q: port %q is not numeric", s, port)
	}
	return endpoint{host: host, port: port, scheme: scheme}, nil
}

func main() {
	kong.Parse(&cli,
		kong.Name("provemewrong"),
		kong.Description("Continuously probe TCP/TLS endpoints and record per-phase timing datasets (DNS, TCP connect, TLS handshake, TTFB, close) to CSV/Parquet."),
		kong.UsageOnError(),
	)
	if cli.Version {
		fmt.Println("provemewrong", version)
		return
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	defaultScheme := probe.Scheme(cli.Scheme)

	var endpoints []endpoint
	for _, arg := range cli.Endpoints {
		for _, part := range strings.Split(arg, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			ep, err := parseEndpoint(part, defaultScheme)
			if err != nil {
				log.Fatalf("error: %v", err)
			}
			endpoints = append(endpoints, ep)
		}
	}
	if len(endpoints) == 0 {
		log.Fatal("error: no endpoints given")
	}

	var formats []dataset.Format
	for _, f := range cli.Format {
		formats = append(formats, dataset.Format(f))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var cfgs []daemon.Config
	var sinks []*dataset.Sink
	for _, ep := range endpoints {
		sink, err := dataset.NewSink(
			cli.OutputDir,
			fmt.Sprintf("provemewrong-%s_%s_%s", ep.scheme, ep.host, ep.port),
			formats, cli.BatchSize, cli.MaxFileSize)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		sinks = append(sinks, sink)
		cfgs = append(cfgs, daemon.Config{
			Probe: probe.Config{
				Host:       ep.host,
				Port:       ep.port,
				Scheme:     ep.scheme,
				ServerName: cli.ServerName,
				Insecure:   cli.Insecure,
				Family:     cli.Family,
				HTTP:       cli.HTTP,
				DNSServer:  cli.DNSServer,
				Timeouts: probe.Timeouts{
					DNS:     cli.DNSTimeout,
					Connect: cli.ConnectTimeout,
					TLS:     cli.TLSTimeout,
					Probe:   cli.ProbeTimeout,
					Test:    cli.TestTimeout,
				},
			},
			Interval: cli.Interval,
			Jitter:   cli.Jitter,
			Duration: cli.Duration,
			Once:     cli.Once,
			Sink:     sink,
			Verbose:  cli.Verbose,
		})
		log.Printf("monitoring %s://%s:%s -> %s (%s)",
			ep.scheme, ep.host, ep.port, cli.OutputDir, strings.Join(cli.Format, "+"))
	}

	err := daemon.RunAll(ctx, cfgs)
	for _, s := range sinks {
		if cerr := s.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	log.Print("shutdown complete")
}
