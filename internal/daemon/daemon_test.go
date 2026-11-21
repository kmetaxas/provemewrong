package daemon

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"provemewrong/internal/dataset"
	"provemewrong/internal/probe"
)

func echoListener(t *testing.T) netip.AddrPort {
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
				buf := make([]byte, 64)
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

func TestOnce(t *testing.T) {
	dir := t.TempDir()
	laddr := echoListener(t)
	sink, err := dataset.NewSink(dir, "once", []dataset.Format{dataset.FormatCSV}, 8, 0)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Probe: probe.Config{
			Host:   "127.0.0.1",
			Port:   strconv.Itoa(int(laddr.Port())),
			Scheme: probe.SchemeTCP,
		},
		Interval: time.Second,
		Once:     true,
		Sink:     sink,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Run(ctx, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if sink.Rows() != 1 {
		t.Fatalf("rows = %d, want 1", sink.Rows())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.csv"))
	if len(files) != 1 {
		t.Fatalf("csv files = %d, want 1", len(files))
	}
	if _, err := os.Stat(files[0]); err != nil {
		t.Fatal(err)
	}
}

func TestStopOnCancel(t *testing.T) {
	dir := t.TempDir()
	laddr := echoListener(t)
	sink, err := dataset.NewSink(dir, "cancel", []dataset.Format{dataset.FormatCSV}, 4, 0)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Probe: probe.Config{
			Host:   "127.0.0.1",
			Port:   strconv.Itoa(int(laddr.Port())),
			Scheme: probe.SchemeTCP,
		},
		Interval: 20 * time.Millisecond,
		Sink:     sink,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if sink.Rows() < 2 {
		t.Fatalf("rows = %d, want >= 2", sink.Rows())
	}
}
