// Package daemon runs the probe loop: one test per interval against one
// endpoint, appending every result to a Sink. Intervals are anchored to the
// start of the previous test, so sampling stays evenly spaced; if a test
// takes longer than the interval, the next test starts immediately and never
// overlaps (overlapping probes would skew each other's timings).
package daemon

import (
	"context"
	"log"
	"math/rand/v2"
	"sync"
	"time"

	"provemewrong/internal/dataset"
	"provemewrong/internal/probe"
)

// Config configures one endpoint loop.
type Config struct {
	Probe    probe.Config
	Interval time.Duration
	Jitter   time.Duration // random extra delay in [0, Jitter) added to each interval
	Duration time.Duration // stop after this long; 0 = run forever
	Once     bool          // run a single test and stop
	Sink     *dataset.Sink
	Verbose  bool
}

// Run executes the probe loop until ctx is cancelled, Duration elapses, or
// Once completes. A test interrupted by cancellation is still recorded (its
// partial result carries the phase in which it was cut off).
func Run(ctx context.Context, cfg Config) error {
	p, err := probe.New(cfg.Probe)
	if err != nil {
		return err
	}

	logf := func(format string, args ...any) {
		if cfg.Verbose {
			log.Printf(format, args...)
		}
	}

	started := time.Now()
	next := time.Now()
	var testID int64
	for {
		testID++
		res := p.Run(ctx, testID)
		if err := cfg.Sink.Append(res); err != nil {
			return err
		}
		logf("%s:%s test=%d total=%.3fms dns=%.3fms tcp=%.3fms tls=%.3fms",
			res.Host, res.Port, res.TestID, ms(res.Total),
			res.DNSMS, lastAttempt(res).TCPMS, lastAttempt(res).TLSMS)

		if cfg.Once {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		if cfg.Duration > 0 && time.Since(started) >= cfg.Duration {
			return nil
		}

		delay := cfg.Interval
		if cfg.Jitter > 0 {
			delay += time.Duration(rand.Int64N(int64(cfg.Jitter)))
		}
		next = next.Add(delay)
		if wait := time.Until(next); wait > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
		} else {
			// Previous test overran the interval; don't queue up tests.
			next = time.Now().Add(delay)
		}
	}
}

func lastAttempt(res *probe.Result) probe.Attempt {
	if len(res.Attempts) == 0 {
		return probe.Attempt{}
	}
	return res.Attempts[len(res.Attempts)-1]
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// RunAll runs one Run per endpoint configuration in parallel. The first
// error cancels the rest; nil is returned on clean shutdown.
func RunAll(ctx context.Context, cfgs []Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, len(cfgs))
	for _, cfg := range cfgs {
		cfg := cfg
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Run(ctx, cfg); err != nil {
				errCh <- err
				cancel()
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err // first error; order undefined but any error is fatal
	}
	return nil
}
