# provemewrong

A Go daemon that continuously probes TCP/TLS endpoints, measures every phase of
a connection with strict separation, and writes high-quality datasets
(CSV / Parquet) for offline analysis in Pandas or any other tool.

Built to answer one question: *when latency spikes from 20–30 ms to 5–10 s,
which phase is responsible?*

## What it measures

Every test performs these steps and times each one **in isolation**:

| Phase | Column | What is included |
|---|---|---|
| DNS resolution | `dns_ms` | Only `LookupNetIP` — nothing else |
| TCP connect | `tcp_connect_ms` | Only SYN/SYN-ACK. The dial targets the already-resolved IP literal, so DNS time can never leak in |
| TLS handshake | `tls_handshake_ms` | Only the TLS handshake over an established TCP connection |
| Time to first byte | `ttfb_ms` | From HTTP HEAD request write start to the first response byte |
| HTTP read | `http_read_ms` | Until end of response |
| Close | `close_ms` | Only `conn.Close()` |
| Whole test | `total_ms` | Wall clock, all phases plus gaps |

Phase separation is enforced by construction: resolution happens first and is
timed alone; the dial is made to an IP (not a hostname); the TLS handshake runs
over the already-connected socket. Each phase has its own timeout
(`--dns-timeout`, `--connect-timeout`, `--tls-timeout`, `--probe-timeout`), so
a slow phase is *recorded*, not silently truncated into another phase's number.

### Why this helps find "random" latency

A 5–10 s spike almost always comes from one phase timing out or retrying.
Because every phase is a separate column with a typed error column
(`dns_error`, `tcp_error`, `tls_error`, `probe_error`), a spike is directly
attributable:

- `dns_ms` high → resolver slowness, failing DNS servers, retries
  (use `--dns-server` to pin a resolver and remove the system cache from the equation)
- `tcp_connect_ms` high → SYN retransmits (packet loss, SYN backlog on the server)
- `tls_handshake_ms` high → CPU-bound server, OCSP/CRL stalls, MTU issues
- `ttfb_ms` high while `tcp_connect_ms` is low → the application is slow, not the network

Each row also carries `started_at`, `local_addr`, the resolved/selected IP, and
the negotiated TLS version/cipher/ALPN, so results can be correlated with
system events (deploys, ephemeral port exhaustion, DNS changes).

## Output schema

One row per connection attempt (a multi-IP failover test emits one row per
dialed IP; DNS columns repeat per attempt). All columns:

```
test_id, started_at, hostname, port, scheme, attempt_seq, ip, local_addr,
dns_ms, dns_error, resolved_ips, dns_server, dns_rcode, dns_attempts,
tcp_connect_ms, tcp_error,
tls_handshake_ms, tls_error, tls_version, tls_cipher, tls_alpn,
probe_sent, ttfb_ms, http_status, http_read_ms, probe_error,
close_ms, close_error, total_ms
```

Durations are fractional milliseconds. CSV nulls are written as `NULL`
(Pandas' default `na_values` already maps them to NaN).

## Usage

```console
$ go build -o provemewrong ./cmd/provemewrong

# one-shot test against an HTTPS endpoint, CSV + Parquet:
$ ./provemewrong --once --http --endpoint example.com:443 \
    --format csv --format parquet --output ./data

# run as a daemon: probe every 2s, forever, two endpoints:
$ ./provemewrong --endpoint tls://api.example.com:443,tcp://db.internal:5432 \
    --interval 2s --output ./data

# cron-friendly sampling, one test per invocation:
$ ./provemewrong --once --endpoint api.example.com:443 --output ./data
```

### Flags (all configuration is via flags — no config file)

| Flag | Default | Meaning |
|---|---|---|
| `--endpoint` | *(required)* | `[tcp://\|tls://]HOST:PORT`, repeatable/comma-separable |
| `--scheme` | `tls` | Default scheme for endpoints without a prefix |
| `--http` | off | Send an HTTP HEAD probe; measures `ttfb_ms`, `http_status`, `http_read_ms` |
| `--interval` | `1s` | Time between tests per endpoint |
| `--jitter` | `0` | Random extra delay in `[0,J)` added to each interval |
| `--duration` | `0` | Stop after this long (`0` = run until stopped) |
| `--once` | off | Run one test per endpoint and exit |
| `--output` | `./data` | Dataset directory |
| `--format` | `csv` | `csv`, `parquet`, or both (repeat the flag) |
| `--batch-size` | `256` | Rows buffered in RAM before flushing to disk |
| `--max-file-size` | `0` | Rotate the file after this many bytes (`0` = never) |
| `--dns-server` | `/etc/resolv.conf` | Pin DNS queries to `host[:port]` instead of the system nameservers |
| `--dns-attempts` | `1` | DNS query rounds before giving up (`1` = no retry); `dnsx` only |
| `--dns-tcp` | off | Send DNS queries over TCP only; `dnsx` only (default: UDP) |
| `--resolver` | `dnsx` | `dnsx` (controlled, observable) or `system` (Go stdlib) |
| `--family` | `any` | `any`, `v4`, `v6` |
| `--server-name` | endpoint host | TLS SNI override |
| `--insecure` | off | Skip TLS certificate verification (diagnostics only) |
| `--dns-timeout` | `3s` | Per-query DNS deadline (applied directly; no hidden resolver timeout) |
| `--connect-timeout` | `3s` | Per-attempt TCP connect budget |
| `--tls-timeout` | `5s` | Per-attempt TLS handshake budget |
| `--probe-timeout` | `10s` | HTTP probe read/write budget |
| `--test-timeout` | `20s` | Total budget for one test |

Run with a systemd unit or any supervisor — the binary *is* the daemon. It
flushes buffered rows on `SIGINT`/`SIGTERM` and exits cleanly.

## Analyzing the data

```python
import pandas as pd

df = pd.read_csv("data/provemewrong-tls_example_com_443-*.csv", parse_dates=["started_at"])

# Which phase is responsible for the worst 1% of tests?
phases = ["dns_ms", "tcp_connect_ms", "tls_handshake_ms", "ttfb_ms", "close_ms"]
df[phases].quantile([0.5, 0.9, 0.99, 1.0])

# When does total_ms spike, and which phase moves with it?
spikes = df[df.total_ms > 500].describe()

# Errors over time
df.groupby(df.started_at.dt.minute)[["tcp_error", "tls_error", "probe_error"]].count()
```

Parquet files can be read directly with `pandas.read_parquet()` or DuckDB.

## Design notes

- **RAM is bounded**: rows accumulate in Arrow builders and only one record
  batch (`--batch-size` rows) exists in memory at a time; batches flush to
  disk and their buffers are released. File size caps rotate output files.
- **No self-interference**: each endpoint probes on its own goroutine, and a
  test that overruns its interval is never overlapped with the next one —
  overlapping probes would skew each other's timings.
- **Single binary**: all configuration is CLI flags, no config file.

### DNS resolution

DNS is resolved by our own resolver (`internal/dnsx`), not the Go standard
library's, for one reason: the stdlib resolver imposes its own internal
per-query timeout — hardcoded 5s, overridable only via `/etc/resolv.conf`
`options timeout:N` — plus a 2-attempt retry, neither exposed through its API.
A caller's context deadline is intersected with that hidden 5s, so a
non-answering nameserver always shows a ~5s "timeout" no matter what you asked
for. That makes the standard resolver useless for measuring DNS latency.

`dnsx` sends queries directly with an explicit deadline equal to
`--dns-timeout` and `--dns-attempts` rounds (default 1, no silent retry). It
also records the nameserver that answered (`dns_server`), the response code
(`dns_rcode`: `NOERROR`/`SERVFAIL`/`NXDOMAIN`/…), and the attempt count, so a
slow lookup is attributable to either a real slow response or a genuine
timeout at the deadline you chose.

Queries use UDP by default (with an EDNS0 buffer of 4096 bytes to accommodate
larger responses). There is **no automatic TCP fallback on truncation**, so on
networks that drop or rate-limit UDP, a query simply times out. Use
`--dns-tcp` to send queries over TCP only and confirm whether UDP packet loss
is the culprit.

`--resolver system` switches back to the Go standard library resolver for A/B
comparison or when you need its `/etc/hosts` and search-domain handling. In
that mode `dns_server` reports `system`, `dns_rcode`/`dns_attempts` are null
(no observability), and the stdlib's own hidden 5s timeout applies again.

Two caveats, both deliberate for a probe tool: `/etc/hosts` and search domains
are *not* consulted, and no DNS caching is performed — every test issues a
fresh query. Nameservers default to `/etc/resolv.conf`; use `--dns-server` to
pin one.

Note: if you still see ~5s timeouts after this change, they are coming from
*your* nameserver (e.g. `127.0.0.1:53` shown in `dns_server` — typically
systemd-resolved or dnsmasq) timing out upstream, not from our code. That is
exactly the distinction `dns_server` + `dns_rcode` let you make.

## Development

```console
$ go test ./...          # unit + integration tests (local TLS servers)
$ go test -race ./...
```

## Roadmap

- ICMP ping RTT and TTL/hop observation alongside TCP probes
- HTTP probe verb/method configuration and response-size caps
- DNS over TCP fallback metrics and EDNS0/truncation reporting
