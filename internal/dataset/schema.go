// Package dataset turns probe.Result values into an Arrow-backed, disk-flushed
// dataset (CSV and/or Parquet).
//
// Memory management: rows are appended into Arrow builders and only one
// record batch (BatchSize rows) is held in memory at a time; each batch is
// written to disk and the buffers are reset. This keeps RAM usage bounded
// regardless of how long the daemon runs.
package dataset

import (
	"github.com/apache/arrow-go/v18/arrow"
)

// Schema returns the canonical Arrow schema of the dataset. It is flat and
// Pandas-friendly: one row per connection attempt (one test usually produces
// one row; multi-IP failover produces one row per dialed IP).
func Schema() *arrow.Schema {
	fields := []arrow.Field{
		{Name: "test_id", Type: arrow.PrimitiveTypes.Int64, Nullable: false},
		{Name: "started_at", Type: &arrow.TimestampType{Unit: arrow.Nanosecond}, Nullable: false},
		{Name: "hostname", Type: arrow.BinaryTypes.String, Nullable: false},
		{Name: "port", Type: arrow.PrimitiveTypes.Int32, Nullable: false},
		{Name: "scheme", Type: arrow.BinaryTypes.String, Nullable: false},
		{Name: "attempt_seq", Type: arrow.PrimitiveTypes.Int32, Nullable: false},
		{Name: "ip", Type: arrow.BinaryTypes.String, Nullable: true},
		{Name: "local_addr", Type: arrow.BinaryTypes.String, Nullable: true},

		{Name: "dns_ms", Type: arrow.PrimitiveTypes.Float64, Nullable: true},
		{Name: "dns_error", Type: arrow.BinaryTypes.String, Nullable: true},
		{Name: "resolved_ips", Type: arrow.BinaryTypes.String, Nullable: true},
		{Name: "dns_server", Type: arrow.BinaryTypes.String, Nullable: true},
		{Name: "dns_rcode", Type: arrow.BinaryTypes.String, Nullable: true},
		{Name: "dns_attempts", Type: arrow.PrimitiveTypes.Int32, Nullable: true},

		{Name: "tcp_connect_ms", Type: arrow.PrimitiveTypes.Float64, Nullable: true},
		{Name: "tcp_error", Type: arrow.BinaryTypes.String, Nullable: true},

		{Name: "tls_handshake_ms", Type: arrow.PrimitiveTypes.Float64, Nullable: true},
		{Name: "tls_error", Type: arrow.BinaryTypes.String, Nullable: true},
		{Name: "tls_version", Type: arrow.BinaryTypes.String, Nullable: true},
		{Name: "tls_cipher", Type: arrow.BinaryTypes.String, Nullable: true},
		{Name: "tls_alpn", Type: arrow.BinaryTypes.String, Nullable: true},

		{Name: "probe_sent", Type: arrow.FixedWidthTypes.Boolean, Nullable: false},
		{Name: "ttfb_ms", Type: arrow.PrimitiveTypes.Float64, Nullable: true},
		{Name: "http_status", Type: arrow.PrimitiveTypes.Int32, Nullable: true},
		{Name: "http_read_ms", Type: arrow.PrimitiveTypes.Float64, Nullable: true},
		{Name: "probe_error", Type: arrow.BinaryTypes.String, Nullable: true},

		{Name: "close_ms", Type: arrow.PrimitiveTypes.Float64, Nullable: true},
		{Name: "close_error", Type: arrow.BinaryTypes.String, Nullable: true},

		{Name: "total_ms", Type: arrow.PrimitiveTypes.Float64, Nullable: false},
	}
	return arrow.NewSchema(fields, nil)
}
