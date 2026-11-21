package dataset

import (
	"context"
	"encoding/csv"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet/file"
	"github.com/apache/arrow-go/v18/parquet/pqarrow"

	"provemewrong/internal/probe"
)

func fakeResult(id int64, attemptCount int) *probe.Result {
	res := &probe.Result{
		TestID:      id,
		StartedAt:   time.Date(2026, 11, 21, 12, 0, 0, int(id), time.UTC),
		Host:        "example.com",
		Port:        "443",
		Scheme:      probe.SchemeTLS,
		DNSServer:   "system",
		DNSRan:      true,
		DNSMS:       12.5,
		ResolvedIPs: []netip.Addr{netipAddr("93.184.216.34")},
		Total:       55 * time.Millisecond,
	}
	for i := 0; i < attemptCount; i++ {
		res.Attempts = append(res.Attempts, probe.Attempt{
			Seq:        i + 1,
			IP:         netipAddr("93.184.216.34"),
			TCPMS:      8.1,
			TLSMS:      30.2,
			TLSVersion: "TLS 1.3",
			TLSCipher:  "TLS_AES_128_GCM_SHA256",
			TLSALPN:    "h2",
			ProbeSent:  true,
			TTFBMS:     10.4,
			HTTPStatus: 200,
			HTTPReadMS: 12.0,
			LocalAddr:  "10.0.0.5:54321",
			Closed:     true,
			CloseMS:    0.4,
		})
	}
	return res
}

func netipAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func csvFiles(dir string) []string {
	fs, _ := filepath.Glob(filepath.Join(dir, "*.csv"))
	return fs
}

func TestSinkCSV(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewSink(dir, "test_example.com_443", []Format{FormatCSV}, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 3; i++ {
		if err := sink.Append(fakeResult(i, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	files := csvFiles(dir)
	if len(files) != 1 {
		t.Fatalf("csv files = %d, want 1", len(files))
	}
	f, err := os.Open(files[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	// header + 3 rows
	if len(records) != 4 {
		t.Fatalf("records = %d, want 4 (header + 3 rows)", len(records))
	}
	header := records[0]
	if len(header) != len(Schema().Fields()) {
		t.Fatalf("header cols = %d, want %d", len(header), len(Schema().Fields()))
	}
	idx := func(name string) int {
		for i, h := range header {
			if h == name {
				return i
			}
		}
		t.Fatalf("missing column %q", name)
		return -1
	}
	if got := records[1][idx("hostname")]; got != "example.com" {
		t.Errorf("hostname = %q", got)
	}
	if got := records[1][idx("dns_ms")]; got != "12.5" {
		t.Errorf("dns_ms = %q, want 12.5", got)
	}
	if got := records[1][idx("tcp_connect_ms")]; got != "8.1" {
		t.Errorf("tcp_connect_ms = %q", got)
	}
	if got := records[1][idx("http_status")]; got != "200" {
		t.Errorf("http_status = %q", got)
	}
	if got := records[1][idx("test_id")]; got != "1" {
		t.Errorf("test_id = %q", got)
	}
}

func TestSinkParquetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewSink(dir, "test_example.com_443", []Format{FormatParquet}, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 5; i++ {
		if err := sink.Append(fakeResult(i, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.parquet"))
	if len(files) != 1 {
		t.Fatalf("parquet files = %d, want 1", len(files))
	}
	rdr, err := file.OpenParquetFile(files[0], false)
	if err != nil {
		t.Fatal(err)
	}
	defer rdr.Close()
	fr, err := pqarrow.NewFileReader(rdr, pqarrow.ArrowReadProperties{}, memory.NewGoAllocator())
	if err != nil {
		t.Fatal(err)
	}
	table, err := fr.ReadTable(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer table.Release()
	if table.NumRows() != 5 {
		t.Fatalf("rows = %d, want 5", table.NumRows())
	}
	if table.NumCols() != int64(len(Schema().Fields())) {
		t.Fatalf("cols = %d, want %d", table.NumCols(), len(Schema().Fields()))
	}
}

func TestSinkRotation(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewSink(dir, "test_example.com_443", []Format{FormatCSV}, 2, 512)
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 10; i++ {
		if err := sink.Append(fakeResult(i, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	files := csvFiles(dir)
	if len(files) < 2 {
		t.Fatalf("files = %d, want >= 2 (rotation)", len(files))
	}
	total := 0
	for _, fp := range files {
		f, err := os.Open(fp)
		if err != nil {
			t.Fatal(err)
		}
		r := csv.NewReader(f)
		records, err := r.ReadAll()
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		total += len(records) - 1
	}
	if total != 10 {
		t.Fatalf("rows across files = %d, want 10", total)
	}
}

func TestSinkDNSFailureRow(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewSink(dir, "test_example.com_443", []Format{FormatCSV}, 8, 0)
	if err != nil {
		t.Fatal(err)
	}
	res := fakeResult(1, 1)
	res.DNSRan = true
	res.DNSError = "no such host"
	res.ResolvedIPs = nil
	res.Attempts = nil
	if err := sink.Append(res); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(csvFiles(dir)[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	row := records[1]
	if row[0] != "1" || row[5] != "0" {
		t.Errorf("row = %v, want test_id=1 attempt_seq=0", row[:6])
	}
	if row[9] != "no such host" {
		t.Errorf("dns_error = %q", row[9])
	}
	// tcp_connect_ms must be null -> CSV writes "NULL" (pandas maps it to NaN)
	if row[12] != "NULL" {
		t.Errorf("tcp_connect_ms = %q, want NULL", row[12])
	}
	// dns_ms must be present even on failure (resolution was attempted)
	if _, err := strconv.ParseFloat(row[8], 64); err != nil {
		t.Errorf("dns_ms = %q not a float", row[8])
	}
}
