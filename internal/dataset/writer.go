package dataset

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/csv"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/compress"
	"github.com/apache/arrow-go/v18/parquet/pqarrow"

	"provemewrong/internal/probe"
)

// Format is an output file format.
type Format string

const (
	FormatCSV     Format = "csv"
	FormatParquet Format = "parquet"
)

func ext(f Format) string { return string(f) }

// Sink accumulates probe.Result values and writes them to files in Dir.
// One Sink per endpoint; callers must not share a Sink across goroutines.
//
// Files are named <BaseName>-<UTC timestamp>-<seq>.<ext>. Rotation is
// size-based: once MaxFileSize bytes are exceeded (checked between batches),
// the current files are closed and a new set is opened.
type Sink struct {
	Dir         string
	BaseName    string
	Formats     []Format
	BatchSize   int
	MaxFileSize int64 // 0 = never rotate

	alloc memory.Allocator

	mu      sync.Mutex
	batch   *appender
	files   []*openFile
	seq     int
	closed  bool
	rows    int64
	lastErr error
}

type openFile struct {
	path string
	file *os.File
	cw   *countingWriter
	csv  *csv.Writer
	pq   *pqarrow.FileWriter
}

// NewSink validates the configuration and creates the output directory.
func NewSink(dir, base string, formats []Format, batchSize int, maxFileSize int64) (*Sink, error) {
	if len(formats) == 0 {
		return nil, fmt.Errorf("dataset: no output formats")
	}
	if batchSize <= 0 {
		return nil, fmt.Errorf("dataset: batch size must be > 0")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("dataset: create output dir: %w", err)
	}
	s := &Sink{
		Dir:         dir,
		BaseName:    sanitize(base),
		Formats:     formats,
		BatchSize:   batchSize,
		MaxFileSize: maxFileSize,
		alloc:       memory.NewGoAllocator(),
		batch:       newAppender(memory.NewGoAllocator(), Schema()),
	}
	return s, nil
}

// Append adds the rows produced by one probe.Result to the in-memory batch,
// flushing to disk when the batch is full.
func (s *Sink) Append(res *probe.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("dataset: append on closed sink")
	}
	if err := s.ensureFiles(); err != nil {
		return err
	}
	s.batch.appendResult(res)
	s.rows++
	if s.batch.n >= s.BatchSize {
		return s.flushLocked()
	}
	return nil
}

// Flush writes any pending rows to disk.
func (s *Sink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	return s.flushLocked()
}

// Close flushes pending rows and closes all output files.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.batch.n > 0 {
		if err := s.flushLocked(); err != nil {
			return err
		}
	}
	return s.closeFilesLocked()
}

// Rows returns the number of tests appended so far (rows = tests + extra
// failover attempts).
func (s *Sink) Rows() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows
}

func (s *Sink) ensureFiles() error {
	if len(s.files) > 0 {
		return nil
	}
	ts := time.Now().UTC().Format("20060102T150405")
	for _, f := range s.Formats {
		path := filepath.Join(s.Dir, fmt.Sprintf("%s-%s-%03d.%s", s.BaseName, ts, s.seq, ext(f)))
		of, err := openFileFor(path, f, s.alloc)
		if err != nil {
			_ = s.closeFilesLocked()
			return err
		}
		s.files = append(s.files, of)
	}
	s.seq++
	return nil
}

func (s *Sink) flushLocked() error {
	if s.batch.n == 0 {
		return nil
	}
	rec := s.batch.build()
	defer rec.Release()
	s.batch = newAppender(memory.NewGoAllocator(), Schema())

	// Write the batch to every open file before considering rotation so no
	// batch is ever split across two files.
	written := []*openFile{}
	for _, of := range s.files {
		if err := of.write(rec); err != nil {
			s.lastErr = err
			return err
		}
		written = append(written, of)
	}

	if s.MaxFileSize > 0 {
		rotating := false
		for _, of := range written {
			if of.cw.n >= s.MaxFileSize {
				rotating = true
			}
		}
		if rotating {
			// Close the rotated files but do not eagerly open the next set:
			// the next Append reopens lazily, so a run that ends right after
			// rotation never leaves an empty trailing file behind.
			if err := s.closeFilesLocked(); err != nil {
				s.lastErr = err
				return err
			}
		}
	}
	return nil
}

func (s *Sink) closeFilesLocked() error {
	var first error
	for _, of := range s.files {
		if err := of.close(); err != nil && first == nil {
			first = err
		}
	}
	s.files = nil
	return first
}

func openFileFor(path string, f Format, alloc memory.Allocator) (*openFile, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("dataset: create %s: %w", path, err)
	}
	of := &openFile{path: path, file: file, cw: &countingWriter{w: file}}
	switch f {
	case FormatCSV:
		of.csv = csv.NewWriter(of.cw, Schema(), csv.WithHeader(true))
	case FormatParquet:
		props := parquet.NewWriterProperties(
			parquet.WithCompression(compress.Codecs.Snappy),
			parquet.WithVersion(parquet.V2_LATEST),
		)
		of.pq, err = pqarrow.NewFileWriter(Schema(), of.cw, props, pqarrow.DefaultWriterProps())
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("dataset: parquet writer %s: %w", path, err)
		}
	default:
		_ = file.Close()
		return nil, fmt.Errorf("dataset: unknown format %q", f)
	}
	return of, nil
}

func (of *openFile) write(rec arrow.Record) error {
	switch {
	case of.csv != nil:
		if err := of.csv.Write(rec); err != nil {
			return fmt.Errorf("dataset: csv write %s: %w", of.path, err)
		}
	case of.pq != nil:
		if err := of.pq.Write(rec); err != nil {
			return fmt.Errorf("dataset: parquet write %s: %w", of.path, err)
		}
	}
	return nil
}

func (of *openFile) close() error {
	var first error
	if of.csv != nil {
		if err := of.csv.Flush(); err != nil && first == nil {
			first = fmt.Errorf("dataset: csv flush %s: %w", of.path, err)
		}
		if err := of.csv.Error(); err != nil && first == nil {
			first = fmt.Errorf("dataset: csv %s: %w", of.path, err)
		}
	}
	if of.pq != nil {
		if err := of.pq.Close(); err != nil && first == nil {
			first = fmt.Errorf("dataset: parquet close %s: %w", of.path, err)
		}
	}
	if err := of.file.Close(); err != nil && first == nil {
		first = fmt.Errorf("dataset: close %s: %w", of.path, err)
	}
	return first
}

// countingWriter tracks the number of bytes written.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// appender accumulates rows into Arrow builders.
type appender struct {
	mem memory.Allocator
	sc  *arrow.Schema
	n   int

	testID     *array.Int64Builder
	startedAt  *array.TimestampBuilder
	hostname   *array.StringBuilder
	port       *array.Int32Builder
	scheme     *array.StringBuilder
	attemptSeq *array.Int32Builder
	ip         *array.StringBuilder
	localAddr  *array.StringBuilder

	dnsMS       *array.Float64Builder
	dnsError    *array.StringBuilder
	resolvedIPs *array.StringBuilder
	dnsServer   *array.StringBuilder

	tcpMS  *array.Float64Builder
	tcpErr *array.StringBuilder

	tlsMS      *array.Float64Builder
	tlsErr     *array.StringBuilder
	tlsVersion *array.StringBuilder
	tlsCipher  *array.StringBuilder
	tlsALPN    *array.StringBuilder

	probeSent  *array.BooleanBuilder
	ttfbMS     *array.Float64Builder
	httpStatus *array.Int32Builder
	httpReadMS *array.Float64Builder
	probeErr   *array.StringBuilder

	closeMS  *array.Float64Builder
	closeErr *array.StringBuilder

	totalMS *array.Float64Builder
}

func newAppender(mem memory.Allocator, sc *arrow.Schema) *appender {
	ts := &arrow.TimestampType{Unit: arrow.Nanosecond}
	return &appender{
		mem: mem, sc: sc,
		testID:      array.NewInt64Builder(mem),
		startedAt:   array.NewTimestampBuilder(mem, ts),
		hostname:    array.NewStringBuilder(mem),
		port:        array.NewInt32Builder(mem),
		scheme:      array.NewStringBuilder(mem),
		attemptSeq:  array.NewInt32Builder(mem),
		ip:          array.NewStringBuilder(mem),
		localAddr:   array.NewStringBuilder(mem),
		dnsMS:       array.NewFloat64Builder(mem),
		dnsError:    array.NewStringBuilder(mem),
		resolvedIPs: array.NewStringBuilder(mem),
		dnsServer:   array.NewStringBuilder(mem),
		tcpMS:       array.NewFloat64Builder(mem),
		tcpErr:      array.NewStringBuilder(mem),
		tlsMS:       array.NewFloat64Builder(mem),
		tlsErr:      array.NewStringBuilder(mem),
		tlsVersion:  array.NewStringBuilder(mem),
		tlsCipher:   array.NewStringBuilder(mem),
		tlsALPN:     array.NewStringBuilder(mem),
		probeSent:   array.NewBooleanBuilder(mem),
		ttfbMS:      array.NewFloat64Builder(mem),
		httpStatus:  array.NewInt32Builder(mem),
		httpReadMS:  array.NewFloat64Builder(mem),
		probeErr:    array.NewStringBuilder(mem),
		closeMS:     array.NewFloat64Builder(mem),
		closeErr:    array.NewStringBuilder(mem),
		totalMS:     array.NewFloat64Builder(mem),
	}
}

func (a *appender) appendResult(res *probe.Result) {
	port, _ := strconv.Atoi(res.Port)
	total := float64(res.Total) / float64(time.Millisecond)
	startedAt := arrow.Timestamp(res.StartedAt.UnixNano())

	var resolved []string
	for _, ip := range res.ResolvedIPs {
		resolved = append(resolved, ip.String())
	}
	resolvedStr := strings.Join(resolved, ",")

	dnsStr := ""
	if res.DNSServer != "" {
		dnsStr = res.DNSServer
	} else if res.DNSRan {
		dnsStr = "system"
	}

	rows := res.Attempts
	if len(rows) == 0 {
		// DNS failure (or empty resolution): emit one row with no attempt data.
		a.appendRow(startedAt, total, res, dnsStr, resolvedStr, nil, port)
		return
	}
	for i := range rows {
		a.appendRow(startedAt, total, res, dnsStr, resolvedStr, &rows[i], port)
	}
}

func (a *appender) appendRow(startedAt arrow.Timestamp, total float64, res *probe.Result, dnsStr, resolvedStr string, att *probe.Attempt, port int) {
	base := []array.Builder{
		a.testID, a.startedAt, a.hostname, a.port, a.scheme, a.attemptSeq,
		a.ip, a.localAddr, a.dnsMS, a.dnsError, a.resolvedIPs, a.dnsServer,
		a.tcpMS, a.tcpErr, a.tlsMS, a.tlsErr, a.tlsVersion, a.tlsCipher,
		a.tlsALPN, a.probeSent, a.ttfbMS, a.httpStatus, a.httpReadMS,
		a.probeErr, a.closeMS, a.closeErr, a.totalMS,
	}
	if len(base) != len(a.sc.Fields()) {
		panic("dataset: appender field mismatch")
	}

	a.testID.Append(res.TestID)
	a.startedAt.Append(startedAt)
	a.hostname.Append(res.Host)
	a.port.Append(int32(port))
	a.scheme.Append(string(res.Scheme))
	a.dnsServer.Append(dnsStr)
	a.totalMS.Append(total)

	if res.DNSRan {
		a.dnsMS.Append(res.DNSMS)
		if res.DNSError != "" {
			a.dnsError.Append(res.DNSError)
		} else {
			a.dnsError.AppendNull()
		}
	} else {
		a.dnsMS.AppendNull()
		a.dnsError.AppendNull()
	}
	if resolvedStr != "" {
		a.resolvedIPs.Append(resolvedStr)
	} else {
		a.resolvedIPs.AppendNull()
	}

	if att == nil {
		a.attemptSeq.Append(0)
		a.ip.AppendNull()
		a.localAddr.AppendNull()
		a.tcpMS.AppendNull()
		a.tcpErr.AppendNull()
		a.tlsMS.AppendNull()
		a.tlsErr.AppendNull()
		a.tlsVersion.AppendNull()
		a.tlsCipher.AppendNull()
		a.tlsALPN.AppendNull()
		a.probeSent.Append(false)
		a.ttfbMS.AppendNull()
		a.httpStatus.AppendNull()
		a.httpReadMS.AppendNull()
		a.probeErr.AppendNull()
		a.closeMS.AppendNull()
		a.closeErr.AppendNull()
		a.n++
		return
	}

	a.attemptSeq.Append(int32(att.Seq))
	if att.IP.IsValid() {
		a.ip.Append(att.IP.String())
	} else {
		a.ip.AppendNull()
	}
	if att.LocalAddr != "" {
		a.localAddr.Append(att.LocalAddr)
	} else {
		a.localAddr.AppendNull()
	}

	appendDur := func(b *array.Float64Builder, ran bool, v float64) {
		if ran {
			b.Append(v)
		} else {
			b.AppendNull()
		}
	}
	appendStr := func(b *array.StringBuilder, s string) {
		if s != "" {
			b.Append(s)
		} else {
			b.AppendNull()
		}
	}

	appendDur(a.tcpMS, true, att.TCPMS)
	appendStr(a.tcpErr, att.TCPError)

	ranTLS := att.TLSError != "" || att.TLSMS > 0 || att.TLSVersion != ""
	appendDur(a.tlsMS, ranTLS, att.TLSMS)
	appendStr(a.tlsErr, att.TLSError)
	appendStr(a.tlsVersion, att.TLSVersion)
	appendStr(a.tlsCipher, att.TLSCipher)
	appendStr(a.tlsALPN, att.TLSALPN)

	a.probeSent.Append(att.ProbeSent)
	appendDur(a.ttfbMS, att.ProbeSent, att.TTFBMS)
	if att.ProbeSent && att.HTTPStatus > 0 {
		a.httpStatus.Append(int32(att.HTTPStatus))
	} else {
		a.httpStatus.AppendNull()
	}
	appendDur(a.httpReadMS, att.ProbeSent && att.HTTPReadMS > 0, att.HTTPReadMS)
	appendStr(a.probeErr, att.ProbeError)

	appendDur(a.closeMS, att.Closed, att.CloseMS)
	appendStr(a.closeErr, att.CloseError)
	a.n++
}

// build materializes the current batch as a Record and resets all builders.
func (a *appender) build() arrow.Record {
	arrays := []arrow.Array{
		a.testID.NewArray(), a.startedAt.NewArray(), a.hostname.NewArray(),
		a.port.NewArray(), a.scheme.NewArray(), a.attemptSeq.NewArray(),
		a.ip.NewArray(), a.localAddr.NewArray(), a.dnsMS.NewArray(),
		a.dnsError.NewArray(), a.resolvedIPs.NewArray(), a.dnsServer.NewArray(),
		a.tcpMS.NewArray(), a.tcpErr.NewArray(), a.tlsMS.NewArray(),
		a.tlsErr.NewArray(), a.tlsVersion.NewArray(), a.tlsCipher.NewArray(),
		a.tlsALPN.NewArray(), a.probeSent.NewArray(), a.ttfbMS.NewArray(),
		a.httpStatus.NewArray(), a.httpReadMS.NewArray(), a.probeErr.NewArray(),
		a.closeMS.NewArray(), a.closeErr.NewArray(), a.totalMS.NewArray(),
	}
	rec := array.NewRecord(a.sc, arrays, int64(a.n))
	a.n = 0
	return rec
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}
