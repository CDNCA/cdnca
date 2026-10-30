package eventspool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	benchmarkTenantID = "11111111-1111-4111-8111-111111111111"
	benchmarkSiteID   = "33333333-3333-4333-8333-333333333333"
	benchmarkNodeID   = "44444444-4444-4444-8444-444444444444"
)

func BenchmarkTelemetryTransport(b *testing.B) {
	source := os.Getenv("CDNCA_TELEMETRY_BENCH_SOURCE")
	if source == "" {
		b.Skip("set CDNCA_TELEMETRY_BENCH_SOURCE to a real OpenResty JSONL log")
	}
	payload, err := os.ReadFile(source)
	if err != nil {
		b.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(payload, []byte{'\n'}), []byte{'\n'})
	if len(lines) < 1000 {
		b.Fatalf("benchmark source has %d events; require at least 1000 real OpenResty events", len(lines))
	}
	identity := TrustedIdentity{
		EnrollmentNodeID: benchmarkNodeID,
		TenantID:         benchmarkTenantID,
		SiteID:           benchmarkSiteID,
		ConfigVersionID:  "55555555-5555-4555-8555-555555555555",
	}
	for _, line := range lines {
		if _, err := ParseSourceLineBound(line, CapturePolicy{}, identity); err != nil {
			b.Fatalf("benchmark source is not a valid OpenResty event: %v", err)
		}
	}

	b.Run("file_tail_durable", func(b *testing.B) {
		benchmarkFileTail(b, payload, len(lines), identity)
	})
	b.Run("unix_dgram_durable", func(b *testing.B) {
		benchmarkUnixDatagram(b, lines, identity)
	})
}

func benchmarkFileTail(b *testing.B, payload []byte, events int, identity TrustedIdentity) {
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	started := time.Now()
	for iteration := 0; iteration < b.N; iteration++ {
		root := benchmarkRoot(b, "file")
		source := filepath.Join(root, "access.jsonl")
		if err := os.WriteFile(source, payload, 0o600); err != nil {
			b.Fatal(err)
		}
		spool := benchmarkSpool(b, filepath.Join(root, "spool"))
		tailer, err := NewTailer(TailConfig{
			SourcePath: source, StateDir: filepath.Join(root, "tail-state"), Identity: identity,
			MaxLineBytes: 1 << 20, MaxBatchEvents: 256, MaxQuarantineBytes: 64 << 20,
		})
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		result, err := tailer.TailOnce(context.Background(), spool)
		b.StopTimer()
		if err != nil || result.AppendedEvents != events || result.DuplicateEvents != 0 {
			b.Fatalf("file tail result=%#v error=%v", result, err)
		}
	}
	reportTransportMetrics(b, len(payload)*b.N, events*b.N, time.Since(started))
}

func benchmarkUnixDatagram(b *testing.B, lines [][]byte, identity TrustedIdentity) {
	b.ReportAllocs()
	totalBytes := 0
	for _, line := range lines {
		totalBytes += len(line)
	}
	b.SetBytes(int64(totalBytes))
	started := time.Now()
	for iteration := 0; iteration < b.N; iteration++ {
		root := benchmarkRoot(b, "unix-dgram")
		spool := benchmarkSpool(b, filepath.Join(root, "spool"))
		socketPath := filepath.Join(root, "collector.sock")
		listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socketPath, Net: "unixgram"})
		if err != nil {
			b.Fatal(err)
		}
		sender, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socketPath, Net: "unixgram"})
		if err != nil {
			_ = listener.Close()
			b.Fatal(err)
		}
		_ = listener.SetReadBuffer(4 << 20)
		_ = sender.SetWriteBuffer(4 << 20)
		deadline := time.Now().Add(10 * time.Second)
		_ = listener.SetReadDeadline(deadline)
		_ = sender.SetWriteDeadline(deadline)
		sendError := make(chan error, 1)
		b.StartTimer()
		go func() {
			for _, line := range lines {
				if _, err := sender.Write(line); err != nil {
					sendError <- err
					return
				}
			}
			sendError <- nil
		}()
		appended, receiveErr := receiveDatagrams(listener, spool, lines, identity)
		senderErr := <-sendError
		b.StopTimer()
		_ = sender.Close()
		_ = listener.Close()
		if receiveErr != nil || senderErr != nil || appended != len(lines) {
			b.Fatalf("unix datagram appended=%d receive_error=%v send_error=%v", appended, receiveErr, senderErr)
		}
	}
	reportTransportMetrics(b, totalBytes*b.N, len(lines)*b.N, time.Since(started))
}

func receiveDatagrams(listener *net.UnixConn, spool *Spool, lines [][]byte, identity TrustedIdentity) (int, error) {
	maximum := 0
	for _, line := range lines {
		if len(line) > maximum {
			maximum = len(line)
		}
	}
	buffer := make([]byte, maximum+1)
	batch := make([]Envelope, 0, 256)
	appended := 0
	for appended < len(lines) {
		length, _, err := listener.ReadFromUnix(buffer)
		if err != nil {
			return appended, err
		}
		envelope, err := ParseSourceLineBound(buffer[:length], CapturePolicy{}, identity)
		if err != nil {
			return appended, err
		}
		envelope.EventID = fmt.Sprintf("benchmark-event-%d", appended+len(batch)+1)
		batch = append(batch, envelope)
		if len(batch) == cap(batch) || appended+len(batch) == len(lines) {
			results, err := spool.AppendBatch(context.Background(), batch)
			if err != nil {
				return appended, err
			}
			for _, result := range results {
				if result.Duplicate || result.Sampled {
					return appended, errors.New("transport benchmark produced a duplicate or sampled event")
				}
			}
			appended += len(results)
			batch = batch[:0]
		}
	}
	return appended, nil
}

func benchmarkRoot(b *testing.B, name string) string {
	b.Helper()
	root, err := os.MkdirTemp("/tmp", "cdnca-obs-transport-"+name+"-")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		b.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		b.Fatal(err)
	}
	return resolved
}

func benchmarkSpool(b *testing.B, root string) *Spool {
	b.Helper()
	config := Config{
		Root: root, MaxEventBytes: 1 << 20, MaxSegmentBytes: 8 << 20,
		SoftLimitBytes: 256 << 20, HardLimitBytes: 512 << 20, MaxTenantBytes: 512 << 20,
		MaxBatchEvents: 256, PressureMode: PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour, Now: time.Now,
	}
	spool, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	return spool
}

func reportTransportMetrics(b *testing.B, bytes, events int, elapsed time.Duration) {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return
	}
	b.ReportMetric(float64(events)/seconds, "events/s")
	b.ReportMetric(float64(bytes)/seconds, "source-bytes/s")
	b.ReportMetric(0, "lost-events")
	b.ReportMetric(0, "duplicate-events")
}
