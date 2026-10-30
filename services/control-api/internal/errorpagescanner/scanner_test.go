package errorpagescanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
)

const expectedProbeBody = "cdnca-clamd-readiness-v1\n"

func TestNewRejectsInvalidConfigWithoutDial(t *testing.T) {
	valid := Config{
		SocketPath: "/tmp/cdnca-clamd.sock", ConnectTimeout: 100 * time.Millisecond,
		ScanTimeout: time.Second,
	}
	tests := map[string]func(*Config){
		"relative socket":       func(config *Config) { config.SocketPath = "clamd.sock" },
		"non canonical socket":  func(config *Config) { config.SocketPath = "/tmp/../tmp/clamd.sock" },
		"control in socket":     func(config *Config) { config.SocketPath = "/tmp/clamd\n.sock" },
		"long socket":           func(config *Config) { config.SocketPath = "/tmp/" + strings.Repeat("a", 101) },
		"short connect timeout": func(config *Config) { config.ConnectTimeout = time.Millisecond },
		"long connect timeout":  func(config *Config) { config.ConnectTimeout = 31 * time.Second },
		"short scan timeout":    func(config *Config) { config.ScanTimeout = 50 * time.Millisecond },
		"connect after scan":    func(config *Config) { config.ConnectTimeout = 2 * time.Second },
		"long scan timeout":     func(config *Config) { config.ScanTimeout = 6 * time.Minute },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			scanner, err := New(t.Context(), config)
			if scanner != nil || !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New() = (%T,%v), want nil ErrInvalidConfig", scanner, err)
			}
		})
	}
	if scanner, err := New(nil, valid); scanner != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(nil) = (%T,%v), want nil ErrInvalidConfig", scanner, err)
	}
}

func TestNewProbesClamdWithINSTREAMBeforeReturning(t *testing.T) {
	requests := make(chan clamdRequest, 1)
	path, attempts := startFakeClamd(t, func(connection net.Conn) {
		request, err := readINSTREAM(connection)
		if err != nil {
			t.Errorf("read probe: %v", err)
			return
		}
		requests <- request
		_, _ = connection.Write([]byte("stream: OK\x00"))
	})
	scanner, err := New(t.Context(), validConfig(path))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if scanner.Name() != ScannerName {
		t.Fatalf("Name() = %q, want %q", scanner.Name(), ScannerName)
	}
	request := <-requests
	if string(request.body) != expectedProbeBody || !request.terminated || attempts.Load() != 1 {
		t.Fatalf("probe body=%q terminated=%t attempts=%d", request.body, request.terminated, attempts.Load())
	}
}

func TestNewFailsClosedWhenProbeIsUnavailableOrRejected(t *testing.T) {
	for name, response := range map[string][]byte{
		"found":     []byte("stream: Eicar-Test-Signature FOUND\x00"),
		"malformed": []byte("stream: maybe\x00"),
		"eof":       nil,
	} {
		t.Run(name, func(t *testing.T) {
			path, _ := startFakeClamd(t, respondAfterRequest(t, response, false))
			scanner, err := New(t.Context(), validConfig(path))
			if scanner != nil || !errors.Is(err, errorpagecontrol.ErrUnavailable) {
				t.Fatalf("New() = (%T,%v), want nil ErrUnavailable", scanner, err)
			}
		})
	}
}

func TestConfigAndScannerFormattingRedactSocketPath(t *testing.T) {
	path, _ := startFakeClamd(t, respondAfterRequest(t, []byte("stream: OK\x00"), false))
	config := validConfig(path)
	scanner, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	values := []any{config, scanner}
	for _, value := range values {
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatalf("Marshal(%T): %v", value, marshalErr)
		}
		for _, formatted := range []string{fmt.Sprint(value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value), string(encoded)} {
			if strings.Contains(formatted, path) || strings.Contains(formatted, filepath.Base(path)) {
				t.Fatalf("%T formatting leaked socket path: %q", value, formatted)
			}
		}
	}
	missing := validConfig(path + "-missing-secret")
	_, err = New(t.Context(), missing)
	if !errors.Is(err, errorpagecontrol.ErrUnavailable) || strings.Contains(err.Error(), missing.SocketPath) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("connect error was not stable and redacted: %v", err)
	}
}

func TestTypedNilScannerFailsClosedAndKeepsStableName(t *testing.T) {
	var scanner *Scanner
	if scanner.Name() != ScannerName {
		t.Fatalf("typed nil Name() = %q", scanner.Name())
	}
	err := scanner.Scan(t.Context(), errorpagecontrol.ScanInput{Size: 1, Body: strings.NewReader("x")})
	if !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		t.Fatalf("typed nil Scan() error = %v, want ErrUnavailable", err)
	}
	var body *bytes.Reader
	path, _ := startFakeClamd(t, respondAfterRequest(t, []byte("stream: OK\x00"), false))
	configured, err := New(t.Context(), validConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	err = configured.Scan(t.Context(), errorpagecontrol.ScanInput{Size: 1, Body: body})
	if !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		t.Fatalf("typed nil body Scan() error = %v, want ErrUnavailable", err)
	}
}

func TestScanAcceptsNonBlockingMemoryReaders(t *testing.T) {
	tests := map[string]func([]byte) io.Reader{
		"bytes reader":   func(body []byte) io.Reader { return bytes.NewReader(body) },
		"bytes buffer":   func(body []byte) io.Reader { return bytes.NewBuffer(body) },
		"strings reader": func(body []byte) io.Reader { return strings.NewReader(string(body)) },
	}
	for name, newReader := range tests {
		t.Run(name, func(t *testing.T) {
			path, attempts := startFakeClamd(t,
				respondAfterRequest(t, []byte("stream: OK\x00"), false),
				respondAfterRequest(t, []byte("stream: OK\x00"), false),
			)
			scanner, err := New(t.Context(), validConfig(path))
			if err != nil {
				t.Fatal(err)
			}
			body := []byte("x")
			if err := scanner.Scan(t.Context(), scanInput(body, int64(len(body)), newReader(body))); err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if attempts.Load() != 2 {
				t.Fatalf("connection attempts = %d, want probe and scan", attempts.Load())
			}
		})
	}
}

func TestScanStreamsExactINSTREAMFramesAndReturnsClean(t *testing.T) {
	for _, size := range []int{1, 65535, 65536, 65537, int(errorpagecontrol.MaxEdgeResourceBytes)} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			body := bytes.Repeat([]byte("a"), size)
			requests := make(chan clamdRequest, 1)
			path, attempts := startFakeClamd(t,
				respondAfterRequest(t, []byte("stream: OK\x00"), false),
				func(connection net.Conn) {
					request, err := readINSTREAM(connection)
					if err != nil {
						t.Errorf("read scan: %v", err)
						return
					}
					requests <- request
					writeFragments(connection, []byte("stream: OK\x00"))
				},
			)
			scanner, err := New(t.Context(), validConfig(path))
			if err != nil {
				t.Fatal(err)
			}
			if err := scanner.Scan(t.Context(), scanInput(body, int64(size), bytes.NewReader(body))); err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			request := <-requests
			if !request.terminated || !bytes.Equal(request.body, body) || attempts.Load() != 2 {
				t.Fatalf("scan bytes=%d terminated=%t attempts=%d", len(request.body), request.terminated, attempts.Load())
			}
			for _, chunk := range request.chunks {
				if chunk < 1 || chunk > 64<<10 {
					t.Fatalf("INSTREAM chunk size = %d", chunk)
				}
			}
		})
	}
}

func TestScanHandlesPartialSocketReads(t *testing.T) {
	body := []byte("partial reads remain exact")
	requests := make(chan clamdRequest, 1)
	path, _ := startFakeClamd(t,
		respondAfterRequest(t, []byte("stream: OK\x00"), false),
		func(connection net.Conn) {
			request, err := readINSTREAM(connection)
			if err != nil {
				t.Errorf("read scan: %v", err)
				return
			}
			requests <- request
			writeFragments(connection, []byte("stream: OK\x00"))
		},
	)
	scanner, err := New(t.Context(), validConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := scanner.Scan(t.Context(), scanInput(body, int64(len(body)), bytes.NewReader(body))); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if request := <-requests; !bytes.Equal(request.body, body) || !request.terminated {
		t.Fatalf("partial request = %#v", request)
	}
}

func TestWriteAllRetriesPartialWrites(t *testing.T) {
	written := &partialWriter{maximum: 2}
	value := []byte("partial writes remain exact")
	if err := writeAll(written, value); err != nil {
		t.Fatalf("writeAll() error = %v", err)
	}
	if !bytes.Equal(written.Bytes(), value) || written.calls < 2 {
		t.Fatalf("writeAll() bytes=%q calls=%d", written.Bytes(), written.calls)
	}
}

func TestScanFOUNDMapsToRejectedWithoutLeakingSignature(t *testing.T) {
	const signature = "Eicar-Test-Signature"
	path, _ := startFakeClamd(t,
		respondAfterRequest(t, []byte("stream: OK\x00"), false),
		respondAfterRequest(t, []byte("stream: "+signature+" FOUND\x00"), false),
	)
	scanner, err := New(t.Context(), validConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	err = scanner.Scan(t.Context(), scanInput([]byte("eicar-like"), 10, strings.NewReader("eicar-like")))
	if !errors.Is(err, errorpagecontrol.ErrScanRejected) || strings.Contains(err.Error(), signature) {
		t.Fatalf("FOUND error = %v", err)
	}
}

func TestScanRejectsInvalidInputBeforeDial(t *testing.T) {
	path, attempts := startFakeClamd(t, respondAfterRequest(t, []byte("stream: OK\x00"), false))
	scanner, err := New(t.Context(), validConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]errorpagecontrol.ScanInput{
		"zero size": {Size: 0, Body: strings.NewReader("")},
		"oversize":  {Size: errorpagecontrol.MaxEdgeResourceBytes + 1, Body: strings.NewReader("x")},
		"nil body":  {Size: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if err := scanner.Scan(t.Context(), input); !errors.Is(err, errorpagecontrol.ErrUnavailable) {
				t.Fatalf("Scan() error = %v, want ErrUnavailable", err)
			}
		})
	}
	if attempts.Load() != 1 {
		t.Fatalf("invalid input dial attempts = %d, want probe only", attempts.Load())
	}
}

func TestScanRejectsShortAndLongBodiesBeforeTerminalFrame(t *testing.T) {
	for name, input := range map[string]errorpagecontrol.ScanInput{
		"short": {Size: 5, Body: strings.NewReader("four")},
		"long":  {Size: 4, Body: strings.NewReader("fives")},
	} {
		t.Run(name, func(t *testing.T) {
			requests := make(chan clamdRequest, 1)
			path, _ := startFakeClamd(t,
				respondAfterRequest(t, []byte("stream: OK\x00"), false),
				func(connection net.Conn) {
					request, _ := readINSTREAM(connection)
					requests <- request
				},
			)
			scanner, err := New(t.Context(), validConfig(path))
			if err != nil {
				t.Fatal(err)
			}
			if err := scanner.Scan(t.Context(), input); !errors.Is(err, errorpagecontrol.ErrUnavailable) {
				t.Fatalf("Scan() error = %v, want ErrUnavailable", err)
			}
			if request := <-requests; request.terminated {
				t.Fatal("size-mismatched body sent terminal frame")
			}
		})
	}
}

func TestScanRejectsZeroNilReaderWithoutSpinning(t *testing.T) {
	path, _ := startFakeClamd(t,
		respondAfterRequest(t, []byte("stream: OK\x00"), false),
		func(connection net.Conn) { _, _ = readINSTREAM(connection) },
	)
	scanner, err := New(t.Context(), validConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	reader := new(zeroNilReader)
	started := time.Now()
	err = scanner.Scan(t.Context(), errorpagecontrol.ScanInput{Size: 1, Body: reader})
	if !errors.Is(err, errorpagecontrol.ErrUnavailable) || time.Since(started) > time.Second || reader.calls.Load() > 128 {
		t.Fatalf("zero reader error=%v elapsed=%s calls=%d", err, time.Since(started), reader.calls.Load())
	}
}

func TestScanRejectsPotentiallyBlockingBodyBeforeDial(t *testing.T) {
	path, attempts := startFakeClamd(t,
		respondAfterRequest(t, []byte("stream: OK\x00"), false),
		func(connection net.Conn) { _, _ = io.Copy(io.Discard, connection) },
	)
	scanner, err := New(t.Context(), validConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	reader := &blockingReader{release: make(chan struct{})}
	defer reader.unblock()
	done := make(chan error, 1)
	go func() {
		done <- scanner.Scan(t.Context(), errorpagecontrol.ScanInput{Size: 1, Body: reader})
	}()
	select {
	case err = <-done:
	case <-time.After(250 * time.Millisecond):
		reader.unblock()
		<-done
		t.Fatal("Scan() blocked on an unsupported body reader")
	}
	if !errors.Is(err, errorpagecontrol.ErrUnavailable) || reader.calls.Load() != 0 || attempts.Load() != 1 {
		t.Fatalf("blocking body error=%v reads=%d attempts=%d, want unavailable before read or dial",
			err, reader.calls.Load(), attempts.Load())
	}
}

func TestScanMapsClamdProtocolFailuresToUnavailable(t *testing.T) {
	tests := map[string][]byte{
		"eof":                  nil,
		"not nul terminated":   []byte("stream: OK"),
		"error":                []byte("stream: size limit exceeded ERROR\x00"),
		"unknown":              []byte("UNKNOWN COMMAND\x00"),
		"empty signature":      []byte("stream:  FOUND\x00"),
		"signature control":    []byte("stream: bad\nsignature FOUND\x00"),
		"newline after result": []byte("stream: OK\n\x00"),
		"oversized response":   append(bytes.Repeat([]byte("x"), 4097), 0),
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			path, _ := startFakeClamd(t,
				respondAfterRequest(t, []byte("stream: OK\x00"), false),
				respondAfterRequest(t, response, false),
			)
			scanner, err := New(t.Context(), validConfig(path))
			if err != nil {
				t.Fatal(err)
			}
			err = scanner.Scan(t.Context(), errorpagecontrol.ScanInput{Size: 1, Body: strings.NewReader("x")})
			raw := string(bytes.TrimRight(response, "\x00"))
			if !errors.Is(err, errorpagecontrol.ErrUnavailable) || raw != "" && strings.Contains(err.Error(), raw) {
				t.Fatalf("protocol error = %v", err)
			}
		})
	}
}

func TestScanInternalDeadlineReturnsUnavailable(t *testing.T) {
	blocked := make(chan struct{})
	path, _ := startFakeClamd(t,
		respondAfterRequest(t, []byte("stream: OK\x00"), false),
		func(connection net.Conn) {
			if _, err := readINSTREAM(connection); err != nil {
				t.Errorf("read deadline scan: %v", err)
				return
			}
			close(blocked)
			_, _ = io.Copy(io.Discard, connection)
		},
	)
	config := validConfig(path)
	config.ScanTimeout = 100 * time.Millisecond
	scanner, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = scanner.Scan(t.Context(), errorpagecontrol.ScanInput{Size: 1, Body: strings.NewReader("x")})
	<-blocked
	if !errors.Is(err, errorpagecontrol.ErrUnavailable) || time.Since(started) > time.Second {
		t.Fatalf("deadline error=%v elapsed=%s", err, time.Since(started))
	}
}

func TestScanCallerCancellationInterruptsResponseRead(t *testing.T) {
	blocked := make(chan struct{})
	path, _ := startFakeClamd(t,
		respondAfterRequest(t, []byte("stream: OK\x00"), false),
		func(connection net.Conn) {
			if _, err := readINSTREAM(connection); err != nil {
				t.Errorf("read canceled scan: %v", err)
				return
			}
			close(blocked)
			_, _ = io.Copy(io.Discard, connection)
		},
	)
	scanner, err := New(t.Context(), validConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- scanner.Scan(ctx, errorpagecontrol.ScanInput{Size: 1, Body: strings.NewReader("x")})
	}()
	<-blocked
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled Scan() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled Scan did not return")
	}
}

func TestScanCallerCancellationBeforeDialDoesNotConnect(t *testing.T) {
	path, attempts := startFakeClamd(t, respondAfterRequest(t, []byte("stream: OK\x00"), false))
	scanner, err := New(t.Context(), validConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = scanner.Scan(ctx, errorpagecontrol.ScanInput{Size: 1, Body: strings.NewReader("x")})
	if !errors.Is(err, context.Canceled) || attempts.Load() != 1 {
		t.Fatalf("canceled Scan() error=%v attempts=%d, want canceled and probe only", err, attempts.Load())
	}
}

func TestScanDoesNotRetryOrReuseConnections(t *testing.T) {
	path, attempts := startFakeClamd(t,
		respondAfterRequest(t, []byte("stream: OK\x00"), false),
		respondAfterRequest(t, []byte("malformed\x00"), false),
	)
	scanner, err := New(t.Context(), validConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	err = scanner.Scan(t.Context(), errorpagecontrol.ScanInput{Size: 1, Body: strings.NewReader("x")})
	if !errors.Is(err, errorpagecontrol.ErrUnavailable) || attempts.Load() != 2 {
		t.Fatalf("Scan() error=%v attempts=%d, want unavailable and two total connections", err, attempts.Load())
	}
}

func TestScanConcurrentConnectionsRemainIsolated(t *testing.T) {
	const scans = 8
	handlers := make([]func(net.Conn), 0, scans+1)
	handlers = append(handlers, respondAfterRequest(t, []byte("stream: OK\x00"), false))
	for range scans {
		handlers = append(handlers, respondAfterRequest(t, []byte("stream: OK\x00"), true))
	}
	path, attempts := startFakeClamd(t, handlers...)
	scanner, err := New(t.Context(), validConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	errorsOut := make(chan error, scans)
	var workers sync.WaitGroup
	for index := range scans {
		workers.Add(1)
		go func(value byte) {
			defer workers.Done()
			errorsOut <- scanner.Scan(t.Context(), errorpagecontrol.ScanInput{Size: 1, Body: bytes.NewReader([]byte{value})})
		}(byte(index))
	}
	workers.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatalf("concurrent Scan() error = %v", err)
		}
	}
	if attempts.Load() != scans+1 {
		t.Fatalf("concurrent connection attempts = %d, want %d", attempts.Load(), scans+1)
	}
}

func validConfig(path string) Config {
	return Config{SocketPath: path, ConnectTimeout: 100 * time.Millisecond, ScanTimeout: time.Second}
}

func scanInput(body []byte, size int64, reader io.Reader) errorpagecontrol.ScanInput {
	return errorpagecontrol.ScanInput{MIMEType: "text/plain", Size: size, Body: reader}
}

type clamdRequest struct {
	body       []byte
	chunks     []int
	terminated bool
}

func startFakeClamd(t *testing.T, handlers ...func(net.Conn)) (string, *atomic.Int32) {
	t.Helper()
	placeholder, err := os.CreateTemp("/tmp", "cdnca-eps-*.sock")
	if err != nil {
		t.Fatalf("reserve fake clamd socket path: %v", err)
	}
	path := placeholder.Name()
	if closeErr := placeholder.Close(); closeErr != nil {
		t.Fatalf("close fake clamd socket placeholder: %v", closeErr)
	}
	if removeErr := os.Remove(path); removeErr != nil {
		t.Fatalf("release fake clamd socket placeholder: %v", removeErr)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen fake clamd: %v", err)
	}
	attempts := new(atomic.Int32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer listener.Close()
		var connections sync.WaitGroup
		for _, handler := range handlers {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			attempts.Add(1)
			connections.Add(1)
			go func(run func(net.Conn), connection net.Conn) {
				defer connections.Done()
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
				run(connection)
			}(handler, connection)
		}
		connections.Wait()
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("fake clamd did not stop")
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			t.Errorf("remove fake clamd socket: %v", removeErr)
		}
	})
	return path, attempts
}

func respondAfterRequest(t *testing.T, response []byte, fragmented bool) func(net.Conn) {
	t.Helper()
	return func(connection net.Conn) {
		if _, err := readINSTREAM(connection); err != nil {
			t.Errorf("read INSTREAM request: %v", err)
			return
		}
		if fragmented {
			writeFragments(connection, response)
			return
		}
		_, _ = connection.Write(response)
	}
}

func readINSTREAM(connection net.Conn) (clamdRequest, error) {
	command := make([]byte, len("zINSTREAM\x00"))
	if _, err := io.ReadFull(connection, command); err != nil {
		return clamdRequest{}, err
	}
	if string(command) != "zINSTREAM\x00" {
		return clamdRequest{}, fmt.Errorf("command = %q", command)
	}
	request := clamdRequest{}
	for {
		var header [4]byte
		if _, err := io.ReadFull(connection, header[:]); err != nil {
			return request, err
		}
		size := int(binary.BigEndian.Uint32(header[:]))
		if size == 0 {
			request.terminated = true
			return request, nil
		}
		if size > 64<<10 {
			return request, fmt.Errorf("chunk size = %d", size)
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(connection, chunk); err != nil {
			return request, err
		}
		request.chunks = append(request.chunks, size)
		request.body = append(request.body, chunk...)
	}
}

func writeFragments(connection net.Conn, response []byte) {
	for _, value := range response {
		_, _ = connection.Write([]byte{value})
	}
}

type zeroNilReader struct{ calls atomic.Int32 }

func (reader *zeroNilReader) Read([]byte) (int, error) {
	reader.calls.Add(1)
	return 0, nil
}

type blockingReader struct {
	calls   atomic.Int32
	release chan struct{}
	once    sync.Once
}

func (reader *blockingReader) Read([]byte) (int, error) {
	reader.calls.Add(1)
	<-reader.release
	return 0, io.EOF
}

func (reader *blockingReader) unblock() {
	reader.once.Do(func() { close(reader.release) })
}

type partialWriter struct {
	bytes.Buffer
	maximum int
	calls   int
}

func (writer *partialWriter) Write(value []byte) (int, error) {
	writer.calls++
	if len(value) > writer.maximum {
		value = value[:writer.maximum]
	}
	return writer.Buffer.Write(value)
}
