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
	"reflect"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
)

const (
	ScannerName         = "clamav-instream-v1"
	instreamCommand     = "zINSTREAM\x00"
	readinessProbeBody  = "cdnca-clamd-readiness-v1\n"
	streamChunkSize     = 64 << 10
	maximumResponseSize = 4096
	maximumEmptyReads   = 100
)

type Scanner struct {
	config Config
}

var _ errorpagecontrol.Scanner = (*Scanner)(nil)

func New(ctx context.Context, config Config) (*Scanner, error) {
	if nilInterface(ctx) || !config.valid() {
		return nil, ErrInvalidConfig
	}
	scanner := &Scanner{config: config}
	err := scanner.scan(ctx, strings.NewReader(readinessProbeBody), int64(len(readinessProbeBody)))
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, context.Canceled
		}
		return nil, errorpagecontrol.ErrUnavailable
	}
	return scanner, nil
}

func (*Scanner) Name() string { return ScannerName }

func (scanner *Scanner) Scan(ctx context.Context, input errorpagecontrol.ScanInput) error {
	if scanner == nil || nilInterface(ctx) || nilInterface(input.Body) || input.Size < 1 ||
		input.Size > errorpagecontrol.MaxEdgeResourceBytes || !nonBlockingMemoryReader(input.Body) {
		return errorpagecontrol.ErrUnavailable
	}
	err := scanner.scan(ctx, input.Body, input.Size)
	if err == nil || errors.Is(err, errorpagecontrol.ErrScanRejected) {
		return err
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return context.Canceled
	}
	return errorpagecontrol.ErrUnavailable
}

func nonBlockingMemoryReader(reader io.Reader) bool {
	switch reader.(type) {
	case *bytes.Buffer, *bytes.Reader, *strings.Reader:
		return true
	default:
		return false
	}
}

func (scanner *Scanner) scan(ctx context.Context, body io.Reader, size int64) error {
	scanCtx, cancel := context.WithTimeout(ctx, scanner.config.ScanTimeout)
	defer cancel()
	connection, err := (&net.Dialer{Timeout: scanner.config.ConnectTimeout}).DialContext(
		scanCtx, "unix", scanner.config.SocketPath,
	)
	if err != nil {
		return errorpagecontrol.ErrUnavailable
	}
	defer connection.Close()
	deadline, ok := scanCtx.Deadline()
	if !ok || connection.SetDeadline(deadline) != nil {
		return errorpagecontrol.ErrUnavailable
	}
	stopCancellation := context.AfterFunc(scanCtx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stopCancellation()
	if writeAll(connection, []byte(instreamCommand)) != nil ||
		streamBody(scanCtx, connection, body, size) != nil {
		return errorpagecontrol.ErrUnavailable
	}
	response, err := readResponse(connection)
	if err != nil {
		return errorpagecontrol.ErrUnavailable
	}
	return parseResponse(response)
}

func streamBody(ctx context.Context, writer io.Writer, body io.Reader, size int64) error {
	buffer := make([]byte, streamChunkSize)
	remaining := size
	eofConfirmed := false
	for remaining > 0 {
		length := min(int64(len(buffer)), remaining)
		read, eof, err := readExact(ctx, body, buffer[:length])
		if err != nil || int64(read) != length {
			return errorpagecontrol.ErrUnavailable
		}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(read))
		if writeAll(writer, header[:]) != nil || writeAll(writer, buffer[:read]) != nil {
			return errorpagecontrol.ErrUnavailable
		}
		remaining -= int64(read)
		if eof {
			if remaining != 0 {
				return errorpagecontrol.ErrUnavailable
			}
			eofConfirmed = true
		}
	}
	if !eofConfirmed {
		exact, err := readerAtEOF(ctx, body)
		if err != nil || !exact {
			return errorpagecontrol.ErrUnavailable
		}
	}
	return writeAll(writer, []byte{0, 0, 0, 0})
}

func readExact(ctx context.Context, reader io.Reader, destination []byte) (int, bool, error) {
	total := 0
	emptyReads := 0
	for total < len(destination) {
		if ctx.Err() != nil {
			return total, false, ctx.Err()
		}
		read, err := reader.Read(destination[total:])
		if read < 0 || read > len(destination)-total {
			return total, false, errorpagecontrol.ErrUnavailable
		}
		total += read
		if read == 0 && err == nil {
			emptyReads++
			if emptyReads >= maximumEmptyReads {
				return total, false, errorpagecontrol.ErrUnavailable
			}
		} else {
			emptyReads = 0
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, true, nil
			}
			return total, false, errorpagecontrol.ErrUnavailable
		}
	}
	return total, false, nil
}

func readerAtEOF(ctx context.Context, reader io.Reader) (bool, error) {
	var extra [1]byte
	emptyReads := 0
	for {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		read, err := reader.Read(extra[:])
		if read < 0 || read > 1 || read > 0 {
			return false, errorpagecontrol.ErrUnavailable
		}
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		if err != nil {
			return false, errorpagecontrol.ErrUnavailable
		}
		emptyReads++
		if emptyReads >= maximumEmptyReads {
			return false, errorpagecontrol.ErrUnavailable
		}
	}
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if written < 0 || written > len(value) || written == 0 && err == nil {
			return errorpagecontrol.ErrUnavailable
		}
		value = value[written:]
		if err != nil {
			return errorpagecontrol.ErrUnavailable
		}
	}
	return nil
}

func readResponse(reader io.Reader) ([]byte, error) {
	response := make([]byte, 0, 128)
	var next [1]byte
	emptyReads := 0
	for len(response) <= maximumResponseSize {
		read, err := reader.Read(next[:])
		if read < 0 || read > 1 {
			return nil, errorpagecontrol.ErrUnavailable
		}
		if read == 1 {
			emptyReads = 0
			if next[0] == 0 {
				return response, nil
			}
			response = append(response, next[0])
		} else if err == nil {
			emptyReads++
			if emptyReads >= maximumEmptyReads {
				return nil, errorpagecontrol.ErrUnavailable
			}
		}
		if err != nil {
			return nil, errorpagecontrol.ErrUnavailable
		}
	}
	return nil, errorpagecontrol.ErrUnavailable
}

func parseResponse(response []byte) error {
	if bytes.Equal(response, []byte("stream: OK")) {
		return nil
	}
	const prefix = "stream: "
	const suffix = " FOUND"
	if !bytes.HasPrefix(response, []byte(prefix)) || !bytes.HasSuffix(response, []byte(suffix)) {
		return errorpagecontrol.ErrUnavailable
	}
	signature := response[len(prefix) : len(response)-len(suffix)]
	if len(signature) == 0 {
		return errorpagecontrol.ErrUnavailable
	}
	for _, character := range signature {
		if character < 0x21 || character > 0x7e {
			return errorpagecontrol.ErrUnavailable
		}
	}
	return errorpagecontrol.ErrScanRejected
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

type safeScanner struct {
	Name       string     `json:"name"`
	Transport  string     `json:"transport"`
	Configured bool       `json:"configured"`
	Config     safeConfig `json:"config"`
}

func (scanner *Scanner) safe() safeScanner {
	configured := scanner != nil && scanner.config.valid()
	config := Config{}.safe()
	if scanner != nil {
		config = scanner.config.safe()
	}
	return safeScanner{Name: ScannerName, Transport: "unix", Configured: configured, Config: config}
}

func (scanner *Scanner) safeString() string {
	safe := scanner.safe()
	return fmt.Sprintf("errorpagescanner.Scanner{name:%s transport:%s configured:%t connect_timeout:%s scan_timeout:%s}",
		safe.Name, safe.Transport, safe.Configured, safe.Config.ConnectTimeout, safe.Config.ScanTimeout)
}

func (scanner *Scanner) String() string   { return scanner.safeString() }
func (scanner *Scanner) GoString() string { return scanner.safeString() }

func (scanner *Scanner) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, scanner.safeString())
}

func (scanner *Scanner) MarshalJSON() ([]byte, error) { return json.Marshal(scanner.safe()) }
