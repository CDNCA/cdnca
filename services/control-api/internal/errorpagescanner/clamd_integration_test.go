package errorpagescanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
)

// Run against a real clamd with its verified signature databases loaded. The
// harmless EICAR test string is streamed in memory and never written to disk.
func TestClamDIntegration(t *testing.T) {
	socket := os.Getenv("ERRORPAGE_CLAMD_INTEGRATION_SOCKET")
	if socket == "" {
		t.Skip("ERRORPAGE_CLAMD_INTEGRATION_SOCKET is not set")
	}
	info, err := os.Stat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("real clamd socket is unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	config := Config{SocketPath: socket, ConnectTimeout: 2 * time.Second, ScanTimeout: 30 * time.Second}
	scanner, err := New(ctx, config)
	if err != nil {
		t.Fatalf("real clamd readiness: %v", err)
	}
	for _, sample := range []struct {
		name, body string
		want       error
	}{
		{"clean HTML", "<!doctype html><html><body>temporarily unavailable</body></html>", nil},
		{"EICAR rejection", `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`, errorpagecontrol.ErrScanRejected},
	} {
		t.Run(sample.name, func(t *testing.T) {
			err := scanner.Scan(ctx, errorpagecontrol.ScanInput{Body: strings.NewReader(sample.body), Size: int64(len(sample.body))})
			if !errors.Is(err, sample.want) {
				t.Fatalf("real scan error = %v, want %v", err, sample.want)
			}
		})
	}
	// A previously healthy adapter must also fail closed when its socket cannot
	// be reached. Do not stop or modify the daemon supplied by the test operator.
	scanner.config.SocketPath = filepath.Join(t.TempDir(), "missing.sock")
	if err := scanner.Scan(ctx, errorpagecontrol.ScanInput{Body: strings.NewReader("clean"), Size: 5}); !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		t.Fatalf("unreachable scanner accepted content: %v", err)
	}
	if _, err := New(ctx, scanner.config); !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		t.Fatalf("unreachable scanner passed readiness: %v", err)
	}
	scanner.config = config
	if err := scanner.Scan(ctx, errorpagecontrol.ScanInput{Body: strings.NewReader("clean"), Size: 5}); err != nil {
		t.Fatalf("scanner did not recover: %v", err)
	}
}
