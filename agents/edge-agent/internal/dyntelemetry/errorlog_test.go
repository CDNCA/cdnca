package dyntelemetry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testdata/reuseport-reload-noise.log is what a real OpenResty 1.31.1.1
// (node runtime image, 2 workers, IPv4 + IPv6 quic reuseport) wrote over two
// reloads.
func TestErrorLogFiltersOnlyTheReuseportReloadNoise(t *testing.T) {
	raw, err := os.ReadFile("testdata/reuseport-reload-noise.log")
	if err != nil {
		t.Fatal(err)
	}
	noise := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(noise) != 8 {
		t.Fatalf("fixture has %d lines", len(noise))
	}
	severe := []string{
		"2026/10/18 14:51:18 [emerg] 10#10: close() socket 127.0.0.1:18443 failed (24: Too many open files)",
		"2026/10/18 14:51:18 [emerg] 10#10: bind() to 0.0.0.0:443 failed (98: Address already in use)",
		"2026/10/18 14:51:18 [alert] 10#10: worker process 12 exited on signal 11",
		"2026/10/18 14:51:18 [crit] 10#10: *5 SSL_do_handshake() failed (SSL: error) while SSL handshaking, client: 1.2.3.4",
		"2026/10/18 14:51:18 [emerg] 10#10: close() socket 127.0.0.1:18443 failed (9: Bad file descriptor), client: 1.2.3.4",
		"2026/10/18 14:51:18 [alert] 10#10: close() socket 127.0.0.1:18443 failed (9: Bad file descriptor)",
	}
	other := []string{
		"2026/10/18 14:51:18 [notice] 13#13: signal process started",
		"2026/10/18 14:51:18 [error] 10#10: *1 lua entry thread aborted",
	}
	path := filepath.Join(t.TempDir(), "error.log")
	content := strings.Join(append(append(append([]string{}, noise...), severe...), other...), "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	reader := &ErrorLog{Path: path}
	summary, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	if summary.Noise != 8 || summary.Lines != 16 || strings.Join(summary.Severe, "\n") != strings.Join(severe, "\n") {
		t.Fatalf("noise %d lines %d severe\n%s", summary.Noise, summary.Lines, strings.Join(summary.Severe, "\n"))
	}
	// Incremental: nothing new, then a partial line, then its end.
	if summary, _ = reader.Read(); summary.Lines != 0 {
		t.Fatalf("re-read %d lines", summary.Lines)
	}
	file, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = file.WriteString(noise[0][:30])
	if summary, _ = reader.Read(); summary.Lines != 0 {
		t.Fatalf("partial line read")
	}
	_, _ = file.WriteString(noise[0][30:] + "\n" + severe[2] + "\n")
	_ = file.Close()
	if summary, _ = reader.Read(); summary.Noise != 1 || len(summary.Severe) != 1 {
		t.Fatalf("after append %+v", summary)
	}
	// Rotation (new inode): read from the start.
	_ = os.Rename(path, path+".1")
	_ = os.WriteFile(path, []byte(severe[0]+"\n"), 0o600)
	if summary, _ = reader.Read(); len(summary.Severe) != 1 || summary.Lines != 1 {
		t.Fatalf("after rotation %+v", summary)
	}
}
