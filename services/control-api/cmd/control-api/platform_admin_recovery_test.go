package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestPlatformRecoveryCLIAdmission(t *testing.T) {
	if runtime.GOOS == "linux" && os.Getuid() == 0 && os.Geteuid() == 0 {
		t.Skip("the non-root admission case runs in the Linux credential subprocess test")
	}
	err := run([]string{"recover-platform-admin", "--password=must-not-echo-this"})
	if err == nil || err.Error() != "platform_recovery_requires_linux_root" {
		t.Fatalf("root-only recovery command was not denied with its safe admission error: %v", err)
	}
}

func TestPlatformRecoveryParsingAndSecretInput(t *testing.T) {
	base := []string{"--user-id", uuid.NewString(), "--scope-id", uuid.NewString(), "--request-id", uuid.NewString()}
	mutation := append(append([]string(nil), base...), "--expected-username", "old-admin", "--expected-revision", "1", "--new-username", "admin")
	for name, args := range map[string][]string{
		"mutation": mutation,
		"pipe":     append(append([]string(nil), mutation...), "--password-stdin"),
		"status":   append(append([]string(nil), base...), "--status"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePlatformRecoveryOptions(args); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, extra := range map[string][]string{
		"password argument": {"--password=must-not-echo-this"},
		"password file":     {"--password-file=/secret/never-opened"},
		"password env":      {"--password-env=NEVER_READ"},
		"positional secret": {"must-not-echo-this"},
		"duplicate target":  {"--user-id", uuid.NewString()},
		"status mutation":   {"--status"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parsePlatformRecoveryOptions(append(append([]string(nil), mutation...), extra...))
			if !errors.Is(err, identity.ErrPlatformRecoveryInput) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "echo") {
				t.Fatalf("expected sanitized flag rejection, got %v", err)
			}
		})
	}
	for _, args := range [][]string{base, {"--status"}, append(append([]string(nil), base...), "--status", "--password-stdin")} {
		if _, err := parsePlatformRecoveryOptions(args); !errors.Is(err, identity.ErrPlatformRecoveryInput) {
			t.Fatalf("invalid operation was accepted: %v", err)
		}
	}
	for _, tc := range []struct {
		goos      string
		uid, euid int
		want      bool
	}{
		{"linux", 0, 0, true}, {"linux", 1000, 0, false}, {"linux", 0, 1000, false},
		{"linux", 1000, 1000, false}, {"darwin", 0, 0, false},
	} {
		if platformRecoveryRoot(tc.goos, tc.uid, tc.euid) != tc.want {
			t.Fatal("real/effective UID admission mismatch")
		}
	}
	for _, value := range []string{"pipe-password-example", "pipe-password-example\n", "short", strings.Repeat("x", 1025), "line-one-password\nline-two", "nul-password\x00end", "cr-password-example\r\n"} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.WriteString(value); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		var prompt bytes.Buffer
		password, err := readPlatformRecoveryPassword(reader, true, &prompt)
		_ = reader.Close()
		want := strings.TrimSuffix(value, "\n")
		valid := len(want) >= 12 && len(want) <= 1024 && !strings.ContainsAny(want, "\x00\r\n")
		if valid != (err == nil) || err == nil && string(password) != want || prompt.Len() != 0 {
			t.Fatal("pipe framing or non-disclosure invariant failed")
		}
		clear(password)
	}
	file, err := os.CreateTemp(t.TempDir(), "forbidden-regular-input-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := readPlatformRecoveryPassword(file, true, io.Discard); err == nil {
		t.Fatal("regular-file password input was accepted")
	}
	if runtime.GOOS == "linux" {
		fifoPath := filepath.Join(t.TempDir(), "forbidden-named-fifo")
		if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
			t.Fatal(err)
		}
		fifo, err := os.OpenFile(fifoPath, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer fifo.Close()
		if _, err := readPlatformRecoveryPassword(fifo, true, io.Discard); err == nil || err.Error() != "platform_recovery_anonymous_pipe_required" {
			t.Fatal("named FIFO was not rejected before reading")
		}
	}
}

func TestPlatformRecoveryLinuxCredentials(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires real Linux UID/EUID")
	}
	if mode := os.Getenv("CDNCA_RECOVERY_CREDENTIAL_TEST_CHILD"); mode != "" {
		if mode == "effective-nonroot" {
			if err := syscall.Seteuid(65534); err != nil {
				t.Fatal(err)
			}
		} else if mode == "real-nonroot" {
			if err := syscall.Setreuid(65534, 0); err != nil {
				t.Fatal(err)
			}
		}
		err := run([]string{"recover-platform-admin", "--status"})
		want := "platform_recovery_requires_linux_root"
		if mode == "root" {
			want = identity.ErrPlatformRecoveryInput.Error()
		}
		if err == nil || err.Error() != want {
			t.Fatalf("credential gate error = %v", err)
		}
		return
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Skip("parent must be Linux root to test credential changes")
	}
	directory, err := os.MkdirTemp("", "cdnca-recovery-uid-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	path := filepath.Join(directory, "recovery.test")
	target, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(target, source)
	closeErr := target.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("copy credential test executable")
	}
	for _, mode := range []string{"root", "nonroot", "effective-nonroot", "real-nonroot"} {
		t.Run(mode, func(t *testing.T) {
			command := exec.Command(path, "-test.run=^TestPlatformRecoveryLinuxCredentials$", "-test.count=1")
			command.Env = []string{"CDNCA_RECOVERY_CREDENTIAL_TEST_CHILD=" + mode}
			if mode == "nonroot" {
				command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
			}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("credential subprocess failed: %v: %s", err, output)
			}
		})
	}
}
