package l4runtime

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
)

func TestProcEntryGoneClassifiesReapedTask(t *testing.T) {
	for _, test := range []struct {
		err  error
		gone bool
	}{
		{&os.PathError{Op: "open", Path: "/proc/1/stat", Err: syscall.ENOENT}, true},
		{&os.PathError{Op: "read", Path: "/proc/1/stat", Err: syscall.ESRCH}, true},
		{&os.PathError{Op: "read", Path: "/proc/1/stat", Err: syscall.EACCES}, false},
		{errors.New("other"), false},
		{nil, false},
	} {
		if got := procEntryGone(test.err); got != test.gone {
			t.Fatalf("procEntryGone(%v) = %v, want %v", test.err, got, test.gone)
		}
	}
}

// The kernel behavior the classifier relies on: a stat file opened while the
// task lives reads ESRCH once the task is reaped.
func TestProcStatReadAfterReapIsGone(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux procfs")
	}
	command := exec.Command("sleep", "60")
	if err := command.Start(); err != nil {
		t.Skip("sleep unavailable: ", err)
	}
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(command.Process.Pid), "stat"))
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	defer file.Close()
	_ = command.Process.Kill()
	_ = command.Wait()
	_, err = file.Read(make([]byte, 512))
	if !procEntryGone(err) {
		t.Fatalf("read of reaped task stat = %v, want a gone classification", err)
	}
}
