package main

import (
	"os"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

// Every TCP L4 configuration renders the live registry's control socket
// (L4-USAGE-01): replays here prepare a temporary directory, not
// /var/lib/cdnca-edge (tests do not run as root).
func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "l4ctl-")
	if err != nil {
		panic(err)
	}
	restore := l4runtime.UseControlDirectoryForTesting(directory)
	code := m.Run()
	restore()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}
