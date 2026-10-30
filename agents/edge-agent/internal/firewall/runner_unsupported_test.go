//go:build !linux

package firewall

import (
	"errors"
	"testing"
)

func TestDefaultManagerIsUnsupportedOffLinux(t *testing.T) {
	_, err := NewManager(testStateRoot(t), "/usr/sbin/nft")
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("NewManager() error = %v, want ErrUnsupported", err)
	}
}
