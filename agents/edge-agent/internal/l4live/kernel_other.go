//go:build !linux

package l4live

import (
	"context"
	"errors"
)

var errUnsupportedOS = errors.New("L4 live connections need Linux")

// LinuxKernel is unavailable off Linux.
type LinuxKernel struct{}

func (LinuxKernel) Established(context.Context, []uint16) ([]Socket, error) {
	return nil, errUnsupportedOS
}
func (LinuxKernel) Close(context.Context, []int, uint64) error { return errUnsupportedOS }

func CanClose() bool { return false }
