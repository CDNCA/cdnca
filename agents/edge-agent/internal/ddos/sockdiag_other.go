//go:build !linux

package ddos

import (
	"context"
	"errors"
	"time"
)


// SockDiag is Linux only.
type SockDiag struct{}

var errUnsupported = errors.New("sock_diag is Linux only")

func (SockDiag) EmptySockets(context.Context, []PortRange, time.Duration) ([]EmptySocket, error) {
	return nil, errUnsupported
}

func (SockDiag) Destroy(context.Context, []EmptySocket) error { return errUnsupported }

func (SockDiag) Connections(context.Context, []PortRange) ([]EmptySocket, error) { return nil, errUnsupported }
