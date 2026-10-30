package acmehttp01

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/nats-io/nats.go"
)

type Runtime struct {
	dispatcher *Dispatcher
	status     *StatusConsumer
	connection *nats.Conn
	closeOnce  sync.Once
	closeErr   error
	active     atomic.Bool
}

func NewRuntime(dispatcher *Dispatcher, status *StatusConsumer, connection *nats.Conn) (*Runtime, error) {
	if dispatcher == nil || status == nil || connection == nil || connection.IsClosed() {
		return nil, ErrInvalidConfig
	}
	return &Runtime{dispatcher: dispatcher, status: status, connection: connection}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	if !r.active.CompareAndSwap(false, true) {
		return errors.New("ACME HTTP-01 transport is already running")
	}
	defer r.active.Store(false)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- r.dispatcher.Run(runCtx) }()
	go func() { errorsChannel <- r.status.Run(runCtx) }()
	err := <-errorsChannel
	cancel()
	second := <-errorsChannel
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return second
}

func (r *Runtime) Ready() error {
	if r == nil || !r.active.Load() || r.connection == nil || !r.connection.IsConnected() || r.connection.IsClosed() {
		return errors.New("ACME HTTP-01 transport is not ready")
	}
	return nil
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.active.Store(false)
		if r.status != nil {
			r.closeErr = r.status.Close()
		}
		if r.connection != nil && !r.connection.IsClosed() {
			if err := r.connection.Drain(); err != nil && r.closeErr == nil {
				r.closeErr = err
			}
			r.connection.Close()
		}
	})
	return r.closeErr
}
