package deployment

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

var ErrOpenRestyStop = errors.New("openresty stop failed")

// Stop gracefully stops the running OpenResty master (SIGQUIT: in-flight
// requests finish) and waits until it is gone. A following Reload starts a
// new master, so Stop + Reload is a restart; it is needed when the set of
// dynamic modules changes (load_module is read only when a master starts).
// Stopping a runtime that is not running succeeds.
func (o *OpenResty) Stop(ctx context.Context, currentPath string) error {
	if err := validateRuntimePath(currentPath); err != nil {
		return err
	}
	if o.pidPath == "" {
		return sanitizedOperationError(ctx, ErrOpenRestyStop)
	}
	pid, err := readOpenRestyPID(o.pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return sanitizedOperationError(ctx, ErrOpenRestyStop)
	}
	if _, err := inspectProcess(pid); errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		if removeErr := os.Remove(o.pidPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return sanitizedOperationError(ctx, ErrOpenRestyStop)
		}
		return nil
	}
	if err := o.run(ctx, o.binary, "-s", "quit", "-p", withTrailingSeparator(currentPath), "-c", o.configFile); err != nil {
		return sanitizedOperationError(ctx, ErrOpenRestyStop)
	}
	return waitUntil(ctx, func() bool {
		_, err := inspectProcess(pid)
		return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
	})
}

func waitUntil(ctx context.Context, done func() bool) error {
	waitCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for !done() {
		select {
		case <-waitCtx.Done():
			return sanitizedOperationError(ctx, ErrOpenRestyStop)
		case <-ticker.C:
		}
	}
	return nil
}
