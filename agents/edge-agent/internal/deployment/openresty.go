package deployment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

var (
	ErrOpenRestyPrecheck = errors.New("openresty configuration precheck failed")
	ErrOpenRestyReload   = errors.New("openresty reload failed")
	ErrOpenRestyHealth   = errors.New("openresty health check failed")
)

type CommandRunner func(context.Context, string, ...string) error
type HealthProbe func(context.Context, string) error

type OpenResty struct {
	binary     string
	configFile string
	pidPath    string
	run        CommandRunner
	probe      HealthProbe
}

func NewOpenResty(binary, configFile string, runner CommandRunner, probe HealthProbe) (*OpenResty, error) {
	if binary == "" || !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return nil, fmt.Errorf("%w: OpenResty binary must be an absolute clean path", ErrInvalidPath)
	}
	if err := validateRelativePath(configFile); err != nil {
		return nil, err
	}
	if runner == nil {
		runner = runCommand
	}
	if probe == nil {
		return nil, fmt.Errorf("%w: OpenResty health probe is required", ErrInvalidCommand)
	}
	return &OpenResty{binary: binary, configFile: configFile, run: runner, probe: probe}, nil
}

func (o *OpenResty) ConfigureGenerationTracking(pidPath string) error {
	if o == nil || pidPath == "" || !filepath.IsAbs(pidPath) || filepath.Clean(pidPath) != pidPath {
		return fmt.Errorf("%w: OpenResty PID path must be absolute and clean", ErrInvalidPath)
	}
	o.pidPath = pidPath
	return nil
}

func (o *OpenResty) Precheck(ctx context.Context, _ string, releasePath string) error {
	if err := validateRuntimePath(releasePath); err != nil {
		return err
	}
	if err := o.run(ctx, o.binary, "-t", "-p", withTrailingSeparator(releasePath), "-c", o.configFile); err != nil {
		return sanitizedOperationError(ctx, ErrOpenRestyPrecheck)
	}
	return nil
}

func (o *OpenResty) Reload(ctx context.Context, _ string, currentPath string) error {
	if err := validateRuntimePath(currentPath); err != nil {
		return err
	}
	var masterPID int
	var previousWorkers []int
	if o.pidPath != "" {
		var err error
		masterPID, err = readOpenRestyPID(o.pidPath)
		if errors.Is(err, ErrCorruptState) {
			if info, statErr := os.Lstat(o.pidPath); statErr == nil && info.Mode().IsRegular() && info.Size() == 0 {
				err = os.ErrNotExist
			}
		}
		if err == nil {
			previousWorkers, err = readProcessChildren(masterPID)
		}
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			if removeErr := os.Remove(o.pidPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return sanitizedOperationError(ctx, ErrOpenRestyReload)
			}
			if err := o.run(ctx, o.binary, "-p", withTrailingSeparator(currentPath), "-c", o.configFile); err != nil {
				return sanitizedOperationError(ctx, ErrOpenRestyReload)
			}
			return nil
		}
		if err != nil {
			return sanitizedOperationError(ctx, ErrOpenRestyReload)
		}
	}
	if err := o.run(ctx, o.binary, "-s", "reload", "-p", withTrailingSeparator(currentPath), "-c", o.configFile); err != nil {
		return sanitizedOperationError(ctx, ErrOpenRestyReload)
	}
	if o.pidPath != "" {
		if err := o.waitForNewWorker(ctx, masterPID, previousWorkers); err != nil {
			return sanitizedOperationError(ctx, ErrOpenRestyReload)
		}
	}
	return nil
}

func (o *OpenResty) Healthy(ctx context.Context, versionID string) error {
	if err := o.probe(ctx, versionID); err != nil {
		return sanitizedOperationError(ctx, ErrOpenRestyHealth)
	}
	return nil
}

func runCommand(ctx context.Context, binary string, args ...string) error {
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func validateRuntimePath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: runtime path must be absolute and clean", ErrInvalidPath)
	}
	return nil
}

func withTrailingSeparator(path string) string {
	return path + string(filepath.Separator)
}

func sanitizedOperationError(ctx context.Context, operationError error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return operationError
}
