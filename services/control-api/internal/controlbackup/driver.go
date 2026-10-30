package controlbackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

const driverOutputLimit = 1 << 20

type CommandDriver struct {
	path string
	env  []string
}

type DriverError struct {
	Code string
}

func (driverError DriverError) Error() string      { return "recovery driver operation failed" }
func (driverError DriverError) StableCode() string { return driverError.Code }

func NewCommandDriver(path string, environment []string) (*CommandDriver, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("recovery driver path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("recovery driver must be an executable regular file")
	}
	return &CommandDriver{path: path, env: append([]string(nil), environment...)}, nil
}

func (driver *CommandDriver) FreezeController() WriteFreezeController {
	return commandFreeze{driver: driver}
}

func (driver *CommandDriver) Capturer(component Component) ComponentCapturer {
	return commandCapturer{driver: driver, component: component}
}

func (driver *CommandDriver) Target() RestoreTarget { return commandTarget{driver: driver} }

func (driver *CommandDriver) Restorer(component Component) ComponentRestorer {
	return commandRestorer{driver: driver, component: component}
}

func (driver *CommandDriver) Probe(name ProbeName) RecoveryProbe {
	return commandProbe{driver: driver, name: name}
}

func (driver *CommandDriver) run(ctx context.Context, operation string, arguments []string, input, output any) error {
	if driver == nil || ctx == nil || !identifierPattern.MatchString(operation) {
		return errors.New("invalid recovery driver invocation")
	}
	encoded := []byte(nil)
	var err error
	if input != nil {
		encoded, err = json.Marshal(input)
		if err != nil {
			return errors.New("encode recovery driver input")
		}
	}
	command := exec.CommandContext(ctx, driver.path, append([]string{operation}, arguments...)...)
	command.Env = append([]string(nil), driver.env...)
	command.Stdin = bytes.NewReader(encoded)
	var stdout bytes.Buffer
	command.Stdout = &limitedWriter{writer: &stdout, remaining: driverOutputLimit}
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		var failure struct {
			ErrorCode string `json:"error_code"`
		}
		if decodeDriverOutput(stdout.Bytes(), &failure) == nil && identifierPattern.MatchString(failure.ErrorCode) {
			return DriverError{Code: failure.ErrorCode}
		}
		return fmt.Errorf("recovery driver operation %s failed", operation)
	}
	if output == nil {
		if stdout.Len() != 0 {
			return fmt.Errorf("recovery driver operation %s returned unexpected output", operation)
		}
		return nil
	}
	if err := decodeDriverOutput(stdout.Bytes(), output); err != nil {
		return fmt.Errorf("recovery driver operation %s returned invalid output", operation)
	}
	return nil
}

func decodeDriverOutput(encoded []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

type limitedWriter struct {
	writer    io.Writer
	remaining int
}

func (writer *limitedWriter) Write(value []byte) (int, error) {
	if len(value) > writer.remaining {
		return 0, errors.New("recovery driver output exceeded limit")
	}
	count, err := writer.writer.Write(value)
	writer.remaining -= count
	return count, err
}

type commandFreeze struct{ driver *CommandDriver }

func (freeze commandFreeze) Acquire(ctx context.Context, backupID string) (WriteFreezeLease, error) {
	var output struct {
		FreezeID string `json:"freeze_id"`
	}
	if err := freeze.driver.run(ctx, "freeze", []string{"--backup-id", backupID}, nil, &output); err != nil {
		return nil, err
	}
	if !identifierPattern.MatchString(output.FreezeID) {
		return nil, errors.New("recovery driver returned invalid write freeze ID")
	}
	return commandFreezeLease{driver: freeze.driver, id: output.FreezeID}, nil
}

type commandFreezeLease struct {
	driver *CommandDriver
	id     string
}

func (lease commandFreezeLease) ID() string { return lease.id }
func (lease commandFreezeLease) Release(ctx context.Context) error {
	return lease.driver.run(ctx, "release", []string{"--freeze-id", lease.id}, nil, nil)
}

type commandCapturer struct {
	driver    *CommandDriver
	component Component
}

func (capturer commandCapturer) Name() Component { return capturer.component }
func (capturer commandCapturer) Capture(ctx context.Context, request CaptureRequest) (ComponentCheckpoint, error) {
	var checkpoint ComponentCheckpoint
	err := capturer.driver.run(ctx, "capture", []string{
		"--component", string(capturer.component), "--backup-id", request.BackupID,
		"--freeze-id", request.WriteFreezeID,
	}, nil, &checkpoint)
	return checkpoint, err
}

type commandTarget struct{ driver *CommandDriver }

func (target commandTarget) Preflight(ctx context.Context, manifest Manifest, targetID string) error {
	return target.driver.run(ctx, "preflight", []string{"--target-id", targetID}, manifest, nil)
}

type commandRestorer struct {
	driver    *CommandDriver
	component Component
}

func (restorer commandRestorer) Name() Component { return restorer.component }
func (restorer commandRestorer) Restore(ctx context.Context, checkpoint ComponentCheckpoint, targetID string) error {
	return restorer.driver.run(ctx, "restore", []string{
		"--component", string(restorer.component), "--target-id", targetID,
	}, checkpoint, nil)
}
func (restorer commandRestorer) Compensate(ctx context.Context, backupID, targetID string) error {
	return restorer.driver.run(ctx, "compensate", []string{
		"--component", string(restorer.component), "--backup-id", backupID, "--target-id", targetID,
	}, nil, nil)
}

type commandProbe struct {
	driver *CommandDriver
	name   ProbeName
}

func (probe commandProbe) Name() ProbeName { return probe.name }
func (probe commandProbe) Check(ctx context.Context, manifest Manifest, targetID string) error {
	return probe.driver.run(ctx, "probe", []string{
		"--name", string(probe.name), "--target-id", targetID,
	}, manifest, nil)
}
