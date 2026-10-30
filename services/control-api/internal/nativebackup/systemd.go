package nativebackup

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// UnitState is the part of `systemctl show` the freeze needs.
type UnitState struct {
	Loaded  bool
	Active  bool
	Enabled bool
}

// Systemd controls units. The production implementation shells out to
// systemctl; unit tests use a fake that records the call order.
type Systemd interface {
	State(context.Context, string) (UnitState, error)
	Start(context.Context, string) error
	Stop(context.Context, string) error
	Enable(context.Context, string) error
	Disable(context.Context, string) error
	DaemonReload(context.Context) error
}

var unitNamePattern = regexp.MustCompile(`^[A-Za-z0-9@._-]{1,128}\.(service|timer|path)$`)

type Systemctl struct{ Executor Executor }

func (systemctl Systemctl) run(ctx context.Context, arguments ...string) (string, error) {
	return run(ctx, systemctl.Executor, Command{Path: "/usr/bin/systemctl", Args: arguments})
}

func (systemctl Systemctl) State(ctx context.Context, unit string) (UnitState, error) {
	if !unitNamePattern.MatchString(unit) {
		return UnitState{}, errors.New("invalid unit name")
	}
	output, err := systemctl.run(ctx, "show", "--property=LoadState,ActiveState,UnitFileState", "--", unit)
	if err != nil {
		return UnitState{}, err
	}
	return parseUnitState(output), nil
}

func parseUnitState(output string) UnitState {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if key, value, found := strings.Cut(strings.TrimSpace(line), "="); found {
			values[key] = value
		}
	}
	active := values["ActiveState"]
	return UnitState{
		Loaded:  values["LoadState"] == "loaded",
		Active:  active == "active" || active == "activating" || active == "reloading",
		Enabled: values["UnitFileState"] == "enabled",
	}
}

func (systemctl Systemctl) action(ctx context.Context, verb, unit string) error {
	if !unitNamePattern.MatchString(unit) {
		return errors.New("invalid unit name")
	}
	_, err := systemctl.run(ctx, verb, "--", unit)
	return err
}

func (systemctl Systemctl) Start(ctx context.Context, unit string) error {
	return systemctl.action(ctx, "start", unit)
}
func (systemctl Systemctl) Stop(ctx context.Context, unit string) error {
	return systemctl.action(ctx, "stop", unit)
}
func (systemctl Systemctl) Enable(ctx context.Context, unit string) error {
	return systemctl.action(ctx, "enable", unit)
}
func (systemctl Systemctl) Disable(ctx context.Context, unit string) error {
	return systemctl.action(ctx, "disable", unit)
}
func (systemctl Systemctl) DaemonReload(ctx context.Context) error {
	_, err := systemctl.run(ctx, "daemon-reload")
	return err
}
