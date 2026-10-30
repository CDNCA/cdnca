package wafengine

import (
	"context"
	"errors"
)

// Delegate is the OpenResty deployment runtime the engine wraps.
type Delegate interface {
	Precheck(ctx context.Context, versionID, releasePath string) error
	Reload(ctx context.Context, versionID, currentPath string) error
	Healthy(ctx context.Context, versionID string) error
}

// Stopper stops the running master (Stop + Reload restarts it).
type Stopper interface {
	Stop(ctx context.Context, currentPath string) error
}

// Runtime gates the engine into each release around the delegate:
//   - Precheck writes the gate and runs nginx -t; when it fails only with the
//     gate (module ABI, rule load error) the gate is dropped and recorded, and
//     the release is checked again without it.
//   - Reload restarts the master instead of reloading when the release loads
//     a different module than the running master (load_module is read only
//     at start). A failed restart with the gate is retried without it; a
//     failed restart without the gate returns the error and the deployment
//     manager rolls back to the previous release (whose gate it rewrites).
type Runtime struct {
	delegate Delegate
	stopper  Stopper
	engine   *Manager
}

func NewRuntime(delegate Delegate, stopper Stopper, engine *Manager) (*Runtime, error) {
	if delegate == nil || stopper == nil || engine == nil {
		return nil, ErrInvalidConfig
	}
	return &Runtime{delegate: delegate, stopper: stopper, engine: engine}, nil
}

func (runtime *Runtime) Precheck(ctx context.Context, versionID, releasePath string) error {
	gate, err := runtime.engine.Prepare(ctx, versionID, releasePath)
	if err != nil {
		return err
	}
	err = runtime.delegate.Precheck(ctx, versionID, releasePath)
	if err == nil || gate.ModulePath == "" {
		return err
	}
	if disableErr := runtime.engine.Disable(versionID, ReasonModuleLoad); disableErr != nil {
		return errors.Join(err, disableErr)
	}
	return runtime.delegate.Precheck(ctx, versionID, releasePath)
}

func (runtime *Runtime) Reload(ctx context.Context, versionID, currentPath string) error {
	gate, err := runtime.engine.Prepare(ctx, versionID, currentPath)
	if err != nil {
		return err
	}
	loaded := runtime.engine.LoadedModule()
	if gate.ModulePath == loaded {
		return runtime.delegate.Reload(ctx, versionID, currentPath)
	}
	err = runtime.restart(ctx, versionID, currentPath)
	if err == nil {
		return runtime.engine.SetLoadedModule(gate.ModulePath)
	}
	if gate.ModulePath == "" {
		return err
	}
	if disableErr := runtime.engine.Disable(versionID, ReasonRestart); disableErr != nil {
		return errors.Join(err, disableErr)
	}
	if retryErr := runtime.restart(ctx, versionID, currentPath); retryErr != nil {
		return errors.Join(err, retryErr)
	}
	return runtime.engine.SetLoadedModule("")
}

func (runtime *Runtime) restart(ctx context.Context, versionID, currentPath string) error {
	if err := runtime.stopper.Stop(ctx, currentPath); err != nil {
		return err
	}
	// The module set the master will load is unknown until it starts.
	if err := runtime.engine.SetLoadedModule("?"); err != nil {
		return err
	}
	return runtime.delegate.Reload(ctx, versionID, currentPath)
}

func (runtime *Runtime) Healthy(ctx context.Context, versionID string) error {
	return runtime.delegate.Healthy(ctx, versionID)
}

// CheckSummary is the deployment status check of the engine.
func (status Status) CheckSummary() (string, bool) {
	switch status.State {
	case StateActive:
		return "waf crs engine active " + status.Version, true
	case StateDegraded:
		return "waf crs engine degraded: " + status.Reason + " (crs sites run self-developed detection only)", false
	default:
		return "waf crs engine not required", true
	}
}
