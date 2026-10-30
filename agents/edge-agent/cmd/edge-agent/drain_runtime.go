package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/drainruntime"
)

const (
	drainActivePlanFile  = "active-plan.json"
	drainPendingPlanFile = "pending-plan.json"
	maxDrainPlanBytes    = 1 << 20
)

var errDrainRuntimeClosed = errors.New("drain runtime is closed")

type drainRuntimeSnapshot struct {
	Enabled       bool               `json:"enabled"`
	Ready         bool               `json:"ready"`
	Running       bool               `json:"running"`
	RunFailed     bool               `json:"run_failed"`
	Pending       bool               `json:"pending"`
	Degraded      bool               `json:"degraded"`
	Phase         drainruntime.Phase `json:"phase,omitempty"`
	LastErrorCode string             `json:"last_error_code,omitempty"`
}

type drainPlanManager interface {
	Process(context.Context, drainruntime.Plan) (drainruntime.Result, error)
	Lookup() (drainruntime.Result, bool, error)
}

type drainRuntimeController interface {
	Recover(context.Context) error
	Run(context.Context) error
	HandleDrainPlan(context.Context, drainruntime.Plan) (drainruntime.Result, error)
	Snapshot() drainRuntimeSnapshot
	Close() error
}

type drainPlanHandler struct {
	stateRoot      string
	manager        drainPlanManager
	resumeInterval time.Duration

	operationMu sync.Mutex
	mu          sync.RWMutex
	plan        *drainruntime.Plan
	snapshot    drainRuntimeSnapshot
	closed      bool
	closeOnce   sync.Once
	closedCh    chan struct{}
}

func newDrainPlanHandler(stateRoot string, manager drainPlanManager, resumeInterval time.Duration) (*drainPlanHandler, error) {
	if !absoluteCleanPath(stateRoot) || stateRoot == string(filepath.Separator) || manager == nil ||
		resumeInterval <= 0 || resumeInterval > time.Minute {
		return nil, drainruntime.ErrInvalidPath
	}
	info, err := os.Lstat(stateRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, drainruntime.ErrInvalidPath
	}
	return &drainPlanHandler{
		stateRoot: stateRoot, manager: manager, resumeInterval: resumeInterval,
		snapshot: drainRuntimeSnapshot{Enabled: true}, closedCh: make(chan struct{}),
	}, nil
}

func assembleDrainRuntime(config fileConfig, timeouts parsedTimeouts, manager *deployment.Manager, runtime *deployment.OpenResty,
	dynamic *dynamicRoutingManager) (drainRuntimeController, error) {
	if !config.DrainRuntime.Enabled {
		return nil, nil
	}
	if dynamic != nil {
		// Dynamic routing: the plan waits for the workers the activation's
		// reload replaced (an activation without a reload has none).
		return newFormalDrainHandler(dynamic, timeouts.DrainResumeInterval), nil
	}
	if manager == nil || runtime == nil {
		return nil, fmt.Errorf("configure drain runtime: formal deployment runtime is required")
	}
	if err := runtime.ConfigureGenerationTracking(filepath.Join(config.DeploymentRoot, "shared", "nginx.pid")); err != nil {
		return nil, fmt.Errorf("configure drain generation tracking: %w", err)
	}
	if err := manager.ConfigureGenerationRuntime(runtime); err != nil {
		return nil, fmt.Errorf("configure deployment generation runtime: %w", err)
	}
	return newFormalDrainHandler(manager, timeouts.DrainResumeInterval), nil
}

func (handler *drainPlanHandler) Recover(ctx context.Context) error {
	if ctx == nil {
		return drainruntime.ErrInvalidPlan
	}
	handler.operationMu.Lock()
	defer handler.operationMu.Unlock()
	if handler.isClosed() {
		return errDrainRuntimeClosed
	}

	active, activeExists, err := handler.readPlan(drainActivePlanFile)
	if err != nil {
		return handler.recoveryFailure(err)
	}
	pending, pendingExists, err := handler.readPlan(drainPendingPlanFile)
	if err != nil {
		return handler.recoveryFailure(err)
	}
	state, found, err := handler.manager.Lookup()
	if err != nil {
		return handler.recoveryFailure(err)
	}
	if activeExists && pendingExists {
		switch {
		case bytes.Equal(active.canonical, pending.canonical):
			if err := handler.removePending(); err != nil {
				return handler.recoveryFailure(err)
			}
		case found && planMatchesResult(pending.compiled, state):
			if err := handler.promotePending(); err != nil {
				return handler.recoveryFailure(err)
			}
			active = pending
		case found && planMatchesResult(active.compiled, state):
			if err := handler.removePending(); err != nil {
				return handler.recoveryFailure(err)
			}
		default:
			return handler.recoveryFailure(drainruntime.ErrCorruptState)
		}
		pendingExists = false
	}
	if !activeExists && pendingExists {
		if !found {
			if err := handler.removePending(); err != nil {
				return handler.recoveryFailure(err)
			}
			handler.setReady(nil)
			return nil
		}
		if !planMatchesResult(pending.compiled, state) {
			return handler.recoveryFailure(drainruntime.ErrCorruptState)
		}
		if err := handler.promotePending(); err != nil {
			return handler.recoveryFailure(err)
		}
		active, activeExists = pending, true
	}
	if activeExists != found || (activeExists && !planMatchesResult(active.compiled, state)) {
		return handler.recoveryFailure(drainruntime.ErrCorruptState)
	}
	if !activeExists {
		handler.setReady(nil)
		return nil
	}

	handler.setPlan(active.compiled.Plan)
	if terminalDrainPhase(state.Phase) {
		handler.applyResult(state, nil)
		return nil
	}
	result, processErr := handler.manager.Process(ctx, active.compiled.Plan)
	if !planMatchesResult(active.compiled, result) {
		return handler.recoveryFailure(coalesceDrainError(processErr))
	}
	handler.applyResult(result, processErr)
	if resumableDrainError(processErr) || result.Phase == drainruntime.PhaseRolledBack {
		return nil
	}
	return processErr
}

func (handler *drainPlanHandler) HandleDrainPlan(ctx context.Context, plan drainruntime.Plan) (drainruntime.Result, error) {
	if ctx == nil {
		return drainruntime.Result{}, drainruntime.ErrInvalidPlan
	}
	if handler.isClosed() {
		return drainruntime.Result{}, errDrainRuntimeClosed
	}
	compiled, err := drainruntime.Compile(plan)
	if err != nil {
		return drainruntime.Result{}, err
	}

	handler.operationMu.Lock()
	defer handler.operationMu.Unlock()
	if handler.isClosed() {
		return drainruntime.Result{}, errDrainRuntimeClosed
	}
	if err := handler.writePending(compiled.CanonicalJSON); err != nil {
		handler.applyFailure("DRAIN_PLAN_PERSIST_FAILED")
		return drainruntime.Result{}, err
	}
	result, processErr := handler.manager.Process(ctx, compiled.Plan)
	if !planMatchesResult(compiled, result) {
		state, found, lookupErr := handler.manager.Lookup()
		if lookupErr == nil && found && planMatchesResult(compiled, state) {
			result = state
		} else {
			if lookupErr != nil {
				handler.applyFailure("DRAIN_STATE_LOOKUP_FAILED")
				return result, errors.Join(processErr, lookupErr)
			}
			_ = handler.removePending()
			return result, processErr
		}
	}
	if err := handler.promotePending(); err != nil {
		handler.applyFailure("DRAIN_PLAN_PROMOTION_FAILED")
		return result, errors.Join(processErr, err)
	}
	handler.setPlan(compiled.Plan)
	handler.applyResult(result, processErr)
	return result, processErr
}

func (handler *drainPlanHandler) Run(ctx context.Context) error {
	if ctx == nil {
		return drainruntime.ErrInvalidPlan
	}
	if handler.isClosed() {
		return errDrainRuntimeClosed
	}
	ticker := time.NewTicker(handler.resumeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-handler.closedCh:
			return errDrainRuntimeClosed
		case <-ticker.C:
			if err := handler.resume(ctx); err != nil {
				return err
			}
		}
	}
}

func (handler *drainPlanHandler) resume(ctx context.Context) error {
	handler.operationMu.Lock()
	defer handler.operationMu.Unlock()
	plan, pending, closed := handler.pendingPlan()
	if closed {
		return errDrainRuntimeClosed
	}
	if !pending || plan == nil {
		return nil
	}
	compiled, err := drainruntime.Compile(*plan)
	if err != nil {
		handler.applyFailure("DRAIN_ACTIVE_PLAN_INVALID")
		return err
	}
	result, processErr := handler.manager.Process(ctx, compiled.Plan)
	if !planMatchesResult(compiled, result) {
		handler.applyFailure("DRAIN_STATE_MISMATCH")
		return coalesceDrainError(processErr)
	}
	handler.applyResult(result, processErr)
	if resumableDrainError(processErr) || result.Phase == drainruntime.PhaseRolledBack {
		return nil
	}
	return processErr
}

func (handler *drainPlanHandler) Snapshot() drainRuntimeSnapshot {
	if handler == nil {
		return drainRuntimeSnapshot{}
	}
	handler.mu.RLock()
	defer handler.mu.RUnlock()
	return handler.snapshot
}

func (handler *drainPlanHandler) Close() error {
	if handler == nil {
		return nil
	}
	handler.closeOnce.Do(func() {
		handler.mu.Lock()
		handler.closed = true
		handler.mu.Unlock()
		close(handler.closedCh)
	})
	return nil
}

type persistedDrainPlan struct {
	compiled  drainruntime.CompiledPlan
	canonical []byte
}

func (handler *drainPlanHandler) readPlan(name string) (persistedDrainPlan, bool, error) {
	path := filepath.Join(handler.stateRoot, name)
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return persistedDrainPlan{}, false, nil
	}
	if err != nil {
		return persistedDrainPlan{}, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 2 || info.Size() > maxDrainPlanBytes {
		return persistedDrainPlan{}, false, drainruntime.ErrCorruptState
	}
	content, err := io.ReadAll(io.LimitReader(file, maxDrainPlanBytes+1))
	if err != nil || len(content) > maxDrainPlanBytes || rejectDuplicateJSONKeys(content) != nil {
		return persistedDrainPlan{}, false, drainruntime.ErrCorruptState
	}
	var plan drainruntime.Plan
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return persistedDrainPlan{}, false, drainruntime.ErrCorruptState
	}
	compiled, err := drainruntime.Compile(plan)
	if err != nil || !bytes.Equal(content, compiled.CanonicalJSON) {
		return persistedDrainPlan{}, false, drainruntime.ErrCorruptState
	}
	return persistedDrainPlan{compiled: compiled, canonical: content}, true, nil
}

func (handler *drainPlanHandler) writePending(content []byte) error {
	temporary, err := os.CreateTemp(handler.stateRoot, ".pending-plan-")
	if err != nil {
		return fmt.Errorf("create pending drain plan: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(handler.stateRoot, drainPendingPlanFile)); err != nil {
		return err
	}
	committed = true
	return syncDrainDirectory(handler.stateRoot)
}

func (handler *drainPlanHandler) promotePending() error {
	if err := os.Rename(filepath.Join(handler.stateRoot, drainPendingPlanFile), filepath.Join(handler.stateRoot, drainActivePlanFile)); err != nil {
		return err
	}
	return syncDrainDirectory(handler.stateRoot)
}

func (handler *drainPlanHandler) removePending() error {
	err := os.Remove(filepath.Join(handler.stateRoot, drainPendingPlanFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDrainDirectory(handler.stateRoot)
}

func syncDrainDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (handler *drainPlanHandler) setPlan(plan drainruntime.Plan) {
	handler.mu.Lock()
	copy := plan
	handler.plan = &copy
	handler.mu.Unlock()
}

func (handler *drainPlanHandler) setReady(plan *drainruntime.Plan) {
	handler.mu.Lock()
	handler.plan = plan
	handler.snapshot = drainRuntimeSnapshot{Enabled: true, Ready: true}
	handler.mu.Unlock()
}

func (handler *drainPlanHandler) applyResult(result drainruntime.Result, processErr error) {
	snapshot := drainRuntimeSnapshot{Enabled: true, Ready: true, Phase: result.Phase}
	snapshot.Pending = !terminalDrainPhase(result.Phase)
	if result.Phase == drainruntime.PhaseRolledBack {
		snapshot.Degraded = true
		snapshot.LastErrorCode = "DRAIN_PLAN_ROLLED_BACK"
	} else if processErr != nil && !resumableDrainError(processErr) {
		snapshot.Degraded = true
		snapshot.LastErrorCode = "DRAIN_RUNTIME_FAILED"
	}
	handler.mu.Lock()
	handler.snapshot = snapshot
	handler.mu.Unlock()
}

func (handler *drainPlanHandler) applyFailure(code string) {
	handler.mu.Lock()
	handler.snapshot.Enabled = true
	handler.snapshot.Degraded = true
	handler.snapshot.LastErrorCode = code
	handler.mu.Unlock()
}

func (handler *drainPlanHandler) recoveryFailure(err error) error {
	handler.applyFailure("DRAIN_RECOVERY_FAILED")
	return err
}

func (handler *drainPlanHandler) pendingPlan() (*drainruntime.Plan, bool, bool) {
	handler.mu.RLock()
	defer handler.mu.RUnlock()
	if handler.plan == nil {
		return nil, handler.snapshot.Pending, handler.closed
	}
	copy := *handler.plan
	return &copy, handler.snapshot.Pending, handler.closed
}

func (handler *drainPlanHandler) isClosed() bool {
	handler.mu.RLock()
	defer handler.mu.RUnlock()
	return handler.closed
}

func terminalDrainPhase(phase drainruntime.Phase) bool {
	return phase == drainruntime.PhaseCompleted || phase == drainruntime.PhaseRolledBack
}

func resumableDrainError(err error) bool {
	return errors.Is(err, drainruntime.ErrHealthPending) || errors.Is(err, drainruntime.ErrDrainInProgress) ||
		errors.Is(err, drainruntime.ErrDrainDeadlineExceeded)
}

func planMatchesResult(compiled drainruntime.CompiledPlan, result drainruntime.Result) bool {
	return result.PlanID == compiled.Plan.PlanID && result.Revision == compiled.Plan.Revision && result.Digest == compiled.Digest
}

func coalesceDrainError(err error) error {
	if err != nil {
		return err
	}
	return drainruntime.ErrCorruptState
}
