package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nativeruntime"
	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// Native node runtime switch (node-runtime-upgrade). A native node
// (security_runtime.mode native, /opt/cdnca-node) runs the OpenResty/Lua
// runtime of its Agent's version: before the daemon is assembled the Agent
// verifies the signed native package beside it and, when its runtime
// differs, switches /opt/cdnca-node/current and config.json (Prepare); after
// the dynamic routing runtime adopted the running master, Commit hot
// upgrades it and the resumed L4 master the same way (nginx binary upgrade;
// the old master then gets QUIT, TERM after 10 seconds and KILL 5 seconds
// later, cutting the sessions it still holds; KillMode=process keeps both
// masters across the restart).

const (
	nativeRuntimeRoot       = "/opt/cdnca-node"
	nativeRuntimeStatusName = "native-runtime/status.json"
)

func nativeRuntimeStatusPath(config fileConfig) string {
	return filepath.Join(filepath.Dir(config.JournalDir), nativeRuntimeStatusName)
}

func nativeRuntimeNode(config fileConfig) bool {
	return config.SecurityRuntime.Mode == securityRuntimeModeNative
}

// pendingNativeRuntime is the switch Prepare left for the daemon to commit
// once dynamic routing adopted the running master (one per process).
var pendingNativeRuntime *nativeruntime.Pending

func startNativeRuntimeSwitch(ctx context.Context, path string, config fileConfig, timeouts parsedTimeouts,
	load func(string) (fileConfig, parsedTimeouts, error)) (fileConfig, parsedTimeouts) {
	config, timeouts, pendingNativeRuntime = prepareNativeRuntime(ctx, path, config, timeouts, load)
	return config, timeouts
}

// commitNativeRuntime hot upgrades the adopted masters to the switched
// binary (no-op without a pending switch).
func commitNativeRuntime(ctx context.Context, masters ...nativeruntime.Master) {
	pending := pendingNativeRuntime
	pendingNativeRuntime = nil
	if !pending.Switched() {
		return
	}
	if err := pending.Commit(ctx, masters...); err != nil {
		slog.Warn("native runtime switch undone", "event", "native_runtime_failed",
			"code", nativeruntime.Code(err), "error", safeLogError(err))
		return
	}
	status := pending.Status()
	slog.Info("native runtime switched", "event", "native_runtime_switched", "release", status.Release,
		"previous_release", status.PreviousRelease, "openresty_version", status.OpenRestyVersion)
}

// prepareNativeRuntime runs before assembly; a switch rewrites config.json,
// which is then loaded again. A failure keeps the previous runtime (the
// status tells the upgrade probe); the Agent still starts on it.
func prepareNativeRuntime(ctx context.Context, path string, config fileConfig, timeouts parsedTimeouts,
	load func(string) (fileConfig, parsedTimeouts, error)) (fileConfig, parsedTimeouts, *nativeruntime.Pending) {
	if !nativeRuntimeNode(config) {
		return config, timeouts, nil
	}
	trust, err := gatewayclient.LoadTrustStore(config.ArtifactTrustFile)
	if err != nil {
		slog.Warn("native runtime switch skipped", "event", "native_runtime_failed", "error", safeLogError(err))
		return config, timeouts, nil
	}
	executable, err := os.Executable()
	if err != nil {
		slog.Warn("native runtime switch skipped", "event", "native_runtime_failed", "error", safeLogError(err))
		return config, timeouts, nil
	}
	if resolved, resolveErr := filepath.EvalSymlinks(executable); resolveErr == nil {
		executable = resolved
	}
	precheck := func(ctx context.Context) error {
		return precheckNativeRuntime(ctx, config)
	}
	pending, err := nativeruntime.Prepare(ctx, nativeruntime.Config{
		Root:         nativeRuntimeRoot,
		PackagePath:  filepath.Join(helper.ProductionReleaseRoot, "versions", agentVersion, helper.NativeSectionName),
		AgentPath:    executable,
		AgentVersion: agentVersion,
		ConfigPath:   path,
		StatusPath:   nativeRuntimeStatusPath(config),
		Keys:         trust.Ed25519Subset(),
		Timeout:      2 * time.Minute,
	}, precheck)
	if err != nil {
		slog.Warn("native runtime kept at the previous version", "event", "native_runtime_failed",
			"code", nativeruntime.Code(err), "error", safeLogError(err))
		return config, timeouts, nil
	}
	status := pending.Status()
	if !pending.Switched() {
		slog.Info("native runtime unchanged", "event", "native_runtime_unchanged", "release", status.Release,
			"openresty_version", status.OpenRestyVersion)
		return config, timeouts, nil
	}
	reloaded, reloadedTimeouts, err := load(path)
	if err != nil {
		abortErr := pending.Abort(err)
		slog.Warn("native runtime switch undone", "event", "native_runtime_failed",
			"code", nativeruntime.Code(abortErr), "error", safeLogError(abortErr))
		return config, timeouts, nil
	}
	slog.Info("native runtime files switched", "event", "native_runtime_prepared", "release", status.Release,
		"previous_release", status.PreviousRelease, "openresty_version", status.OpenRestyVersion)
	return reloaded, reloadedTimeouts, pending
}

// precheckNativeRuntime: `openresty -t` and an init-only load (init_by_lua,
// nothing listens) of the live dynamic routing configuration through the
// switched link. Never applied: nothing to check.
func precheckNativeRuntime(ctx context.Context, config fileConfig) error {
	_, shared := dynamicRoutingRoots(config)
	conf := filepath.Join(shared, "nginx.conf")
	if _, err := os.Stat(conf); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return nativeruntime.PrecheckOpenResty(ctx, config.OpenResty.Binary, shared+"/", conf, dynamicRoutingGlobals(config))
}

// nativeRuntimeHealth is the upgrade health probe's view: the runtime of
// this Agent's version is active. Not a native node: always healthy.
func nativeRuntimeHealth(config fileConfig) error {
	if !nativeRuntimeNode(config) {
		return nil
	}
	status, err := nativeruntime.ReadStatus(nativeRuntimeStatusPath(config))
	if err != nil {
		return nativeruntime.HealthError(nativeruntime.Status{}, agentVersion)
	}
	return nativeruntime.HealthError(status, agentVersion)
}

var (
	nativeRuntimeReleasePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nativeRuntimeCodePattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

// nativeRuntimeReport is the heartbeat's EdgeRuntimeStatus.native_runtime:
// the status this Agent's start wrote (nil when absent, unreadable or from
// another Agent). ROLLED_BACK is a failed switch, or an unchanged runtime
// after the updater rolled back the Agent whose switch failed; release is
// then the runtime that failed and previous_release the one kept active.
// Values outside the wire format are left out, never sent.
func nativeRuntimeReport(statusPath string) *agentv1.NativeRuntimeStatus {
	status, err := nativeruntime.ReadStatus(statusPath)
	if err != nil || status.AgentVersion != agentVersion {
		return nil
	}
	var report *agentv1.NativeRuntimeStatus
	switch {
	case status.State == nativeruntime.StateSwitched:
		report = &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_SWITCHED,
			Release: status.Release, PreviousRelease: status.PreviousRelease}
	case status.State == nativeruntime.StateUnchanged && status.RolledBack != nil:
		report = &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK,
			Release: status.RolledBack.Release, PreviousRelease: status.Release, ErrorCode: status.RolledBack.ErrorCode}
	case status.State == nativeruntime.StateUnchanged:
		report = &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_UNCHANGED,
			Release: status.Release}
	case status.State == nativeruntime.StateFailed:
		report = &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK,
			Release: status.Release, PreviousRelease: status.PreviousRelease, ErrorCode: status.ErrorCode}
	default:
		return nil
	}
	if !nativeRuntimeReleasePattern.MatchString(report.Release) {
		report.Release = ""
	}
	if !nativeRuntimeReleasePattern.MatchString(report.PreviousRelease) {
		report.PreviousRelease = ""
	}
	if report.State != agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK || !nativeRuntimeCodePattern.MatchString(report.ErrorCode) {
		report.ErrorCode = ""
	}
	return report
}
