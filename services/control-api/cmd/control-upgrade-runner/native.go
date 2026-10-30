package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

type nativeStatusRunner interface {
	controlUpgradePlanRunner
	Probe(context.Context) (controlplaneupgrade.NativeStandaloneStatus, error)
	PublishStatus(context.Context, string) error
}

func runNativeStandalone(ctx context.Context, installationID string, trust *entitlementguard.TrustStore,
	store *controlplaneupgrade.FileStore) error {
	protocol, err := integerEnv("CONTROL_UPGRADE_PROTOCOL_VERSION", 1)
	if err != nil {
		return err
	}
	artifactKeys, err := readNativeArtifactTrust(requiredEnv("CDNCA_NATIVE_UPGRADE_ARTIFACT_TRUST_FILE"), 0)
	if err != nil {
		return err
	}
	step, err := durationEnv("CONTROL_UPGRADE_STEP_TIMEOUT", 3*time.Minute)
	if err != nil {
		return err
	}
	health, err := durationEnv("CONTROL_UPGRADE_HEALTH_TIMEOUT", 2*time.Minute)
	if err != nil {
		return err
	}
	poll, err := durationEnv("CONTROL_UPGRADE_POLL_INTERVAL", 5*time.Second)
	if err != nil {
		return err
	}
	database, err := durationEnv("CDNCA_NATIVE_UPGRADE_DATABASE_TIMEOUT", 30*time.Minute)
	if err != nil {
		return err
	}
	httpSource, lkg, initial, err := openHTTPPlanRuntime(installationID)
	if err != nil {
		return err
	}
	source := &nativePlanSource{source: httpSource, now: time.Now}
	// The native constructor owns runner.lock for its lifetime. This branch must
	// never also acquire the legacy command-level runner lock.
	runner, err := controlplaneupgrade.NewNativeStandaloneRunner(controlplaneupgrade.NativeStandaloneConfig{
		InstallationID: installationID, ProtocolVersion: protocol, ReleaseRoot: requiredEnv("CONTROL_UPGRADE_RELEASE_ROOT"),
		LockPath:           requiredEnv("CDNCA_NATIVE_UPGRADE_RELEASE_LOCK_FILE"),
		SourceGitDirectory: requiredEnv("CDNCA_NATIVE_UPGRADE_SOURCE_GIT_DIR"),
		ArtifactPublicKeys: artifactKeys,
		ControlUnit:        requiredEnv("CDNCA_NATIVE_UPGRADE_CONTROL_UNIT"), GatewayUnit: requiredEnv("CDNCA_NATIVE_UPGRADE_GATEWAY_UNIT"),
		ControlHealthURL: requiredEnv("CDNCA_NATIVE_UPGRADE_CONTROL_HEALTH_URL"),
		GatewayHealthURL: requiredEnv("CDNCA_NATIVE_UPGRADE_GATEWAY_HEALTH_URL"),
		WebIndexURL:      requiredEnv("CDNCA_NATIVE_UPGRADE_WEB_INDEX_URL"),
		WebCAFile:        requiredEnv("CDNCA_NATIVE_UPGRADE_WEB_CA_FILE"),
		MaintenanceFile:  requiredEnv("CDNCA_NATIVE_UPGRADE_MAINTENANCE_FILE"),
		PollInterval:     time.Second, StepTimeout: step, HealthTimeout: health,
		DatabaseToolsDirectory: requiredEnv("CDNCA_NATIVE_UPGRADE_DATABASE_TOOLS_DIR"), DatabaseTimeout: database,
		PlanSourceReady: source.Ready,
	}, trust, store, time.Now)
	if err != nil {
		return err
	}
	defer runner.Close()
	verify := newNativePlanVerifier(ctx, trust, installationID, protocol, store, runner, time.Now)
	return runNativeWithStatus(ctx, runner, requiredEnv("CDNCA_NATIVE_UPGRADE_STATUS_FILE"),
		5*time.Second, func(runCtx context.Context) error {
			return runPlanLoop(runCtx, source, lkg, initial, runner, verify, poll,
				strings.EqualFold(requiredEnv("CONTROL_UPGRADE_ONESHOT"), "true"), slog.Default())
		})
}

func newNativePlanVerifier(ctx context.Context, trust *entitlementguard.TrustStore, installationID string,
	protocol int, store *controlplaneupgrade.FileStore, runner nativeStatusRunner, now func() time.Time) httpPlanVerifier {
	return func(encoded []byte) error {
		signed, err := entitlement.DecodeUpgradePlanArtifactBundle(encoded)
		if err != nil {
			return controlplaneupgrade.ErrInvalidPlan
		}
		if err := newHTTPPlanVerifier(trust, installationID, signed.Bundle.CurrentVersion, protocol, now)(encoded); err != nil {
			return err
		}
		state, err := store.Load()
		if err != nil && !errors.Is(err, controlplaneupgrade.ErrStateNotFound) {
			return err
		}
		if err == nil && state.BundleSHA256 == fmt.Sprintf("%x", sha256.Sum256(encoded)) {
			// A previously verified durable plan may resume an interrupted drain or
			// return its terminal receipt. The library revalidates exact bindings.
			return nil
		}
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		status, err := runner.Probe(probeCtx)
		if err != nil || !status.Ready || status.Busy || status.Phase != "idle" || status.Reason != "ready" ||
			status.CurrentVersion != signed.Bundle.CurrentVersion || status.InstallationID != installationID ||
			status.ProtocolVersion != protocol ||
			(status.ArtifactFormat != controlplaneupgrade.NativeManifestSchema && status.ArtifactFormat != controlplaneupgrade.NativeManifestSignedSchema) {
			return controlplaneupgrade.ErrTargetMismatch
		}
		return nil
	}
}

func readNativeArtifactTrust(filename string, owner uint32) (map[string]ed25519.PublicKey, error) {
	if filename == "" {
		return nil, nil
	}
	invalid := errors.New("native artifact trust file is not independently provisioned or is invalid")
	if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
		return nil, invalid
	}
	resolved, err := filepath.EvalSymlinks(filename)
	if err != nil || resolved != filename {
		return nil, invalid
	}
	for parent := filepath.Dir(filename); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return nil, invalid
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || stat.Uid != owner || (info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return nil, invalid
		}
		if owner != 0 || parent == "/" {
			break
		}
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, invalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 65536 || info.Mode().Perm()&0o022 != 0 {
		return nil, invalid
	}
	encoded, err := readStableRegularFile(filename, info, 65536)
	if err != nil {
		return nil, invalid
	}
	keys, err := controlplaneupgrade.DecodeNativeArtifactTrust(encoded)
	if err != nil {
		return nil, invalid
	}
	return keys, nil
}

func runNativeWithStatus(ctx context.Context, runner nativeStatusRunner, path string, interval time.Duration,
	loop func(context.Context) error) error {
	if ctx == nil || runner == nil || loop == nil || interval <= 0 || interval > 10*time.Second {
		return controlplaneupgrade.ErrInvalidConfig
	}
	parent := ctx
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	publish := func(ctx context.Context) error {
		probeCtx, done := context.WithTimeout(ctx, 5*time.Second)
		defer done()
		return runner.PublishStatus(probeCtx, path)
	}
	if err := publish(ctx); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- nil
				return
			case <-ticker.C:
				if err := publish(ctx); err != nil {
					if ctx.Err() != nil {
						done <- nil
						return
					}
					cancel()
					done <- err
					return
				}
			}
		}
	}()
	err := loop(ctx)
	cancel()
	if statusErr := <-done; statusErr != nil {
		return statusErr
	}
	// Stop the heartbeat before the final projection, so an in-flight cancelled
	// probe cannot overwrite the terminal state. The final probe remains bounded.
	if statusErr := publish(context.WithoutCancel(parent)); statusErr != nil {
		return statusErr
	}
	return err
}
