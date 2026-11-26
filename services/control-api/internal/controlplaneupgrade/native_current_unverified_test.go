//go:build !windows

package controlplaneupgrade

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Issue 43: files copied over the current release (a hot update) no longer
// match its signed manifest. The runner must start, stay not ready with a
// stable reason, refuse every plan without touching anything, and recover
// once the release matches again.
func TestNativeUnverifiedCurrentReleaseKeepsRunnerUpAndRefusesPlans(t *testing.T) {
	for _, drift := range []struct{ name, path, check string }{
		{"binary replaced", "bin/control-api", "bin/control-api"},
		{"backup left beside binary", "bin/control-api.bak-20261121023703", "file_not_in_manifest bin/control-api.bak-20261121023703"},
	} {
		t.Run(drift.name, func(t *testing.T) {
			fixture := newNativeFixture(t)
			config, trust, store, now := fixture.runner.executor.config, fixture.runner.runner.trust, fixture.runner.runner.store, fixture.runner.runner.now
			if err := fixture.runner.Close(); err != nil {
				t.Fatal(err)
			}
			release := fixture.runner.executor.release(fixture.old)
			target := filepath.Join(release, drift.path)
			original, readErr := os.ReadFile(target)
			if err := os.WriteFile(target, nativeELF("1.4.0hotfix"), 0o755); err != nil {
				t.Fatal(err)
			}
			maintenanceBefore, err := os.ReadFile(config.MaintenanceFile)
			if err != nil {
				t.Fatal(err)
			}

			runner, err := newNativeStandaloneRunner(config, trust, store, now, uint32(os.Getuid()), fixture.commands, fixture.commands.inspect)
			if err != nil {
				t.Fatalf("runner must start on an unverified current release: %v", err)
			}
			fixture.runner = runner
			status, err := runner.Probe(t.Context())
			if !errors.Is(err, ErrTargetMismatch) || !strings.Contains(err.Error(), drift.check) || status.Ready ||
				status.Reason != NativeReasonCurrentReleaseUnverified || status.CurrentVersion != "" {
				t.Fatalf("probe: %+v %v", status, err)
			}
			filename := filepath.Join(config.ReleaseRoot, "runner-status.json")
			if err := runner.PublishStatus(t.Context(), filename); err != nil {
				t.Fatal(err)
			}
			published, err := readNativeStandaloneStatus(filename, fixture.installationID(), now(), uint32(os.Getuid()), fixture.commands.inspect)
			if err != nil || published.Ready || published.Reason != NativeReasonCurrentReleaseUnverified {
				t.Fatalf("published status not observable: %+v %v", published, err)
			}

			if _, err := runner.Run(t.Context(), fixture.bundle); !errors.Is(err, ErrTargetMismatch) {
				t.Fatalf("plan executed on an unverified release: %v", err)
			}
			if _, err := store.Load(); !errors.Is(err, ErrStateNotFound) {
				t.Fatalf("refused plan left durable state: %v", err)
			}
			maintenanceAfter, err := os.ReadFile(config.MaintenanceFile)
			if err != nil || !bytes.Equal(maintenanceBefore, maintenanceAfter) || fixture.commands.restarts != 0 || fixture.commands.stops != 0 {
				t.Fatalf("refused plan changed the host: maintenance=%s restarts=%d stops=%d", maintenanceAfter, fixture.commands.restarts, fixture.commands.stops)
			}
			if link, err := os.Readlink(filepath.Join(config.ReleaseRoot, "current")); err != nil || filepath.Base(link) != fixture.old.Digest {
				t.Fatalf("current moved: %s %v", link, err)
			}

			if readErr == nil {
				err = os.WriteFile(target, original, 0o755)
			} else {
				err = os.Remove(target)
			}
			if err != nil {
				t.Fatal(err)
			}
			if status, err := runner.Probe(t.Context()); err != nil || !status.Ready || status.CurrentVersion != "1.4.0" {
				t.Fatalf("restored release not ready without restart: %+v %v", status, err)
			}
		})
	}
}
