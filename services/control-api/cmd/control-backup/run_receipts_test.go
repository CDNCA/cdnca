package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
)

type backupCLIFixture struct {
	plan                                       backupPlan
	path, directory, events, ready, driverPlan string
	keys                                       map[string]ed25519.PublicKey
}

func newBackupCLIFixture(t *testing.T, mode string) backupCLIFixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "signing.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}), 0o400); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	driver := filepath.Join(directory, "driver")
	script := "#!/bin/sh\nexec '" + strings.ReplaceAll(executable, "'", "'\\''") + "' -test.run=^TestBackupDriverProcess$ -- \"$@\"\n"
	if err := os.WriteFile(driver, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	driverPlan := filepath.Join(directory, "driver-plan.json")
	contents, _ := json.Marshal(map[string]string{"mode": mode})
	if err := os.WriteFile(driverPlan, contents, 0o400); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	plan := backupPlan{Schema: backupPlanSchema, InstallationID: "11111111-1111-4111-8111-111111111111",
		BackupID: "receipt-test", SourceClusterID: "test-control", DriverPlanSHA256: hex.EncodeToString(digest[:]),
		AppVersion: "1.0.0", SchemaVersion: 252, CoreManifestSHA256: strings.Repeat("c", 64),
		EnvelopeKey:      controlbackup.SecretReference{Provider: "kms", Name: "backup/key", Version: "1"},
		TargetRPOSeconds: 300, TargetRTOSeconds: 1800, SigningKeyID: "run-key",
		SigningPrivateKeyFile: keyPath, DriverPath: driver, ManifestDirectory: directory}
	fixture := backupCLIFixture{plan: plan, directory: directory, path: writeBackupPlan(t, plan),
		events: filepath.Join(directory, "events"), ready: filepath.Join(directory, "ready"), driverPlan: driverPlan,
		keys: map[string]ed25519.PublicKey{"run-key": key.Public().(ed25519.PublicKey)}}
	t.Setenv("CDNCA_BACKUP_TEST_DRIVER", "1")
	t.Setenv("CDNCA_BACKUP_TEST_ROOT", directory)
	t.Setenv("CDNCA_BACKUP_TEST_ORIGINAL", driverPlan)
	t.Setenv("CONTROL_RECOVERY_DRIVER_PLAN", driverPlan)
	return fixture
}

func (fixture backupCLIFixture) read(t *testing.T) controlbackup.VerifiedBackupRun {
	t.Helper()
	verified, err := controlbackup.ReadBackupRun(fixture.directory, fixture.plan.BackupID, fixture.keys,
		controlbackup.BackupRunExpectation{InstallationID: fixture.plan.InstallationID, SourceClusterID: fixture.plan.SourceClusterID})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func (fixture backupCLIFixture) eventText(t *testing.T) string {
	t.Helper()
	encoded, err := os.ReadFile(fixture.events)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestBackupCLIWholeRunFactsAndReplay(t *testing.T) {
	for _, test := range []struct{ mode, state, code string }{
		{"success", "succeeded", "backup_succeeded"},
		{"capture-failure", "failed", "backup_capture_failed"},
		{"invalid-result", "failed", "backup_manifest_failed"},
		{"manifest-failure", "failed", "backup_manifest_failed"},
		{"freeze-failure", "unknown", "backup_outcome_unknown"},
		{"release-failure", "unknown", "backup_outcome_unknown"},
		{"terminal-failure", "unknown", "backup_run_store_failed"},
		{"mutate-original", "succeeded", "backup_succeeded"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			fixture := newBackupCLIFixture(t, test.mode)
			err := run(context.Background(), []string{"--plan", fixture.path})
			if test.state == "succeeded" && err != nil || test.state != "succeeded" && (err == nil || err.Error() != test.code) {
				t.Fatalf("run: %v", err)
			}
			verified := fixture.read(t)
			if test.state == "unknown" && verified.Terminal != nil {
				t.Fatal("unknown was made terminal")
			}
			if test.state != "unknown" && (verified.Terminal == nil || verified.Terminal.State != test.state || verified.Terminal.ResultCode != test.code) {
				t.Fatalf("terminal = %#v", verified.Terminal)
			}
			events := fixture.eventText(t)
			if strings.Count(events, "freeze\n") != 1 {
				t.Fatalf("freeze count: %q", events)
			}
			if test.mode != "freeze-failure" && !strings.HasSuffix(events, "release\n") {
				t.Fatalf("no final release: %q", events)
			}
			if verified.Terminal != nil && verified.Terminal.CompletedAt.Before(verified.Start.StartedAt) {
				t.Fatal("negative run duration")
			}
			// Replay needs no driver binary/config. It returns the original facts.
			if err := os.Rename(fixture.plan.DriverPath, fixture.plan.DriverPath+".done"); err != nil {
				t.Fatal(err)
			}
			replayErr := run(context.Background(), []string{"--plan", fixture.path})
			if test.state == "succeeded" && replayErr != nil || test.state != "succeeded" && replayErr == nil {
				t.Fatalf("replay: %v", replayErr)
			}
			if fixture.eventText(t) != events {
				t.Fatal("replay invoked driver")
			}
			changed := fixture.plan
			changed.SourceClusterID = "other-control"
			if err := run(context.Background(), []string{"--plan", writeBackupPlan(t, changed)}); !errors.Is(err, controlbackup.ErrBackupRunConflict) {
				t.Fatalf("identity conflict: %v", err)
			}
			changed = fixture.plan
			changed.TargetRPOSeconds++
			if err := run(context.Background(), []string{"--plan", writeBackupPlan(t, changed)}); !errors.Is(err, controlbackup.ErrBackupRunConflict) {
				t.Fatalf("plan conflict: %v", err)
			}
		})
	}
}

func TestBackupCLIRejectsLegacyAndDriverDriftBeforeStart(t *testing.T) {
	fixture := newBackupCLIFixture(t, "success")
	legacy := fixture.plan
	legacy.Schema = "cdnca.control-backup.plan/v1"
	if err := run(context.Background(), []string{"--plan", writeBackupPlan(t, legacy)}); err == nil || err.Error() != "backup_plan_v1_requires_upgrade" {
		t.Fatalf("v1: %v", err)
	}
	changed := fixture.plan
	changed.DriverPlanSHA256 = strings.Repeat("f", 64)
	if err := run(context.Background(), []string{"--plan", writeBackupPlan(t, changed)}); err == nil || err.Error() != "backup_driver_plan_mismatch" {
		t.Fatalf("driver drift: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.directory, "runs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid preflight wrote run: %v", err)
	}
	if fixture.eventText(t) != "" {
		t.Fatal("invalid preflight invoked driver")
	}
}

func TestBackupCLIProcess(t *testing.T) {
	if os.Getenv("CDNCA_BACKUP_TEST_CLI") != "1" {
		return
	}
	if err := run(context.Background(), []string{"--plan", os.Getenv("CDNCA_BACKUP_TEST_PLAN")}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(71)
	}
	os.Exit(0)
}

func TestBackupCLIConcurrentProcessesAndCrashWindows(t *testing.T) {
	for _, mode := range []string{"success", "freeze-block", "release-block"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newBackupCLIFixture(t, mode)
			t.Setenv("CDNCA_BACKUP_TEST_CLI", "1")
			t.Setenv("CDNCA_BACKUP_TEST_PLAN", fixture.path)
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-test.run=^TestBackupCLIProcess$")
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }()
			if mode == "success" {
				second := exec.Command(executable, "-test.run=^TestBackupCLIProcess$")
				secondOutput, secondErr := second.CombinedOutput()
				firstErr := command.Wait()
				// Process launch order does not determine the exclusive mkdir winner.
				if firstErr != nil && secondErr != nil {
					t.Fatalf("neither process completed: first=%v %s; second=%v %s", firstErr, output.String(), secondErr, secondOutput)
				}
				terminal := fixture.read(t).Terminal
				if terminal == nil || terminal.State != controlbackup.BackupRunSucceeded || terminal.ResultCode != "backup_succeeded" {
					t.Fatalf("concurrent run has no verified success: %+v", terminal)
				}
				for _, result := range []struct {
					err    error
					output []byte
				}{{firstErr, output.Bytes()}, {secondErr, secondOutput}} {
					if result.err == nil {
						var receipt struct {
							BackupID       string `json:"backup_id"`
							ManifestSHA256 string `json:"manifest_sha256"`
						}
						if json.Unmarshal(result.output, &receipt) != nil || receipt.BackupID != fixture.plan.BackupID || receipt.ManifestSHA256 != terminal.ManifestSHA256 {
							t.Fatalf("successful process did not report the verified receipt: %s", result.output)
						}
						continue
					}
					var exit *exec.ExitError
					code := strings.TrimSpace(string(result.output))
					if !errors.As(result.err, &exit) || exit.ExitCode() != 71 || code != controlbackup.ErrBackupRunUnknown.Error() && code != controlbackup.ErrBackupRunIntegrity.Error() {
						t.Fatalf("unexpected losing process error: %v %s", result.err, result.output)
					}
				}
				if fixture.eventText(t) != "freeze\ncapture\ncapture\ncapture\nrelease\n" {
					t.Fatalf("driver operations were not performed exactly once: %q", fixture.eventText(t))
				}
			} else {
				deadline := time.Now().Add(10 * time.Second)
				for {
					if _, err := os.Stat(fixture.ready); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("driver did not reach crash window")
					}
					time.Sleep(10 * time.Millisecond)
				}
				if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil {
					t.Fatal(err)
				}
				_ = command.Wait()
				if fixture.read(t).Terminal != nil {
					t.Fatal("crashed run has terminal")
				}
				before := fixture.eventText(t)
				if err := run(context.Background(), []string{"--plan", fixture.path}); !errors.Is(err, controlbackup.ErrBackupRunUnknown) {
					t.Fatalf("crash replay: %v", err)
				}
				if fixture.eventText(t) != before {
					t.Fatal("crash replay executed driver")
				}
			}
			if strings.Count(fixture.eventText(t), "freeze\n") != 1 {
				t.Fatal("multiple executions")
			}
		})
	}
}

func TestBackupCLIPartialStartNeverExecutes(t *testing.T) {
	for _, mode := range []string{"missing-start", "malformed-start"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newBackupCLIFixture(t, "success")
			directory := filepath.Join(fixture.directory, "runs", fixture.plan.BackupID)
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if mode == "malformed-start" {
				if err := os.WriteFile(filepath.Join(directory, "start.signed.json"), []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := run(context.Background(), []string{"--plan", fixture.path}); !errors.Is(err, controlbackup.ErrBackupRunIntegrity) {
				t.Fatalf("partial run must fail closed: %v", err)
			}
			if fixture.eventText(t) != "" {
				t.Fatal("partial run invoked the driver")
			}
			if _, err := os.Stat(filepath.Join(directory, "terminal.signed.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial run acquired a terminal: %v", err)
			}
		})
	}
}

// This subprocess is deliberately a fault-injection driver, not a real backup.
func TestBackupDriverProcess(t *testing.T) {
	if os.Getenv("CDNCA_BACKUP_TEST_DRIVER") != "1" {
		return
	}
	var arguments []string
	for index, arg := range os.Args {
		if arg == "--" {
			arguments = os.Args[index+1:]
			break
		}
	}
	if len(arguments) == 0 {
		os.Exit(2)
	}
	operation := arguments[0]
	root := os.Getenv("CDNCA_BACKUP_TEST_ROOT")
	runDir := filepath.Join(root, "runs", "receipt-test")
	if _, err := os.Stat(filepath.Join(runDir, "start.signed.json")); err != nil {
		os.Exit(3)
	}
	if _, err := os.Stat(filepath.Join(runDir, "terminal.signed.json")); !errors.Is(err, os.ErrNotExist) {
		os.Exit(4)
	}
	encoded, err := os.ReadFile(os.Getenv("CONTROL_RECOVERY_DRIVER_PLAN"))
	if err != nil {
		os.Exit(5)
	}
	var plan struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal(encoded, &plan) != nil {
		os.Exit(6)
	}
	file, err := os.OpenFile(filepath.Join(root, "events"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(7)
	}
	_, _ = fmt.Fprintln(file, operation)
	_ = file.Sync()
	_ = file.Close()
	fail := func() { _, _ = fmt.Fprint(os.Stdout, `{"error_code":"test_injected_failure"}`); os.Exit(9) }
	if plan.Mode == operation+"-failure" {
		fail()
	}
	if plan.Mode == operation+"-block" {
		_ = os.WriteFile(filepath.Join(root, "ready"), []byte(operation), 0o600)
		for {
			time.Sleep(time.Hour)
		}
	}
	if operation == "freeze" {
		if plan.Mode == "mutate-original" {
			_ = os.Chmod(os.Getenv("CDNCA_BACKUP_TEST_ORIGINAL"), 0o600)
			_ = os.WriteFile(os.Getenv("CDNCA_BACKUP_TEST_ORIGINAL"), []byte(`{"mode":"capture-failure"}`), 0o400)
		}
		_, _ = fmt.Fprint(os.Stdout, `{"freeze_id":"freeze-test"}`)
		os.Exit(0)
	}
	if operation == "capture" {
		var component controlbackup.Component
		for index, arg := range arguments {
			if arg == "--component" {
				component = controlbackup.Component(arguments[index+1])
			}
		}
		checkpoint := controlbackup.ComponentCheckpoint{Component: component, BackupID: "receipt-test", WriteFreezeID: "freeze-test",
			SnapshotID: "snapshot-" + string(component), Revision: 1, CapturedAt: time.Now().UTC().Add(-time.Second), SHA256: strings.Repeat("a", 64), SizeBytes: 10}
		if component == controlbackup.ComponentJetStream {
			checkpoint.JetStreamTopology = controlbackup.RequiredJetStreamTopology()
			if plan.Mode == "manifest-failure" {
				_ = os.Mkdir(filepath.Join(root, "receipt-test.signed.json"), 0o700)
			}
		}
		if plan.Mode == "invalid-result" {
			checkpoint.SHA256 = "bad"
		}
		_ = json.NewEncoder(os.Stdout).Encode(checkpoint)
		os.Exit(0)
	}
	if operation == "release" {
		if plan.Mode == "terminal-failure" {
			_ = os.Mkdir(filepath.Join(runDir, "terminal.signed.json.tmp"), 0o700)
		}
		os.Exit(0)
	}
	os.Exit(8)
}
