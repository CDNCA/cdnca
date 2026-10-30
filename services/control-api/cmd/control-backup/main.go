package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
	"github.com/google/uuid"
)

const backupPlanSchema = "cdnca.control-backup.plan/v2"

var (
	backupIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	backupVersionPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	backupSHA256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type backupPlan struct {
	Schema                string                        `json:"schema"`
	InstallationID        string                        `json:"installation_id"`
	DriverPlanSHA256      string                        `json:"driver_plan_sha256"`
	BackupID              string                        `json:"backup_id"`
	BackupIDEnvironment   string                        `json:"backup_id_environment"`
	SourceClusterID       string                        `json:"source_cluster_id"`
	AppVersion            string                        `json:"app_version"`
	SchemaVersion         uint64                        `json:"schema_version"`
	CoreManifestSHA256    string                        `json:"core_manifest_sha256"`
	EnvelopeKey           controlbackup.SecretReference `json:"envelope_key"`
	TargetRPOSeconds      int64                         `json:"target_rpo_seconds"`
	TargetRTOSeconds      int64                         `json:"target_rto_seconds"`
	SigningKeyID          string                        `json:"signing_key_id"`
	SigningPrivateKeyFile string                        `json:"signing_private_key_file"`
	DriverPath            string                        `json:"driver_path"`
	ManifestDirectory     string                        `json:"manifest_directory"`
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "control backup failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("control-backup", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	planPath := flags.String("plan", "", "absolute path to the immutable backup plan")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *planPath == "" {
		return errors.New("usage: control-backup --plan ABSOLUTE_PATH")
	}
	encoded, err := controlbackup.ReadTrustedFile(*planPath)
	if err != nil || controlbackup.ValidatePlanSecretFields(encoded) != nil {
		return errors.New("backup plan is unavailable")
	}
	var plan backupPlan
	if err := controlbackup.DecodeStrictJSON(encoded, &plan); err != nil {
		return errors.New("backup plan is invalid")
	}
	if plan.Schema == "cdnca.control-backup.plan/v1" {
		return errors.New("backup_plan_v1_requires_upgrade")
	}
	targetRPO, targetRTO, err := validateBackupPlan(plan)
	if err != nil {
		return errors.New("backup plan is invalid")
	}
	privateKeyPEM, err := controlbackup.ReadTrustedFile(plan.SigningPrivateKeyFile)
	if err != nil {
		return errors.New("backup signing key is unavailable")
	}
	defer clearBytes(privateKeyPEM)
	privateKey, err := controlbackup.DecodeEd25519PrivateKey(privateKeyPEM)
	if err != nil {
		return err
	}
	defer clearBytes(privateKey)
	backupID := plan.BackupID
	if backupID == "" {
		backupID = os.Getenv(plan.BackupIDEnvironment)
	}
	if !backupIdentifierPattern.MatchString(backupID) {
		return errors.New("backup identity is unavailable")
	}
	effectivePlan := plan
	effectivePlan.BackupID, effectivePlan.BackupIDEnvironment = backupID, ""
	canonicalPlan, err := json.Marshal(effectivePlan)
	if err != nil {
		return controlbackup.ErrBackupRunInvalid
	}
	planDigest := sha256.Sum256(canonicalPlan)
	expected := controlbackup.BackupRunExpectation{InstallationID: plan.InstallationID,
		SourceClusterID: plan.SourceClusterID, BackupID: backupID, PlanSHA256: hex.EncodeToString(planDigest[:])}
	// The CLI trusts only the configured signing key, never a key supplied by a receipt.
	keys := map[string]ed25519.PublicKey{plan.SigningKeyID: privateKey.Public().(ed25519.PublicKey)}
	runs, err := controlbackup.NewFileBackupRunStore(plan.ManifestDirectory, keys, expected)
	if err != nil {
		return err
	}
	runDirectory := filepath.Join(plan.ManifestDirectory, "runs", backupID)
	if _, err := os.Lstat(runDirectory); !errors.Is(err, os.ErrNotExist) {
		previous, readErr := controlbackup.ReadBackupRun(plan.ManifestDirectory, backupID, keys, expected)
		if readErr != nil {
			return readErr
		}
		return replayBackupRun(previous)
	}
	driverPlan, err := controlbackup.ReadTrustedFile(os.Getenv("CONTROL_RECOVERY_DRIVER_PLAN"))
	if err != nil {
		return errors.New("backup_driver_plan_unavailable")
	}
	driverDigest := sha256.Sum256(driverPlan)
	if hex.EncodeToString(driverDigest[:]) != plan.DriverPlanSHA256 {
		return errors.New("backup_driver_plan_mismatch")
	}
	// The driver reads this exact verified snapshot, not a mutable original path.
	driverPlanPath := filepath.Join(runDirectory, "driver-plan.json")
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "CONTROL_RECOVERY_DRIVER_PLAN=") {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "CONTROL_RECOVERY_DRIVER_PLAN="+driverPlanPath)
	driver, err := controlbackup.NewCommandDriver(plan.DriverPath, environment)
	if err != nil {
		return err
	}
	store, err := controlbackup.NewFileManifestStore(plan.ManifestDirectory)
	if err != nil {
		return err
	}
	started, created, err := runs.Begin(controlbackup.BackupRunStart{
		Schema: controlbackup.BackupRunStartSchema, BackupID: backupID, InstallationID: plan.InstallationID,
		SourceClusterID: plan.SourceClusterID, PlanSHA256: expected.PlanSHA256, StartedAt: time.Now().UTC(),
	}, plan.SigningKeyID, privateKey)
	if err != nil {
		return err
	}
	if !created {
		return replayBackupRun(started)
	}
	if err := writePinnedDriverPlan(driverPlanPath, driverPlan); err != nil {
		return controlbackup.ErrBackupRunStore
	}
	orchestrator := controlbackup.BackupOrchestrator{
		Freeze: driver.FreezeController(),
		Capturers: []controlbackup.ComponentCapturer{
			driver.Capturer(controlbackup.ComponentPostgreSQL),
			driver.Capturer(controlbackup.ComponentClickHouse),
			driver.Capturer(controlbackup.ComponentJetStream),
		},
		Store: store, SigningKeyID: plan.SigningKeyID, PrivateKey: privateKey, Now: time.Now,
	}
	result, runErr := orchestrator.Run(ctx, controlbackup.BackupRequest{
		BackupID: backupID, SourceClusterID: plan.SourceClusterID, AppVersion: plan.AppVersion,
		SchemaVersion: plan.SchemaVersion, CoreManifestSHA256: plan.CoreManifestSHA256,
		EnvelopeKey: plan.EnvelopeKey, TargetRPO: targetRPO, TargetRTO: targetRTO,
	})
	terminal := controlbackup.BackupRunTerminal{Schema: controlbackup.BackupRunTerminalSchema,
		BackupID: backupID, StartSHA256: started.SignedStart.PayloadSHA256, CompletedAt: time.Now().UTC(),
		State: controlbackup.BackupRunSucceeded, ResultCode: "backup_succeeded"}
	if runErr != nil {
		var failure *controlbackup.BackupRunError
		if !errors.As(runErr, &failure) || failure.OutcomeUnknown {
			return controlbackup.ErrBackupRunUnknown
		}
		terminal.State, terminal.ResultCode = controlbackup.BackupRunFailed, failure.Code
	} else {
		terminal.ManifestSHA256 = result.SignedManifest.PayloadSHA256
		terminal.RecoveryPointAt = &result.Manifest.RecoveryPointAt
		terminal.ObservedRPOSeconds = &result.Manifest.Objectives.ObservedRPOSeconds
	}
	finished, err := runs.Finish(terminal, plan.SigningKeyID, privateKey)
	if err != nil {
		return err
	}
	return replayBackupRun(finished)
}

func validateBackupPlan(plan backupPlan) (time.Duration, time.Duration, error) {
	installationID, installationErr := uuid.Parse(plan.InstallationID)
	if installationErr != nil || installationID == uuid.Nil || installationID.String() != plan.InstallationID ||
		!backupSHA256Pattern.MatchString(plan.DriverPlanSHA256) || plan.Schema != backupPlanSchema || ((plan.BackupID == "") == (plan.BackupIDEnvironment == "")) ||
		(plan.BackupID != "" && !backupIdentifierPattern.MatchString(plan.BackupID)) ||
		(plan.BackupIDEnvironment != "" && !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`).MatchString(plan.BackupIDEnvironment)) ||
		!backupIdentifierPattern.MatchString(plan.SourceClusterID) ||
		!backupVersionPattern.MatchString(plan.AppVersion) || plan.SchemaVersion == 0 ||
		!backupSHA256Pattern.MatchString(plan.CoreManifestSHA256) ||
		!backupIdentifierPattern.MatchString(plan.SigningKeyID) || plan.EnvelopeKey.Validate() != nil {
		return 0, 0, errors.New("invalid backup plan binding")
	}
	targetRPO, err := planDuration(plan.TargetRPOSeconds)
	if err != nil {
		return 0, 0, err
	}
	targetRTO, err := planDuration(plan.TargetRTOSeconds)
	if err != nil {
		return 0, 0, err
	}
	return targetRPO, targetRTO, nil
}

func planDuration(seconds int64) (time.Duration, error) {
	const maximum = 365 * 24 * time.Hour
	if seconds <= 0 || seconds > int64(maximum/time.Second) {
		return 0, errors.New("duration is outside the supported range")
	}
	return time.Duration(seconds) * time.Second, nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func replayBackupRun(run controlbackup.VerifiedBackupRun) error {
	if run.Terminal == nil {
		return controlbackup.ErrBackupRunUnknown
	}
	if run.Terminal.State == controlbackup.BackupRunFailed {
		return &controlbackup.BackupRunError{Code: run.Terminal.ResultCode}
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		BackupID        string `json:"backup_id"`
		ManifestSHA256  string `json:"manifest_sha256"`
		RecoveryPointAt string `json:"recovery_point_at"`
		ObservedRPO     int64  `json:"observed_rpo_seconds"`
	}{run.Start.BackupID, run.Terminal.ManifestSHA256,
		run.Terminal.RecoveryPointAt.Format(time.RFC3339Nano), *run.Terminal.ObservedRPOSeconds})
}

func writePinnedDriverPlan(path string, encoded []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
