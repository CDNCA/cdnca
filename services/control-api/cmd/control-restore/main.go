package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
)

const restorePlanSchema = "cdnca.control-restore.plan/v2"

const (
	restoreIntentSchema    = "cdnca.control-restore.intent/v1"
	restoreIntentStarted   = "started"
	restoreIntentFileLimit = 64 << 10
)

var (
	restoreIdentifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	restoreVersionPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	restoreSHA256Pattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	errRestorePlanMismatch     = errors.New("signed recovery manifest does not match restore plan")
	errRestoreIntentConflict   = errors.New("restore intent conflict")
	errRestoreOutcomeUncertain = errors.New("restore operation outcome is uncertain")
)

type restorePlan struct {
	Schema                     string                        `json:"schema"`
	OperationID                string                        `json:"operation_id"`
	TargetID                   string                        `json:"target_id"`
	MaxSchemaVersion           uint64                        `json:"max_schema_version"`
	ExpectedBackupID           string                        `json:"expected_backup_id"`
	ExpectedSourceClusterID    string                        `json:"expected_source_cluster_id"`
	ExpectedAppVersion         string                        `json:"expected_app_version"`
	ExpectedManifestSHA256     string                        `json:"expected_manifest_sha256"`
	ExpectedCoreManifestSHA256 string                        `json:"expected_core_manifest_sha256"`
	ExpectedEnvelopeKey        controlbackup.SecretReference `json:"expected_envelope_key"`
	SignedManifestFile         string                        `json:"signed_manifest_file"`
	SigningKeyID               string                        `json:"signing_key_id"`
	SigningPublicKeyFile       string                        `json:"signing_public_key_file"`
	DriverPath                 string                        `json:"driver_path"`
	ReceiptDirectory           string                        `json:"receipt_directory"`
}

type restoreIntent struct {
	Schema         string    `json:"schema"`
	OperationID    string    `json:"operation_id"`
	TargetID       string    `json:"target_id"`
	BackupID       string    `json:"backup_id"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	State          string    `json:"state"`
	StartedAt      time.Time `json:"started_at"`
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "control restore failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("control-restore", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	planPath := flags.String("plan", "", "absolute path to the immutable restore plan")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *planPath == "" {
		return errors.New("usage: control-restore --plan ABSOLUTE_PATH")
	}
	encoded, err := controlbackup.ReadTrustedFile(*planPath)
	if err != nil || controlbackup.ValidatePlanSecretFields(encoded) != nil {
		return errors.New("restore plan is unavailable")
	}
	var plan restorePlan
	if err := controlbackup.DecodeStrictJSON(encoded, &plan); err != nil || validateRestorePlan(plan) != nil {
		return errors.New("restore plan is invalid")
	}
	signedEncoded, err := controlbackup.ReadTrustedFile(plan.SignedManifestFile)
	if err != nil {
		return errors.New("signed recovery manifest is unavailable")
	}
	var signed controlbackup.SignedManifest
	if err := controlbackup.DecodeStrictJSON(signedEncoded, &signed); err != nil {
		return errors.New("signed recovery manifest is invalid")
	}
	publicKeyPEM, err := controlbackup.ReadTrustedFile(plan.SigningPublicKeyFile)
	if err != nil {
		return errors.New("recovery signing public key is unavailable")
	}
	publicKey, err := controlbackup.DecodeEd25519PublicKey(publicKeyPEM)
	if err != nil {
		return err
	}
	manifest, err := verifyRestorePlan(plan, signed, publicKey)
	if err != nil {
		return err
	}
	driver, err := controlbackup.NewCommandDriver(plan.DriverPath, os.Environ())
	if err != nil {
		return err
	}
	receipts, err := controlbackup.NewFileReceiptStore(plan.ReceiptDirectory)
	if err != nil {
		return err
	}
	intent := restoreIntent{
		Schema: restoreIntentSchema, OperationID: plan.OperationID, TargetID: plan.TargetID,
		BackupID: manifest.BackupID, ManifestSHA256: signed.PayloadSHA256,
		State: restoreIntentStarted, StartedAt: time.Now().UTC(),
	}
	created, err := putRestoreIntent(plan.ReceiptDirectory, intent)
	if err != nil {
		return err
	}
	if !created {
		if _, found, err := receipts.Get(ctx, plan.OperationID); err != nil {
			return err
		} else if !found {
			return errRestoreOutcomeUncertain
		}
	}
	orchestrator := controlbackup.RestoreOrchestrator{
		Target: driver.Target(),
		Restorers: []controlbackup.ComponentRestorer{
			driver.Restorer(controlbackup.ComponentPostgreSQL),
			driver.Restorer(controlbackup.ComponentClickHouse),
			driver.Restorer(controlbackup.ComponentJetStream),
		},
		Probes: []controlbackup.RecoveryProbe{
			driver.Probe(controlbackup.ProbeDNS),
			driver.Probe(controlbackup.ProbeAgentReconnect),
		},
		Receipts: receipts, PublicKeys: map[string]ed25519.PublicKey{plan.SigningKeyID: publicKey}, Now: time.Now,
	}
	receipt, runErr := orchestrator.Run(ctx, controlbackup.RestoreRequest{
		OperationID: plan.OperationID, TargetID: plan.TargetID,
		SignedManifest: signed, MaxSchemaVersion: plan.MaxSchemaVersion,
	})
	if receipt.OperationID != "" {
		if err := json.NewEncoder(os.Stdout).Encode(receipt); err != nil {
			return err
		}
	}
	return runErr
}

func validateRestorePlan(plan restorePlan) error {
	if plan.Schema != restorePlanSchema || !restoreIdentifierPattern.MatchString(plan.OperationID) ||
		!restoreIdentifierPattern.MatchString(plan.TargetID) || plan.MaxSchemaVersion == 0 ||
		!restoreIdentifierPattern.MatchString(plan.ExpectedBackupID) ||
		!restoreIdentifierPattern.MatchString(plan.ExpectedSourceClusterID) ||
		!restoreVersionPattern.MatchString(plan.ExpectedAppVersion) ||
		!restoreSHA256Pattern.MatchString(plan.ExpectedManifestSHA256) ||
		!restoreSHA256Pattern.MatchString(plan.ExpectedCoreManifestSHA256) ||
		plan.ExpectedEnvelopeKey.Validate() != nil || !restoreIdentifierPattern.MatchString(plan.SigningKeyID) {
		return errRestorePlanMismatch
	}
	return nil
}

func verifyRestorePlan(plan restorePlan, signed controlbackup.SignedManifest, publicKey ed25519.PublicKey) (controlbackup.Manifest, error) {
	if validateRestorePlan(plan) != nil || signed.SigningKeyID != plan.SigningKeyID ||
		signed.PayloadSHA256 != plan.ExpectedManifestSHA256 {
		return controlbackup.Manifest{}, errRestorePlanMismatch
	}
	manifest, err := controlbackup.VerifyManifest(signed, map[string]ed25519.PublicKey{plan.SigningKeyID: publicKey}, controlbackup.ManifestExpectation{
		BackupID: plan.ExpectedBackupID, SourceClusterID: plan.ExpectedSourceClusterID,
		AppVersion: plan.ExpectedAppVersion, MaxSchemaVersion: plan.MaxSchemaVersion,
	})
	if err != nil || manifest.CoreManifestSHA256 != plan.ExpectedCoreManifestSHA256 ||
		manifest.EnvelopeKey != plan.ExpectedEnvelopeKey {
		return controlbackup.Manifest{}, errRestorePlanMismatch
	}
	return manifest, nil
}

func putRestoreIntent(directory string, intent restoreIntent) (bool, error) {
	if err := validateRestoreIntentDirectory(directory); err != nil || validateRestoreIntent(intent) != nil {
		return false, errRestoreIntentConflict
	}
	path := filepath.Join(directory, intent.OperationID+".intent.json")
	if same, conflict, err := matchingRestoreIntent(path, intent); err != nil {
		return false, err
	} else if conflict {
		return false, errRestoreIntentConflict
	} else if same {
		return false, nil
	}
	encoded, err := json.Marshal(intent)
	if err != nil {
		return false, errRestoreIntentConflict
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(directory, "."+intent.OperationID+".intent.*")
	if err != nil {
		return false, errors.New("create restore intent staging")
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, errors.New("secure restore intent staging")
	}
	if _, err := temporary.Write(encoded); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		_ = temporary.Close()
		return false, errors.New("persist restore intent staging")
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if same, conflict, readErr := matchingRestoreIntent(path, intent); readErr == nil && same && !conflict {
			return false, nil
		}
		return false, errRestoreIntentConflict
	}
	if err := os.Remove(temporaryPath); err != nil {
		_ = os.Remove(path)
		return false, errors.New("remove restore intent staging")
	}
	cleanup = false
	directoryHandle, err := os.Open(directory)
	if err != nil {
		_ = os.Remove(path)
		return false, errors.New("open restore intent directory")
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		_ = os.Remove(path)
		_ = directoryHandle.Sync()
		return false, errors.New("sync restore intent directory")
	}
	return true, nil
}

func matchingRestoreIntent(path string, expected restoreIntent) (same, conflict bool, err error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > restoreIntentFileLimit {
		return false, true, errRestoreIntentConflict
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return false, true, errRestoreIntentConflict
	}
	var existing restoreIntent
	if err := controlbackup.DecodeStrictJSON(encoded, &existing); err != nil || validateRestoreIntent(existing) != nil {
		return false, true, errRestoreIntentConflict
	}
	canonical, err := json.Marshal(existing)
	if err != nil || !bytes.Equal(encoded, append(canonical, '\n')) {
		return false, true, errRestoreIntentConflict
	}
	same = existing.Schema == expected.Schema && existing.OperationID == expected.OperationID &&
		existing.TargetID == expected.TargetID && existing.BackupID == expected.BackupID &&
		existing.ManifestSHA256 == expected.ManifestSHA256 && existing.State == expected.State
	return same, !same, nil
}

func validateRestoreIntent(intent restoreIntent) error {
	if intent.Schema != restoreIntentSchema || !restoreIdentifierPattern.MatchString(intent.OperationID) ||
		!restoreIdentifierPattern.MatchString(intent.TargetID) || !restoreIdentifierPattern.MatchString(intent.BackupID) ||
		!restoreSHA256Pattern.MatchString(intent.ManifestSHA256) || intent.State != restoreIntentStarted ||
		intent.StartedAt.IsZero() || intent.StartedAt.Location() != time.UTC {
		return errRestoreIntentConflict
	}
	return nil
}

func validateRestoreIntentDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errRestoreIntentConflict
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errRestoreIntentConflict
	}
	return nil
}
