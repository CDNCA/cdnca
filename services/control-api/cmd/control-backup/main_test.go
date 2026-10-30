package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
)

func TestRunRejectsInvalidBackupPlanBeforeReadingKeysOrDriver(t *testing.T) {
	t.Parallel()

	valid := backupPlan{
		InstallationID: "11111111-1111-4111-8111-111111111111", DriverPlanSHA256: strings.Repeat("b", 64),
		Schema: backupPlanSchema, BackupID: "backup-ops12-20260809", SourceClusterID: "customer-control-a",
		AppVersion: "1.8.0", SchemaVersion: 176, CoreManifestSHA256: strings.Repeat("a", 64),
		EnvelopeKey:      controlbackup.SecretReference{Provider: "kms", Name: "control-backup/customer-a", Version: "42"},
		TargetRPOSeconds: 300, TargetRTOSeconds: 1800, SigningKeyID: "backup-signing-2026-08",
		SigningPrivateKeyFile: "/does/not/exist/signing.pem", DriverPath: "/does/not/exist/driver",
		ManifestDirectory: "/does/not/exist/manifests",
	}
	tests := []struct {
		name   string
		mutate func(*backupPlan)
	}{
		{name: "backup id", mutate: func(plan *backupPlan) { plan.BackupID = "../backup" }},
		{name: "source cluster", mutate: func(plan *backupPlan) { plan.SourceClusterID = "customer/control" }},
		{name: "app version", mutate: func(plan *backupPlan) { plan.AppVersion = " v1 " }},
		{name: "schema version", mutate: func(plan *backupPlan) { plan.SchemaVersion = 0 }},
		{name: "core manifest digest", mutate: func(plan *backupPlan) { plan.CoreManifestSHA256 = strings.Repeat("A", 64) }},
		{name: "envelope key", mutate: func(plan *backupPlan) { plan.EnvelopeKey.Version = "" }},
		{name: "target RPO", mutate: func(plan *backupPlan) { plan.TargetRPOSeconds = 0 }},
		{name: "target RTO", mutate: func(plan *backupPlan) { plan.TargetRTOSeconds = 366 * 24 * 60 * 60 }},
		{name: "signing key id", mutate: func(plan *backupPlan) { plan.SigningKeyID = "signing/key" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			plan := valid
			test.mutate(&plan)
			path := writeBackupPlan(t, plan)
			err := run(context.Background(), []string{"--plan", path})
			if err == nil || err.Error() != "backup plan is invalid" {
				t.Fatalf("run() error = %v, want backup plan is invalid", err)
			}
		})
	}
}

func TestValidateBackupPlanAcceptsBoundedProductionPlan(t *testing.T) {
	t.Parallel()

	plan := backupPlan{
		InstallationID: "11111111-1111-4111-8111-111111111111", DriverPlanSHA256: strings.Repeat("b", 64),
		Schema: backupPlanSchema, BackupID: "backup-ops12-20260809", SourceClusterID: "customer-control-a",
		AppVersion: "1.8.0", SchemaVersion: 176, CoreManifestSHA256: strings.Repeat("a", 64),
		EnvelopeKey:      controlbackup.SecretReference{Provider: "kms", Name: "control-backup/customer-a", Version: "42"},
		TargetRPOSeconds: 300, TargetRTOSeconds: 1800, SigningKeyID: "backup-signing-2026-08",
		SigningPrivateKeyFile: "/run/secrets/backup-signing.pem", DriverPath: "/opt/cdnca/bin/recovery-driver",
		ManifestDirectory: "/var/lib/cdnca/recovery-manifests",
	}
	rpo, rto, err := validateBackupPlan(plan)
	if err != nil || rpo.Seconds() != 300 || rto.Seconds() != 1800 {
		t.Fatalf("validateBackupPlan() = (%v, %v, %v)", rpo, rto, err)
	}
}

func writeBackupPlan(t *testing.T, plan backupPlan) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "plan.json")
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := controlbackup.ValidatePlanSecretFields(encoded); err != nil && !errors.Is(err, controlbackup.ErrInvalidManifest) {
		t.Fatal(err)
	}
	return path
}
