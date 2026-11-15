package entitlement

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sameVersionExecutionGoldenSHA256 = "c2534c4919d678e99bc5b2e5307397b705ac8e49def0d15057b5270b4e32f209"

// The release_sequence decides a same-version re-release.
func TestValidUpgradeDirectionSameVersionReleaseSequence(t *testing.T) {
	for _, test := range []struct {
		name               string
		operation          string
		current, target    string
		v3                 bool
		currentSeq, seqNew uint64
		want               bool
	}{
		{"higher", UpgradeOperation, "1.0.35", "1.0.35", true, 7, 9, true},
		{"equal", UpgradeOperation, "1.0.35", "1.0.35", true, 9, 9, false},
		{"lower", UpgradeOperation, "1.0.35", "1.0.35", true, 9, 7, false},
		{"missing current sequence", UpgradeOperation, "1.0.35", "1.0.35", true, 0, 9, false},
		{"not v3", UpgradeOperation, "1.0.35", "1.0.35", false, 7, 9, false},
		{"same-version rollback", RollbackOperation, "1.0.35", "1.0.35", true, 7, 9, false},
		{"reinstall operation", ReinstallOperation, "1.0.35", "1.0.35", true, 7, 9, false},
		{"version upgrade", UpgradeOperation, "1.0.35", "1.0.36", true, 0, 9, true},
		{"version upgrade with current sequence", UpgradeOperation, "1.0.35", "1.0.36", true, 7, 9, false},
		{"version rollback", RollbackOperation, "1.0.36", "1.0.35", true, 0, 9, true},
	} {
		if got := validUpgradeDirection(test.operation, test.current, test.target, test.v3, test.currentSeq, test.seqNew); got != test.want {
			t.Errorf("%s: validUpgradeDirection = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestUpgradeCandidateRereleaseStatus(t *testing.T) {
	signed, _, _, _ := candidateFixture(t)
	base := signed.Snapshot
	base.CurrentVersion = base.Candidate.Manifest.Version
	base.Status, base.Reason = "up_to_date", "same_version"
	if err := base.Validate(); err != nil {
		t.Fatalf("legacy same-version snapshot: %v", err)
	}
	for _, test := range []struct {
		name               string
		currentSeq, target uint64
		status, reason     string
		valid              bool
	}{
		{"higher is a re-release", 7, 9, "available", "rerelease_available", true},
		{"higher must not say up_to_date", 7, 9, "up_to_date", "same_version", false},
		{"equal is up to date", 9, 9, "up_to_date", "same_version", true},
		{"lower is up to date", 9, 7, "up_to_date", "same_version", true},
		{"lower must not be a re-release", 9, 7, "available", "rerelease_available", false},
		{"requested but missing target sequence", 7, 0, "up_to_date", "same_version", false},
		{"target sequence without request", 0, 9, "up_to_date", "same_version", false},
	} {
		snapshot := base
		snapshot.CurrentReleaseSequence, snapshot.ReleaseSequence = test.currentSeq, test.target
		snapshot.Status, snapshot.Reason = test.status, test.reason
		if err := snapshot.Validate(); (err == nil) != test.valid {
			t.Errorf("%s: Validate() = %v, want valid=%v", test.name, err, test.valid)
		}
	}
}

func TestUpgradePlanArtifactBundleSameVersionRerelease(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	_, privateKey := upgradeGrantTestKey(0xa3)
	bundle := validUpgradePlanArtifactBundle(t, now, privateKey)
	bundle.Schema = UpgradePlanArtifactBundleV2Schema
	bundle.Forward.Manifest.Schema = ArtifactManifestV3Schema
	bundle.Forward.Manifest.ReleaseSequence = 21
	signature, err := SignArtifactManifestV3(context.Background(), bundle.Forward.Manifest,
		testSigner{id: "release-bundle-key", private: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	bundle.Forward.ManifestSignature = base64.RawURLEncoding.EncodeToString(signature)
	bundle.Rollback = bundle.Forward
	bundle.CurrentVersion = bundle.Version
	bundle.CurrentReleaseSequence = 20
	if err := bundle.Validate(); err != nil {
		t.Fatalf("same-version re-release bundle: %v", err)
	}
	for name, mutate := range map[string]func(*UpgradePlanArtifactBundle){
		"equal sequence":   func(b *UpgradePlanArtifactBundle) { b.CurrentReleaseSequence = 21 },
		"higher installed": func(b *UpgradePlanArtifactBundle) { b.CurrentReleaseSequence = 22 },
		"missing current":  func(b *UpgradePlanArtifactBundle) { b.CurrentReleaseSequence = 0 },
		"v1 schema":        func(b *UpgradePlanArtifactBundle) { b.Schema = UpgradePlanArtifactBundleSchema },
		"distinct rollback": func(b *UpgradePlanArtifactBundle) {
			b.Rollback.Manifest.ReleaseSequence = 20
		},
	} {
		mutated := bundle
		mutate(&mutated)
		if mutated.Validate() == nil {
			t.Errorf("%s: same-version bundle accepted", name)
		}
	}
	crossVersion := validUpgradePlanArtifactBundle(t, now, privateKey)
	crossVersion.CurrentReleaseSequence = 5
	if crossVersion.Validate() == nil {
		t.Fatal("cross-version bundle with current_release_sequence accepted")
	}
}

func TestUpgradeGrantCurrentReleaseSequenceOnlyForReinstall(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	grant := validUpgradeGrant(now, make([]byte, 64))
	if err := grant.Validate(); err != nil {
		t.Fatalf("fixture grant: %v", err)
	}
	grant.CurrentReleaseSequence = 5
	if grant.Validate() == nil {
		t.Fatal("upgrade grant with current_release_sequence accepted")
	}
	grant.CurrentVersion, grant.Operation = grant.Version, ReinstallOperation
	if err := grant.Validate(); err != nil {
		t.Fatalf("reinstall grant with current_release_sequence: %v", err)
	}
}

// Golden vector: also committed as
// agents/edge-agent/internal/updater/testdata/upgrade-execution-v3-samever.golden.json
// and verified there by the Agent; both sides pin the digest.
func TestSignSameVersionUpgradeExecutionMatchesAgentGoldenVector(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	execution := validUpgradeExecution(now)
	execution.Schema = UpgradeExecutionV3Schema
	execution.PlanID = "00000000-0000-4000-8000-000000000024"
	execution.PlanRevision = 3
	execution.BatchID = "00000000-0000-4000-8000-000000000025"
	execution.ArtifactBundleID = "00000000-0000-4000-8000-000000000026"
	execution.ArtifactBundleSHA256 = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, sha256.Size))
	execution.CommandIssuanceNotAfter = execution.ExpiresAt
	execution.ExecutionSequence = 11
	execution.Health.Command = []string{"{artifact}", "--version"}
	execution.TargetVersion = execution.CurrentVersion
	execution.Operation = UpgradeOperation
	execution.CurrentReleaseSequence = execution.ReleaseSequence
	execution.ReleaseSequence = execution.CurrentReleaseSequence + 2
	signed, err := SignUpgradeExecution(context.Background(), execution,
		testSigner{id: "control-execution-1", private: goldenExecutionKey(0x81)},
		testSigner{id: "edge-consumption-1", private: goldenExecutionKey(0x82)})
	if err != nil {
		t.Fatalf("SignUpgradeExecution() error = %v", err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "upgrade-execution-v3-samever.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(encoded, golden) {
		t.Fatalf("same-version execution differs from golden vector (%v):\n got %s", err, encoded)
	}
	digest := sha256.Sum256(golden)
	if got := hex.EncodeToString(digest[:]); got != sameVersionExecutionGoldenSHA256 {
		t.Fatalf("golden vector sha256 = %s, want %s", got, sameVersionExecutionGoldenSHA256)
	}
}
