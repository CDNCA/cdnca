package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Produced by libs/entitlement.SignUpgradeExecution (control-api's signer) in
// libs/entitlement/upgrade_execution_golden_test.go; both sides pin this digest.
const upgradeExecutionGoldenSHA256 = "fe6cc24503881f5e2df791c4a7038278a3e0500e186698544551da67dece9602"

func TestVerifyUpgradeExecutionAcceptsControlPlaneGoldenVector(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("testdata", "upgrade-execution-v3.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if got := hex.EncodeToString(digest[:]); got != upgradeExecutionGoldenSHA256 {
		t.Fatalf("golden vector sha256 = %s, want %s", got, upgradeExecutionGoldenSHA256)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	options := UpgradeExecutionConsumerOptions{
		Now:                    now.Add(2 * time.Minute),
		ExpectedInstallationID: "00000000-0000-4000-8000-000000000004",
		ExpectedNodeID:         "00000000-0000-4000-8000-000000000021",
		ExpectedCommandID:      "00000000-0000-4000-8000-000000000022",
		ExpectedNonce:          "00000000-0000-4000-8000-000000000023",
		ExpectedCurrentVersion: "1.0.0", ExpectedTargetVersion: "2.0.0",
		ExpectedPlanID: "00000000-0000-4000-8000-000000000024", ExpectedPlanRevision: 3,
		ExpectedBatchID:  "00000000-0000-4000-8000-000000000025",
		ExpectedPlatform: "linux", ExpectedArchitecture: "amd64", MaxArtifactBytes: 1024,
		ControlKeys: map[string]ed25519.PublicKey{"control-execution-1": executionFixtureKey(0x81).Public().(ed25519.PublicKey)},
		EdgeKeys:    map[string]ed25519.PublicKey{"edge-consumption-1": executionFixtureKey(0x82).Public().(ed25519.PublicKey)},
		RequireV2:   true,
	}
	replay := &executionReplayFixture{consume: true}
	plan, err := VerifyAndConsumeUpgradeExecution(context.Background(), encoded, options, replay)
	if err != nil {
		t.Fatalf("Agent rejected control-plane signed execution: %v", err)
	}
	if replay.calls != 1 || plan.ExecutionSequence != 11 || plan.TargetVersion != "2.0.0" {
		t.Fatalf("plan = %#v, replay calls = %d", plan, replay.calls)
	}
}
