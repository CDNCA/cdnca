package entitlement

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The same bytes are committed as
// agents/edge-agent/internal/updater/testdata/upgrade-execution-v3.golden.json and
// verified there with the Agent's own verifier; both tests pin this digest so a
// one-sided protocol change (audience, purpose, domain, field) fails on both sides.
const upgradeExecutionGoldenSHA256 = "fe6cc24503881f5e2df791c4a7038278a3e0500e186698544551da67dece9602"

func TestUpgradeExecutionUsesAgentAudienceAndPurpose(t *testing.T) {
	if UpgradeExecutionAudience != "cdnca-edge-upgrade" || UpgradeExecutionPurpose != "cdnca-edge-upgrade-execution" {
		t.Fatalf("audience/purpose = %q/%q, want the Agent's cdnca-edge-upgrade values",
			UpgradeExecutionAudience, UpgradeExecutionPurpose)
	}
}

func TestSignUpgradeExecutionMatchesAgentGoldenVector(t *testing.T) {
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
	path := filepath.Join("testdata", "upgrade-execution-v3.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden vector: %v", err)
	}
	if !bytes.Equal(encoded, golden) {
		t.Fatalf("signed execution differs from golden vector:\n got %s\nwant %s", encoded, golden)
	}
	digest := sha256.Sum256(golden)
	if got := hex.EncodeToString(digest[:]); got != upgradeExecutionGoldenSHA256 {
		t.Fatalf("golden vector sha256 = %s, want %s", got, upgradeExecutionGoldenSHA256)
	}
}

func goldenExecutionKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}
