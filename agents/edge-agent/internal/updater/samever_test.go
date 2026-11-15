package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A same-version execution is a re-release bound to release_sequence.
func newSameVersionFixture(t *testing.T, current, target uint64) executionFixture {
	t.Helper()
	fixture := newExecutionV3Fixture(t)
	fixture.execution.TargetVersion = fixture.execution.CurrentVersion
	fixture.execution.CurrentReleaseSequence = current
	fixture.execution.ReleaseSequence = target
	resignExecutionFixture(t, &fixture)
	return fixture
}

func TestUpgradeExecutionSameVersionHigherReleaseSequenceIsExecutable(t *testing.T) {
	fixture := newSameVersionFixture(t, 7, 9)
	plan, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, fixture.options(),
		&executionReplayFixture{consume: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.CurrentVersion != plan.TargetVersion || plan.CurrentReleaseSequence != 7 || plan.ReleaseSequence != 9 ||
		plan.Action != ActionUpgrade {
		t.Fatalf("same-version plan = %#v", plan)
	}
	decoded, err := decodeUpgradeExecution(fixture.encoded)
	if err != nil {
		t.Fatal(err)
	}
	want, err := upgradeExecutionSigningBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := SigningBytes(plan); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("same-version signing bytes differ: %v", err)
	}
}

func TestUpgradeExecutionSameVersionRejectsNotHigherOrMissingSequence(t *testing.T) {
	for _, test := range []struct {
		name            string
		current, target uint64
	}{{"equal", 9, 9}, {"lower", 9, 7}, {"missing current", 0, 9}} {
		fixture := newSameVersionFixture(t, test.current, test.target)
		replay := &executionReplayFixture{consume: true}
		if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, fixture.options(),
			replay); !errors.Is(err, ErrInvalidUpgradeExecutionEnvelope) || replay.calls != 0 {
			t.Fatalf("%s: err=%v replay calls=%d", test.name, err, replay.calls)
		}
	}
}

func TestUpgradeExecutionSameVersionRequiresV3(t *testing.T) {
	v2 := newSameVersionFixture(t, 7, 9)
	v2.execution.Schema = upgradeExecutionV2Schema
	v2.execution.ExecutionSequence = 0
	resignExecutionFixture(t, &v2)
	if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), v2.encoded, v2.options(),
		&executionReplayFixture{consume: true}); !errors.Is(err, ErrInvalidUpgradeExecutionEnvelope) {
		t.Fatalf("v2 same-version accepted: %v", err)
	}
	crossVersion := newExecutionV3Fixture(t)
	crossVersion.execution.CurrentReleaseSequence = 7
	resignExecutionFixture(t, &crossVersion)
	if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), crossVersion.encoded, crossVersion.options(),
		&executionReplayFixture{consume: true}); !errors.Is(err, ErrInvalidUpgradeExecutionEnvelope) {
		t.Fatalf("cross-version execution with current_release_sequence accepted: %v", err)
	}
}

// What an older agent sees: it has no current_release_sequence field, so the
// strict decoder refuses the envelope; without the field the same-version
// target is a plain non-upgrade and is refused too. Neither touches the node.
func TestUpgradeExecutionSameVersionOlderAgentShapeRefused(t *testing.T) {
	fixture := newSameVersionFixture(t, 7, 9)
	unknown := bytes.Replace(fixture.encoded, []byte(`"current_release_sequence"`), []byte(`"current_release_sequence_x"`), 1)
	if _, err := decodeUpgradeExecution(unknown); !errors.Is(err, ErrInvalidUpgradeExecutionEnvelope) {
		t.Fatalf("unknown execution field accepted: %v", err)
	}
	stripped := newSameVersionFixture(t, 0, 9)
	if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), stripped.encoded, stripped.options(),
		&executionReplayFixture{consume: true}); !errors.Is(err, ErrInvalidUpgradeExecutionEnvelope) {
		t.Fatalf("same-version execution without release sequences accepted: %v", err)
	}
}

func TestValidatePlanSameVersionNeedsHigherReleaseSequence(t *testing.T) {
	for _, test := range []struct {
		name            string
		v3              bool
		action          Action
		comparison      int
		current, target uint64
		want            bool
	}{
		{"higher", true, ActionUpgrade, 0, 7, 9, true},
		{"equal", true, ActionUpgrade, 0, 9, 9, false},
		{"lower", true, ActionUpgrade, 0, 9, 7, false},
		{"missing", true, ActionUpgrade, 0, 0, 9, false},
		{"not v3", false, ActionUpgrade, 0, 7, 9, false},
		{"rollback", true, ActionRollback, 0, 7, 9, false},
		{"different version", true, ActionUpgrade, 1, 7, 9, false},
	} {
		if got := sameVersionRerelease(test.v3, test.action, test.comparison, test.current, test.target); got != test.want {
			t.Errorf("%s: sameVersionRerelease = %v, want %v", test.name, got, test.want)
		}
	}
}

// Pinned with libs/entitlement TestSignSameVersionUpgradeExecutionMatchesAgentGoldenVector.
const sameVersionExecutionGoldenSHA256 = "c2534c4919d678e99bc5b2e5307397b705ac8e49def0d15057b5270b4e32f209"

func TestVerifyUpgradeExecutionAcceptsSameVersionGoldenVector(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("testdata", "upgrade-execution-v3-samever.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if got := hex.EncodeToString(digest[:]); got != sameVersionExecutionGoldenSHA256 {
		t.Fatalf("golden vector sha256 = %s, want %s", got, sameVersionExecutionGoldenSHA256)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	options := UpgradeExecutionConsumerOptions{
		Now:                    now.Add(2 * time.Minute),
		ExpectedInstallationID: "00000000-0000-4000-8000-000000000004",
		ExpectedNodeID:         "00000000-0000-4000-8000-000000000021",
		ExpectedCommandID:      "00000000-0000-4000-8000-000000000022",
		ExpectedNonce:          "00000000-0000-4000-8000-000000000023",
		ExpectedCurrentVersion: "1.0.0", ExpectedTargetVersion: "1.0.0",
		ExpectedPlanID: "00000000-0000-4000-8000-000000000024", ExpectedPlanRevision: 3,
		ExpectedBatchID:  "00000000-0000-4000-8000-000000000025",
		ExpectedPlatform: "linux", ExpectedArchitecture: "amd64", MaxArtifactBytes: 1024,
		ControlKeys: map[string]ed25519.PublicKey{"control-execution-1": executionFixtureKey(0x81).Public().(ed25519.PublicKey)},
		EdgeKeys:    map[string]ed25519.PublicKey{"edge-consumption-1": executionFixtureKey(0x82).Public().(ed25519.PublicKey)},
		RequireV2:   true,
	}
	plan, err := VerifyAndConsumeUpgradeExecution(context.Background(), encoded, options, &executionReplayFixture{consume: true})
	if err != nil {
		t.Fatalf("Agent rejected control-plane signed same-version execution: %v", err)
	}
	if plan.CurrentReleaseSequence == 0 || plan.ReleaseSequence <= plan.CurrentReleaseSequence {
		t.Fatalf("plan = %#v", plan)
	}
}
