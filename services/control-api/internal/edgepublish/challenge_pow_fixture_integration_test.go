//go:build integration

package edgepublish

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DeclareChallengePoW records a new Connect session for nodeID declaring (or
// not) CHALLENGE_POW v1, otherwise as AddNode.
func (scope *SystemRepublishScope) DeclareChallengePoW(t *testing.T, nodeID uuid.UUID, declared bool) {
	t.Helper()
	features := systemRepublishFeatures(6)
	version := "1.0.35-no-pow"
	if declared {
		features = append(features, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_CHALLENGE_POW, ApiVersion: 1})
		version = "1.0.35-pow"
	}
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeID, version, features)
}

// SetChallengePoWDifficulty sets revision version of policyID's
// pow_difficulty (migration 648), bypassing the document trigger as
// SeedChallengeOrigin does.
func (scope *SystemRepublishScope) SetChallengePoWDifficulty(t *testing.T, policyID uuid.UUID, version int64, difficulty int) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE challenge_policy_revisions SET pow_difficulty=$3
			WHERE policy_id=$1 AND revision=$2`, policyID, version, difficulty)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
