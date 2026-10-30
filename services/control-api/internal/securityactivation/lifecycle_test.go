package securityactivation

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestPhaseIdentityRequiresExactCandidateConfigArtifactAndTargetSnapshot(t *testing.T) {
	candidate := Candidate{
		ID: uuid.New(), TenantScopeID: uuid.New(), SiteID: uuid.New(),
		CandidateSourceRevision: 11, CandidateConfigVersionID: uuid.New(),
		CandidateArtifactSHA256: sha256.Sum256([]byte("artifact")),
		TargetSnapshotSHA256:    sha256.Sum256([]byte("targets")),
	}
	valid := PhaseIdentity{
		CandidateID: candidate.ID, RolloutID: uuid.New(), Phase: "canary",
		ConfigVersionID: candidate.CandidateConfigVersionID,
		ArtifactSHA256:  candidate.CandidateArtifactSHA256, TargetSnapshotSHA256: candidate.TargetSnapshotSHA256,
	}
	if err := validatePhaseIdentity(candidate, valid); err != nil {
		t.Fatalf("valid phase identity rejected: %v", err)
	}
	for name, mutate := range map[string]func(*PhaseIdentity){
		"candidate": func(value *PhaseIdentity) { value.CandidateID = uuid.New() },
		"config":    func(value *PhaseIdentity) { value.ConfigVersionID = uuid.New() },
		"artifact":  func(value *PhaseIdentity) { value.ArtifactSHA256[0] ^= 0xff },
		"targets":   func(value *PhaseIdentity) { value.TargetSnapshotSHA256[0] ^= 0xff },
	} {
		t.Run(name, func(t *testing.T) {
			changed := valid
			mutate(&changed)
			if err := validatePhaseIdentity(candidate, changed); !errors.Is(err, ErrConflict) {
				t.Fatalf("identity mismatch error = %v, want ErrConflict", err)
			}
		})
	}
}

func TestReceiptAggregationRejectsDuplicateStaleOutOfOrderAndMismatchedFacts(t *testing.T) {
	candidate := Candidate{
		ID: uuid.New(), CandidateConfigVersionID: uuid.New(),
		CandidateArtifactSHA256: sha256.Sum256([]byte("artifact")),
	}
	nodeA, nodeB := uuid.New(), uuid.New()
	rolloutID := uuid.New()
	deployments := map[uuid.UUID]uuid.UUID{nodeA: uuid.New(), nodeB: uuid.New()}
	healthy := func(nodeID uuid.UUID, sequence int64) ReceiptFact {
		return ReceiptFact{
			RolloutID: rolloutID, DeploymentID: deployments[nodeID], Phase: "canary", Action: "apply",
			NodeID: nodeID, Attempt: 1, TransitionSequence: sequence, State: "healthy",
			ConfigVersionID: candidate.CandidateConfigVersionID,
			ArtifactSHA256:  candidate.CandidateArtifactSHA256,
		}
	}
	stale := healthy(nodeA, 3)
	stale.State = "activated"
	facts, err := aggregateReceiptFacts(candidate, []uuid.UUID{nodeA, nodeB}, []ReceiptFact{
		healthy(nodeB, 5), healthy(nodeA, 4), healthy(nodeA, 4), stale,
	}, nil)
	if err != nil || facts.total != 2 || facts.healthy != 2 {
		t.Fatalf("aggregateReceiptFacts = %+v, %v", facts, err)
	}

	for name, receipts := range map[string][]ReceiptFact{
		"foreign node":  {healthy(uuid.New(), 1)},
		"wrong config":  {func() ReceiptFact { value := healthy(nodeA, 1); value.ConfigVersionID = uuid.New(); return value }()},
		"wrong digest":  {func() ReceiptFact { value := healthy(nodeA, 1); value.ArtifactSHA256[0] ^= 0xff; return value }()},
		"failed latest": {func() ReceiptFact { value := healthy(nodeA, 2); value.State = "failed"; return value }()},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := aggregateReceiptFacts(candidate, []uuid.UUID{nodeA}, receipts, nil)
			if name == "failed latest" {
				if err != nil || got.failed != 1 || got.healthy != 0 {
					t.Fatalf("failed facts = %+v, %v", got, err)
				}
				return
			}
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("aggregateReceiptFacts error = %v, want ErrConflict", err)
			}
		})
	}

	failed := healthy(nodeA, 1)
	failed.State = "failed"
	pendingRetry := failed
	pendingRetry.Attempt, pendingRetry.TransitionSequence, pendingRetry.State = 2, 1, "queued"
	if got, err := aggregateReceiptFacts(candidate, []uuid.UUID{nodeA}, []ReceiptFact{failed, pendingRetry}, nil); err != nil || got.failed != 0 || got.cancelled != 0 || got.healthy != 0 {
		t.Fatalf("pending latest retry facts = %+v, %v", got, err)
	}
	cancelled := pendingRetry
	cancelled.State = "cancelled"
	if got, err := aggregateReceiptFacts(candidate, []uuid.UUID{nodeA}, []ReceiptFact{failed, cancelled}, nil); err != nil || got.cancelled != 1 || got.failed != 0 || got.healthy != 0 {
		t.Fatalf("cancelled latest projection facts = %+v, %v", got, err)
	}
}

// Site runtime v2: every node runs its own HPKE artifact, so a healthy node
// reports its own digest, not the candidate's plaintext digest.
func TestReceiptAggregationComparesEachV2NodeWithItsOwnArtifact(t *testing.T) {
	candidate := Candidate{
		ID: uuid.New(), CandidateConfigVersionID: uuid.New(),
		CandidateArtifactSHA256: sha256.Sum256([]byte("plaintext bundle")),
	}
	nodeA, nodeB := uuid.New(), uuid.New()
	artifacts := map[uuid.UUID][sha256.Size]byte{
		nodeA: sha256.Sum256([]byte("node a ciphertext")), nodeB: sha256.Sum256([]byte("node b ciphertext")),
	}
	rolloutID := uuid.New()
	healthy := func(nodeID uuid.UUID, digest [sha256.Size]byte) ReceiptFact {
		return ReceiptFact{
			RolloutID: rolloutID, DeploymentID: uuid.NewSHA1(rolloutID, nodeID[:]), Phase: "canary", Action: "apply",
			NodeID: nodeID, Attempt: 1, TransitionSequence: 5, State: "healthy",
			ConfigVersionID: candidate.CandidateConfigVersionID, ArtifactSHA256: digest,
		}
	}
	facts, err := aggregateReceiptFacts(candidate, []uuid.UUID{nodeA, nodeB},
		[]ReceiptFact{healthy(nodeA, artifacts[nodeA]), healthy(nodeB, artifacts[nodeB])}, artifacts)
	if err != nil || facts.total != 2 || facts.healthy != 2 {
		t.Fatalf("v2 per-node facts = %+v, %v", facts, err)
	}
	for name, receipt := range map[string]ReceiptFact{
		"candidate plaintext digest": healthy(nodeA, candidate.CandidateArtifactSHA256),
		"another node's artifact":    healthy(nodeA, artifacts[nodeB]),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := aggregateReceiptFacts(candidate, []uuid.UUID{nodeA}, []ReceiptFact{receipt}, artifacts); !errors.Is(err, ErrConflict) {
				t.Fatalf("aggregateReceiptFacts error = %v, want ErrConflict", err)
			}
		})
	}
	if _, err := aggregateReceiptFacts(candidate, []uuid.UUID{nodeA}, []ReceiptFact{healthy(nodeA, artifacts[nodeA])},
		map[uuid.UUID][sha256.Size]byte{nodeB: artifacts[nodeB]}); !errors.Is(err, ErrConflict) {
		t.Fatalf("node without a v2 artifact error = %v, want ErrConflict", err)
	}
}

func TestDeterministicCanarySelectionIsStableAndExpansionExcludesCanary(t *testing.T) {
	nodes := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	firstCanary, firstExpand, err := partitionTargets(nodes, 2)
	if err != nil {
		t.Fatal(err)
	}
	secondCanary, secondExpand, err := partitionTargets([]uuid.UUID{nodes[3], nodes[1], nodes[0], nodes[2]}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalUUIDList(firstCanary) != canonicalUUIDList(secondCanary) ||
		canonicalUUIDList(firstExpand) != canonicalUUIDList(secondExpand) {
		t.Fatal("canary selection changed with input order")
	}
	if len(firstCanary) != 2 || len(firstExpand) != 2 {
		t.Fatalf("canary/expand sizes = %d/%d", len(firstCanary), len(firstExpand))
	}
	if _, _, err := partitionTargets(nodes, 0); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero canary error = %v", err)
	}
}
