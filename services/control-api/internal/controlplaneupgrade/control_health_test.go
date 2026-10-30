package controlplaneupgrade

import (
	"errors"
	"testing"
	"time"
)

func TestControlCoordinatorRequiresReplicaQuorumAndFailsClosed(t *testing.T) {
	repository := newMemorySecretRepository()
	publication := &PublicationReceipt{PlanID: "00000000-0000-4000-8000-000000000002", PublicationRevision: 1,
		CurrentVersion: "1.4.0", CurrentDigest: digest52, TargetVersion: "1.5.0", TargetDigest: digest51,
		RollbackVersion: "1.4.0", RollbackDigest: digest52}
	repository.document.Publication = publication
	coordinator, err := NewControlCoordinator(ControlCoordinatorConfig{ReplicaID: "control-0", Version: "1.4.0",
		Digest: digest52, ExpectedReplicas: 3, Quorum: 2, ObservationTTL: time.Minute,
		Now: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }}, repository)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := coordinator.BeginDrain(t.Context(), publication.PlanID)
	if !errors.Is(err, ErrQuorumUnavailable) || snapshot.Phase != ControlDraining || snapshot.HealthyReplicas != 1 {
		t.Fatalf("first drain = (%#v, %v)", snapshot, err)
	}
	peer, err := NewControlCoordinator(ControlCoordinatorConfig{ReplicaID: "control-1", Version: "1.4.0",
		Digest: digest52, ExpectedReplicas: 3, Quorum: 2, ObservationTTL: time.Minute,
		Now: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }}, repository)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Observe(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err = coordinator.BeginDrain(t.Context(), publication.PlanID)
	if err != nil || snapshot.HealthyReplicas != 2 || snapshot.Phase != ControlDraining {
		t.Fatalf("quorum drain = (%#v, %v)", snapshot, err)
	}
	if _, err := coordinator.Resume(t.Context(), "00000000-0000-4000-8000-000000000099"); !errors.Is(err, ErrPlanConflict) {
		t.Fatalf("unknown resume error = %v", err)
	}
	snapshot, _ = coordinator.Snapshot(t.Context())
	if snapshot.Phase != ControlDraining {
		t.Fatalf("unknown resume opened gate: %#v", snapshot)
	}
	coordinator.config.Version, coordinator.config.Digest = "1.5.0", digest51
	peer.config.Version, peer.config.Digest = "1.5.0", digest51
	if _, err := coordinator.Observe(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Observe(t.Context()); err != nil {
		t.Fatal(err)
	}
	receipt, err := coordinator.Resume(t.Context(), publication.PlanID)
	if err != nil || receipt.Result != ResultApplied || receipt.PlanID != publication.PlanID {
		t.Fatalf("resume = (%#v, %v)", receipt, err)
	}
	snapshot, _ = coordinator.Snapshot(t.Context())
	if snapshot.Phase != ControlActive || snapshot.Receipt == nil || snapshot.Receipt.ReceiptID != receipt.ReceiptID {
		t.Fatalf("active snapshot = %#v", snapshot)
	}
	replayed, err := coordinator.Resume(t.Context(), publication.PlanID)
	if err != nil || !replayed.Replayed || replayed.ReceiptID != receipt.ReceiptID {
		t.Fatalf("resume replay = (%#v, %v)", replayed, err)
	}
}

func TestControlCoordinatorRollbackFailureRemainsDraining(t *testing.T) {
	repository := newMemorySecretRepository()
	repository.document.Publication = &PublicationReceipt{PlanID: "00000000-0000-4000-8000-000000000002",
		PublicationRevision: 1, CurrentVersion: "1.4.0", CurrentDigest: digest52,
		TargetVersion: "1.5.0", TargetDigest: digest51, RollbackVersion: "1.4.0", RollbackDigest: digest52}
	coordinator, err := NewControlCoordinator(ControlCoordinatorConfig{ReplicaID: "control-0", Version: "1.4.0",
		Digest: digest52, ExpectedReplicas: 2, Quorum: 2, ObservationTTL: time.Minute, Now: time.Now}, repository)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.BeginDrain(t.Context(), repository.document.Publication.PlanID); !errors.Is(err, ErrQuorumUnavailable) {
		t.Fatalf("drain error = %v", err)
	}
	if _, err := coordinator.Resume(t.Context(), repository.document.Publication.PlanID); !errors.Is(err, ErrQuorumUnavailable) {
		t.Fatalf("rollback quorum error = %v", err)
	}
	snapshot, _ := coordinator.Snapshot(t.Context())
	if snapshot.Phase != ControlDraining || snapshot.Receipt != nil {
		t.Fatalf("rollback failure did not fail closed: %#v", snapshot)
	}
}
