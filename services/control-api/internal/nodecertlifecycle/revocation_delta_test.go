package nodecertlifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRevocationCheckpointDeltaDurableReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	installation := "01HZXNODE10DELTA"
	nodeOne := uuid.MustParse("d318940f-bbe5-453c-b6a6-bd04bc31e5c7")
	nodeTwo := uuid.MustParse("706876a3-f788-4f15-ac9f-5be430f8431b")
	epochOne := uuid.MustParse("504daf70-aed6-4b89-afbe-947e4e3ea344")
	epochTwo := uuid.MustParse("f4c9cc4f-f2f4-4ed4-8482-2a4074eb7ccb")
	store := &wireOnlyDeltaCheckpointStore{}
	applier, err := NewCheckpointApplier(store, installation, map[string]ed25519.PublicKey{"revocation-key-1": publicKey}, func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	baseWire, err := IssueRevocationCheckpoint(rand.Reader, privateKey, RevocationCheckpointRequest{
		InstallationID: installation, Revision: 10, IssuedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "revocation-key-1",
		Certificates: []RevokedCertificate{{NodeID: nodeOne, SerialNumber: "1", AuthorizationRevision: 3}},
		CAEpochs:     []RevokedCAEpoch{{EpochID: epochOne, Epoch: 4}},
	})
	if err != nil {
		t.Fatal(err)
	}
	base, err := applier.Apply(context.Background(), baseWire)
	if err != nil {
		t.Fatal(err)
	}
	deltaWire, err := IssueRevocationCheckpointDelta(rand.Reader, privateKey, RevocationCheckpointDeltaRequest{
		InstallationID: installation, BaseRevision: base.Revision, BaseDigest: base.Digest, Revision: 11,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "revocation-key-1",
		Certificates: []RevokedCertificate{{NodeID: nodeTwo, SerialNumber: "2", AuthorizationRevision: 4}},
		CAEpochs:     []RevokedCAEpoch{{EpochID: epochTwo, Epoch: 5}},
	})
	if err != nil {
		t.Fatal(err)
	}
	deltaApplier, err := NewRevocationCheckpointDeltaApplier(store, installation,
		map[string]ed25519.PublicKey{"revocation-key-1": publicKey}, privateKey, "revocation-key-1", func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := deltaApplier.Apply(context.Background(), deltaWire)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Revision != 11 || len(merged.Certificates) != 2 || len(merged.CAEpochs) != 2 {
		t.Fatalf("merged checkpoint = %+v", merged)
	}
	if _, err := deltaApplier.Apply(context.Background(), deltaWire); !errors.Is(err, ErrCheckpointDeltaReplay) {
		t.Fatalf("delta replay error = %v", err)
	}
	loaded, found, err := store.Load(context.Background(), installation)
	if err != nil || !found || loaded.Revision != 11 || len(loaded.Certificates) != 0 || len(loaded.CAEpochs) != 0 {
		t.Fatalf("durable merged LKG = (%+v, %v, %v)", loaded, found, err)
	}
	decoded, err := decodeStoredRevocationCheckpoint(loaded.WireBytes, map[string]ed25519.PublicKey{"revocation-key-1": publicKey}, installation)
	if err != nil || len(decoded.Certificates) != 2 || len(decoded.CAEpochs) != 2 {
		t.Fatalf("durable merged facts = (%+v, %v)", decoded, err)
	}
}

type wireOnlyDeltaCheckpointStore struct {
	checkpoint VerifiedRevocationCheckpoint
	found      bool
}

func (store *wireOnlyDeltaCheckpointStore) Load(_ context.Context, _ string) (VerifiedRevocationCheckpoint, bool, error) {
	checkpoint := store.checkpoint
	checkpoint.Certificates = nil
	checkpoint.CAEpochs = nil
	return checkpoint, store.found, nil
}

func (store *wireOnlyDeltaCheckpointStore) StoreNext(_ context.Context, checkpoint VerifiedRevocationCheckpoint, previousRevision uint64) error {
	if store.found && store.checkpoint.Revision != previousRevision || !store.found && previousRevision != 0 {
		return ErrCheckpointConflict
	}
	store.checkpoint, store.found = checkpoint, true
	return nil
}

func TestRevocationCheckpointDeltaRejectsConflictingAndNonCanonicalFacts(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	installation := "01HZXNODE10DELTA"
	nodeID := uuid.MustParse("d318940f-bbe5-453c-b6a6-bd04bc31e5c7")
	request := RevocationCheckpointDeltaRequest{
		InstallationID: installation, BaseRevision: 7, BaseDigest: [32]byte{1}, Revision: 8,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "revocation-key-1",
		Certificates: []RevokedCertificate{{NodeID: nodeID, SerialNumber: "1", AuthorizationRevision: 2}, {NodeID: nodeID, SerialNumber: "1", AuthorizationRevision: 3}},
	}
	if _, err := IssueRevocationCheckpointDelta(rand.Reader, privateKey, request); !errors.Is(err, ErrCheckpointDeltaInvalid) {
		t.Fatalf("duplicate issue error = %v", err)
	}
	valid := request
	valid.Certificates = valid.Certificates[:1]
	wire, err := IssueRevocationCheckpointDelta(rand.Reader, privateKey, valid)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRevocationCheckpointDelta(wire, map[string]ed25519.PublicKey{"revocation-key-1": publicKey}, installation, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Revision != 8 || verified.BaseRevision != 7 || verified.BaseDigest != valid.BaseDigest {
		t.Fatalf("verified delta = %+v", verified)
	}
	mutated := append([]byte(nil), wire...)
	mutated[len(mutated)-1] ^= 1
	if _, err := VerifyRevocationCheckpointDelta(mutated, map[string]ed25519.PublicKey{"revocation-key-1": publicKey}, installation, now, time.Minute); !errors.Is(err, ErrCheckpointDeltaInvalid) {
		t.Fatalf("signature mutation error = %v", err)
	}
}
