package nodecertlifecycle

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCertificatePolicyNearExpiryClockSkewAndOverlap(t *testing.T) {
	policy, err := NewCertificatePolicy(2*time.Minute, 6*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		notBefore      time.Time
		notAfter       time.Time
		wantConnection bool
		wantRenewal    bool
	}{
		{"clock skew accepted", now.Add(time.Minute), now.Add(24 * time.Hour), true, false},
		{"pending beyond skew", now.Add(3 * time.Minute), now.Add(24 * time.Hour), false, false},
		{"near expiry", now.Add(-time.Hour), now.Add(5 * time.Hour), true, true},
		{"expired within skew", now.Add(-time.Hour), now.Add(-time.Minute), true, true},
		{"expired beyond skew", now.Add(-time.Hour), now.Add(-3 * time.Minute), false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := policy.Evaluate(test.notBefore, test.notAfter, now)
			if decision.ConnectionAllowed != test.wantConnection || decision.RenewalRequired != test.wantRenewal || decision.Reason == "" {
				t.Fatalf("Evaluate() = %+v", decision)
			}
		})
	}
}

func TestSealArtifactBindsEveryIdentityAndRejectsUnavailableRecipient(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("certificate-private-material")
	digest := sha256.Sum256(plaintext)
	request := ArtifactSealRequest{
		NodeID:          uuid.MustParse("d318940f-bbe5-453c-b6a6-bd04bc31e5c7"),
		TenantID:        uuid.MustParse("706876a3-f788-4f15-ac9f-5be430f8431b"),
		ConfigVersionID: uuid.MustParse("f4c9cc4f-f2f4-4ed4-8482-2a4074eb7ccb"),
		DeploymentID:    uuid.MustParse("c973265d-081c-4b35-9600-f0d229b48afb"),
		ArtifactID:      uuid.MustParse("f2806dbe-0b69-4fa3-933d-bdcce3d8af54"),
		Plaintext:       plaintext, PlaintextSHA256: digest,
		RecipientPublicKey: privateKey.PublicKey().Bytes(), RecipientKeyRevision: 9,
		RecipientKeyID:        ArtifactRecipientKeyID(privateKey.PublicKey().Bytes()),
		CurrentRecipientKeyID: ArtifactRecipientKeyID(privateKey.PublicKey().Bytes()),
		RecipientState:        RecipientActive,
	}
	sealed, err := SealArtifact(rand.Reader, request)
	if err != nil {
		t.Fatalf("SealArtifact() error = %v", err)
	}
	opened, err := OpenArtifact(privateKey.Bytes(), sealed, request.Binding())
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("OpenArtifact() = (%q, %v)", opened, err)
	}
	mutated := request.Binding()
	mutated.TenantID = uuid.New()
	if _, err := OpenArtifact(privateKey.Bytes(), sealed, mutated); !errors.Is(err, ErrArtifactBinding) {
		t.Fatalf("mutated binding error = %v", err)
	}
	for _, state := range []RecipientState{RecipientDraining, RecipientRevoked} {
		candidate := request
		candidate.RecipientState = state
		if _, err := SealArtifact(rand.Reader, candidate); !errors.Is(err, ErrRecipientUnavailable) {
			t.Fatalf("state %q error = %v", state, err)
		}
	}
	request.CurrentRecipientKeyID = "x25519:stale"
	if _, err := SealArtifact(rand.Reader, request); !errors.Is(err, ErrRecipientUnavailable) {
		t.Fatalf("stale recipient error = %v", err)
	}
}

func TestSignedRevocationCheckpointStrictMonotonicDurableLKG(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	installation := "01HZXNODE10INSTALLATION"
	store := &memoryCheckpointStore{}
	applier, err := NewCheckpointApplier(store, installation, map[string]ed25519.PublicKey{"revocation-key-1": publicKey}, func() time.Time { return now }, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request := RevocationCheckpointRequest{
		InstallationID: installation, Revision: 41, IssuedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "revocation-key-1",
		Certificates: []RevokedCertificate{{NodeID: uuid.MustParse("d318940f-bbe5-453c-b6a6-bd04bc31e5c7"), SerialNumber: "1", AuthorizationRevision: 7}},
		CAEpochs:     []RevokedCAEpoch{{EpochID: uuid.MustParse("504daf70-aed6-4b89-afbe-947e4e3ea344"), Epoch: 3}},
	}
	wire, err := IssueRevocationCheckpoint(rand.Reader, privateKey, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applier.Apply(context.Background(), wire); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if _, err := applier.Apply(context.Background(), wire); !errors.Is(err, ErrCheckpointReplay) {
		t.Fatalf("replay error = %v", err)
	}
	request.Revision--
	older, err := IssueRevocationCheckpoint(rand.Reader, privateKey, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applier.Apply(context.Background(), older); !errors.Is(err, ErrCheckpointReplay) {
		t.Fatalf("rollback error = %v", err)
	}
	loaded, found, err := store.Load(context.Background(), installation)
	if err != nil || !found || loaded.Revision != 41 {
		t.Fatalf("durable LKG = (%+v, %v, %v)", loaded, found, err)
	}
}

type memoryCheckpointStore struct {
	mu         sync.Mutex
	checkpoint VerifiedRevocationCheckpoint
	found      bool
}

func (store *memoryCheckpointStore) Load(_ context.Context, _ string) (VerifiedRevocationCheckpoint, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.checkpoint, store.found, nil
}

func (store *memoryCheckpointStore) StoreNext(_ context.Context, checkpoint VerifiedRevocationCheckpoint, previousRevision uint64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.found && store.checkpoint.Revision != previousRevision || !store.found && previousRevision != 0 {
		return ErrCheckpointConflict
	}
	store.checkpoint, store.found = checkpoint, true
	return nil
}
