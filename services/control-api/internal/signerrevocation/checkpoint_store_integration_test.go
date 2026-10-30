package signerrevocation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/signercheckpoint"
	"github.com/google/uuid"
)

type checkpointStoreTrust struct {
	pins  []entitlementguard.VerificationKey
	roots map[signercheckpoint.AuthorityRef]ed25519.PublicKey
}

func (trust checkpointStoreTrust) KeysetPins(context.Context) ([]entitlementguard.VerificationKey, error) {
	return trust.pins, nil
}

func (trust checkpointStoreTrust) OfflineRoot(_ context.Context, ref signercheckpoint.AuthorityRef) (ed25519.PublicKey, error) {
	key := trust.roots[ref]
	if len(key) == 0 {
		return nil, signercheckpoint.ErrAuthorityUntrusted
	}
	return key, nil
}

func TestCheckpointStoreAcceptRestoreOutageAndTamper(t *testing.T) {
	pool := signerRevocationPool(t)
	encoded, trust := checkpointStoreGolden(t)
	now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
	store := NewCheckpointStore(pool, trust, func() time.Time { return now })
	etag := strongETag(encoded)

	accepted, err := store.AcceptV2(t.Context(), uuid.New(), encoded, etag, now)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Checkpoint.Revision != 1 || accepted.Checkpoint.HeadSequence != 1 ||
		accepted.Runtime.Revision != 1 || accepted.Runtime.RevocationHead.Sequence != 1 || accepted.ETag != etag {
		t.Fatalf("accepted LKG = %#v", accepted)
	}
	restored, err := store.RestoreV2(t.Context())
	if err != nil || restored.Checkpoint.CheckpointSHA256 != accepted.Checkpoint.CheckpointSHA256 ||
		restored.Runtime.Revision != accepted.Runtime.Revision {
		t.Fatalf("restored LKG = (%#v, %v)", restored, err)
	}
	runtimeState, err := NewRuntime(restored.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	decision := runtimeState.DecideLease(SignerIdentity{KeyID: "offline-root", Generation: 1}, now)
	if decision.Allowed || decision.Reason != ReasonSignerRevoked {
		t.Fatalf("restored runtime decision = %#v", decision)
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 1
	if _, err := store.AcceptV2(t.Context(), uuid.New(), tampered, strongETag(tampered), now); err == nil {
		t.Fatal("tampered checkpoint was accepted")
	}
	assertCheckpointStoreCounts(t, store, 1, 1, 1)
	if err := store.RecordCheckpointOutage(t.Context(), uuid.New(), ReasonCheckpointServerOutage, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	assertCheckpointStoreCounts(t, store, 1, 1, 2)
	afterOutage, err := store.RestoreV2(t.Context())
	if err != nil || afterOutage.Checkpoint.Revision != 1 {
		t.Fatalf("outage changed LKG = (%#v, %v)", afterOutage, err)
	}

	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_signer_checkpoint_snapshots
		DISABLE TRIGGER control_signer_checkpoint_snapshots_immutable_077`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE control_signer_checkpoint_snapshots
		SET signed_checkpoint=set_byte(signed_checkpoint,0,get_byte(signed_checkpoint,0)#1) WHERE revision=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_signer_checkpoint_snapshots
		ENABLE TRIGGER control_signer_checkpoint_snapshots_immutable_077`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreV2(t.Context()); !errors.Is(err, ErrInvalidStoredState) {
		t.Fatalf("tampered restore error = %v", err)
	}
}

func TestCheckpointStoreReplayIsAtomicAndAudited(t *testing.T) {
	pool := signerRevocationPool(t)
	encoded, trust := checkpointStoreGolden(t)
	now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
	clockNow := now
	store := NewCheckpointStore(pool, trust, func() time.Time { return clockNow })
	etag := strongETag(encoded)
	accepted, err := store.AcceptV2(t.Context(), uuid.New(), encoded, etag, now)
	if err != nil {
		t.Fatal(err)
	}
	runtimeState, err := NewRuntime(accepted.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	clockNow = now.Add(time.Minute)
	replayed, err := store.AcceptV2(t.Context(), uuid.New(), encoded, etag, clockNow)
	if err != nil || replayed.Checkpoint.Revision != 1 {
		t.Fatalf("replay = (%#v, %v)", replayed, err)
	}
	if !replayed.AcceptedAt.Equal(accepted.AcceptedAt) {
		t.Fatalf("replay accepted_at changed from %s to %s", accepted.AcceptedAt, replayed.AcceptedAt)
	}
	if err := runtimeState.Replace(replayed.Runtime); err != nil {
		t.Fatalf("replace exact checkpoint replay: %v", err)
	}
	assertCheckpointStoreCounts(t, store, 1, 1, 2)
}

func TestCheckpointStoreRevisionGapAndExpiredRestartRecovery(t *testing.T) {
	pool := signerRevocationPool(t)
	encoded, trust := checkpointStoreGolden(t)
	now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
	store := NewCheckpointStore(pool, trust, func() time.Time { return now })

	bootstrap := checkpointStoreRevision(t, encoded, 5, 4)
	first, err := store.AcceptV2(t.Context(), uuid.New(), bootstrap, strongETag(bootstrap), now)
	if err != nil || first.Checkpoint.Revision != 5 {
		t.Fatalf("revision 5 bootstrap = (%#v, %v)", first, err)
	}
	successor := checkpointStoreRevision(t, encoded, 9, 8)
	next, err := store.AcceptV2(t.Context(), uuid.New(), successor, strongETag(successor), now)
	if err != nil || next.Checkpoint.Revision != 9 || next.Runtime.Revision != 9 {
		t.Fatalf("revision 5 to 9 = (%#v, %v)", next, err)
	}

	restarted := NewCheckpointStore(pool, trust, func() time.Time { return now.Add(24 * time.Hour) })
	restored, err := restarted.RestoreV2(t.Context())
	if err != nil || restored.Checkpoint.Revision != 9 || restored.Runtime.RevocationHead.Sequence != 1 {
		t.Fatalf("expired outer restart restore = (%#v, %v)", restored, err)
	}
	assertCheckpointStoreCounts(t, store, 2, 2, 2)
}

func TestCheckpointStoreRejectsTamperedAuditBeforeOutageAppend(t *testing.T) {
	pool := signerRevocationPool(t)
	encoded, trust := checkpointStoreGolden(t)
	now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
	store := NewCheckpointStore(pool, trust, func() time.Time { return now })
	if _, err := store.AcceptV2(t.Context(), uuid.New(), encoded, strongETag(encoded), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_signer_checkpoint_audit
		DISABLE TRIGGER control_signer_checkpoint_audit_immutable_077`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE control_signer_checkpoint_audit
		SET reason_code='checkpoint_replay' WHERE stream_position=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_signer_checkpoint_audit
		ENABLE TRIGGER control_signer_checkpoint_audit_immutable_077`); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordCheckpointOutage(t.Context(), uuid.New(), ReasonCheckpointServerOutage,
		now.Add(time.Minute)); !errors.Is(err, ErrInvalidStoredState) {
		t.Fatalf("tampered audit append error = %v", err)
	}
	assertCheckpointStoreCounts(t, store, 1, 1, 1)
}

func TestCheckpointStoreRestoreRejectsMissingAcceptAudit(t *testing.T) {
	pool := signerRevocationPool(t)
	encoded, trust := checkpointStoreGolden(t)
	now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
	store := NewCheckpointStore(pool, trust, func() time.Time { return now })
	if _, err := store.AcceptV2(t.Context(), uuid.New(), encoded, strongETag(encoded), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_signer_checkpoint_audit
		DISABLE TRIGGER control_signer_checkpoint_audit_immutable_077`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM control_signer_checkpoint_audit WHERE event_type='accept'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_signer_checkpoint_audit
		ENABLE TRIGGER control_signer_checkpoint_audit_immutable_077`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreV2(t.Context()); !errors.Is(err, ErrInvalidStoredState) {
		t.Fatalf("missing accept audit restore error = %v", err)
	}
}

func TestCheckpointStoreAcceptFailuresLeaveNoPartialFacts(t *testing.T) {
	for name, injection := range map[string]string{
		"manifest": `
			CREATE FUNCTION reject_checkpoint_test_insert() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'injected manifest failure' USING ERRCODE = 'P0001'; END $$;
			CREATE TRIGGER reject_checkpoint_test_insert BEFORE INSERT ON control_signer_checkpoint_manifests
			FOR EACH ROW EXECUTE FUNCTION reject_checkpoint_test_insert()`,
		"audit": `
			CREATE FUNCTION reject_checkpoint_test_insert() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'injected audit failure' USING ERRCODE = 'P0001'; END $$;
			CREATE TRIGGER reject_checkpoint_test_insert BEFORE INSERT ON control_signer_checkpoint_audit
			FOR EACH ROW EXECUTE FUNCTION reject_checkpoint_test_insert()`,
		"deferred commit": `
			CREATE FUNCTION reject_checkpoint_test_insert() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'injected commit failure' USING ERRCODE = 'P0001'; END $$;
			CREATE CONSTRAINT TRIGGER reject_checkpoint_test_insert AFTER INSERT ON control_signer_checkpoint_snapshots
			DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_checkpoint_test_insert()`,
	} {
		t.Run(name, func(t *testing.T) {
			pool := signerRevocationPool(t)
			encoded, trust := checkpointStoreGolden(t)
			now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
			store := NewCheckpointStore(pool, trust, func() time.Time { return now })
			if _, err := pool.Exec(t.Context(), injection); err != nil {
				t.Fatal(err)
			}
			if _, err := store.AcceptV2(t.Context(), uuid.New(), encoded, strongETag(encoded), now); err == nil {
				t.Fatal("injected checkpoint acceptance failure was hidden")
			}
			assertCheckpointStoreCounts(t, store, 0, 0, 0)
		})
	}
}

func assertCheckpointStoreCounts(t *testing.T, store *CheckpointStore, snapshots, manifests, audit int) {
	t.Helper()
	var gotSnapshots, gotManifests, gotAudit int
	if err := store.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM control_signer_checkpoint_snapshots),
		(SELECT count(*) FROM control_signer_checkpoint_manifests),
		(SELECT count(*) FROM control_signer_checkpoint_audit)`).Scan(&gotSnapshots, &gotManifests, &gotAudit); err != nil ||
		gotSnapshots != snapshots || gotManifests != manifests || gotAudit != audit {
		t.Fatalf("counts snapshots=%d/%d manifests=%d/%d audit=%d/%d err=%v",
			gotSnapshots, snapshots, gotManifests, manifests, gotAudit, audit, err)
	}
}

func checkpointStoreGolden(t *testing.T) ([]byte, checkpointStoreTrust) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	encoded, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../tests/contracts/signer-revocation-checkpoint-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Signed json.RawMessage `json:"signed"`
	}
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	var signed signercheckpoint.SignedCheckpoint
	if err := json.Unmarshal(fixture.Signed, &signed); err != nil {
		t.Fatal(err)
	}
	var keyset struct {
		Keys []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(signed.Checkpoint.Keyset, &keyset); err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(keyset.Keys[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("cdnca-checkpoint-golden-offline-root"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	ref := signercheckpoint.AuthorityRef{Kind: signercheckpoint.AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}
	return fixture.Signed, checkpointStoreTrust{
		pins:  []entitlementguard.VerificationKey{{KeyID: keyset.Keys[0].KeyID, PublicKey: publicKey}},
		roots: map[signercheckpoint.AuthorityRef]ed25519.PublicKey{ref: privateKey.Public().(ed25519.PublicKey)},
	}
}

func checkpointStoreRevision(t *testing.T, encoded []byte, revision, previous uint64) []byte {
	t.Helper()
	var signed signercheckpoint.SignedCheckpoint
	if err := json.Unmarshal(encoded, &signed); err != nil {
		t.Fatal(err)
	}
	signed.Checkpoint.Revision = revision
	signed.Checkpoint.PreviousRevision = &previous
	previousDigest := sha256.Sum256([]byte("unobserved checkpoint revision"))
	previousText := base64.RawURLEncoding.EncodeToString(previousDigest[:])
	signed.Checkpoint.PreviousCheckpointSHA256 = &previousText
	canonical, err := signercheckpoint.CanonicalCheckpoint(signed.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	signed.Envelope.CheckpointSHA256 = base64.RawURLEncoding.EncodeToString(digest[:])
	envelope, err := signercheckpoint.CanonicalEnvelope(signed.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("cdnca-checkpoint-golden-offline-root"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	signed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, envelope))
	result, err := signercheckpoint.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
