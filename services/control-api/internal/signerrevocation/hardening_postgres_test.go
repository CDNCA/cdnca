package signerrevocation

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestPostgresAcceptUsesTrustedClockAndBoundsObservedAt(t *testing.T) {
	pool := signerRevocationPool(t)
	fixture := makeTrustFixture(t, "root", "current")
	clockNow := fixedNow.Add(2 * time.Hour)
	store := NewStore(pool, fixture, func() time.Time { return clockNow })

	bootstrap, err := store.Accept(t.Context(), Candidate{OperationID: uuid.New(), KeysetPayload: fixture.body,
		KeysetETag: strongETag(fixture.body), ObservedAt: clockNow.Add(-maxCandidateClockSkew)})
	if err != nil || !bootstrap.AcceptedAt.Equal(clockNow) {
		t.Fatalf("fixed-clock bootstrap = (%#v, %v)", bootstrap, err)
	}

	expired := testManifest(1, nil, nil, "root", 1)
	expired.IssuedAt = canonicalTime(clockNow.Add(-10 * time.Minute))
	expired.EffectiveNotBefore = expired.IssuedAt
	expired.ExpiresAt = canonicalTime(clockNow.Add(-time.Minute))
	encoded := signManifest(t, expired,
		AuthorityRef{Kind: AuthorityLineage, KeyID: "current", Generation: 2}, fixture.privateKeys["current"])
	_, err = store.Accept(t.Context(), Candidate{OperationID: uuid.New(), RevocationPayload: encoded,
		RevocationETag: strongETag(encoded), ObservedAt: clockNow.Add(-2 * time.Minute)})
	if !errors.Is(err, ErrManifestNotCurrent) {
		t.Fatalf("expired at trusted now error = %v", err)
	}

	_, err = store.Accept(t.Context(), Candidate{OperationID: uuid.New(), KeysetPayload: fixture.body,
		KeysetETag: strongETag(fixture.body), ObservedAt: clockNow.Add(maxCandidateClockSkew + time.Microsecond)})
	if !errors.Is(err, ErrObservedAtOutOfRange) {
		t.Fatalf("future observed-at error = %v", err)
	}
	assertLKGCounts(t, pool, 1, 0)
	var rejected int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM control_signer_revocation_events
		WHERE stage='reject' AND reason_code=$1`, ReasonObservedAtOutOfRange).Scan(&rejected); err != nil || rejected != 1 {
		t.Fatalf("observed-at rejection events = %d, err=%v", rejected, err)
	}
}

func TestRestoreReplaysOneRepeatableReadSnapshotAcrossConcurrentCommit(t *testing.T) {
	pool := signerRevocationPool(t)
	fixture := makeTrustFixture(t, "root", "current")
	storeNow := fixedNow.Add(5 * time.Minute)
	store := NewStore(pool, fixture, func() time.Time { return storeNow })
	if _, err := store.Accept(t.Context(), Candidate{OperationID: uuid.New(), KeysetPayload: fixture.body,
		KeysetETag: strongETag(fixture.body), ObservedAt: fixedNow}); err != nil {
		t.Fatal(err)
	}
	genesis := testManifest(1, nil, nil, "root", 1)
	genesisEncoded := signManifest(t, genesis,
		AuthorityRef{Kind: AuthorityLineage, KeyID: "current", Generation: 2}, fixture.privateKeys["current"])
	first, err := store.Accept(t.Context(), Candidate{OperationID: uuid.New(), RevocationPayload: genesisEncoded,
		RevocationETag: strongETag(genesisEncoded), ObservedAt: fixedNow.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}

	tx, err := pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	manifestRows, err := readManifestRows(t.Context(), tx)
	if err != nil || len(manifestRows) != 1 {
		t.Fatalf("establish restore snapshot = (%d, %v)", len(manifestRows), err)
	}

	previous := uint64(1)
	previousDigest := first.RevocationHead.ManifestSHA256
	successor := testManifest(2, &previous, &previousDigest, "root", 1)
	successor.IssuedAt = canonicalTime(fixedNow.Add(4 * time.Minute))
	successor.EffectiveNotBefore = successor.IssuedAt
	successorEncoded := signManifest(t, successor,
		AuthorityRef{Kind: AuthorityLineage, KeyID: "current", Generation: 2}, fixture.privateKeys["current"])
	if _, err := store.Accept(t.Context(), Candidate{OperationID: uuid.New(), RevocationPayload: successorEncoded,
		RevocationETag: strongETag(successorEncoded), ObservedAt: fixedNow.Add(4 * time.Minute)}); err != nil {
		t.Fatalf("concurrent commit: %v", err)
	}

	oldSnapshot, err := store.restoreTx(t.Context(), tx)
	if err != nil || oldSnapshot.Revision != 2 || oldSnapshot.RevocationHead.Sequence != 1 {
		t.Fatalf("repeatable-read restore = (%#v, %v)", oldSnapshot, err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	current, err := store.Restore(t.Context())
	if err != nil || current.Revision != 3 || current.RevocationHead.Sequence != 2 {
		t.Fatalf("post-commit restore = (%#v, %v)", current, err)
	}
}

func TestVerifyAuditRejectsOrphanAndMismatchedEventPositions(t *testing.T) {
	for _, test := range []struct {
		name          string
		eventPosition uint64
		withAudit     bool
	}{
		{name: "orphan event", eventPosition: 1},
		{name: "mismatched position", eventPosition: 2, withAudit: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := signerRevocationPool(t)
			fixture := makeTrustFixture(t, "root")
			store := NewStore(pool, fixture, func() time.Time { return fixedNow })
			eventID := uuid.New()
			if _, err := pool.Exec(t.Context(), `INSERT INTO control_signer_revocation_events(
				id,stream_position,operation_id,stage,result,reason_code,occurred_at)
				VALUES($1,$2,$3,'fetch','success',$4,$5)`, eventID, test.eventPosition, uuid.New(),
				ReasonFetchReceived, fixedNow); err != nil {
				t.Fatal(err)
			}
			if test.withAudit {
				if _, err := pool.Exec(t.Context(), `INSERT INTO control_signer_revocation_audit(
					stream_position,event_id,previous_hash,event_hash,occurred_at)
					VALUES(1,$1,NULL,$2,$3)`, eventID, make([]byte, 32), fixedNow); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.VerifyAudit(t.Context()); !errors.Is(err, ErrInvalidStoredState) {
				t.Fatalf("VerifyAudit error = %v", err)
			}
		})
	}
}
