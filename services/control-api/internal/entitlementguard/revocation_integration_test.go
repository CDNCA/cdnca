package entitlementguard

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRevocationServiceMonotonicPersistenceAndLeaseReplay(t *testing.T) {
	pool := isolatedEntitlementPool(t)
	var now time.Time
	if err := pool.QueryRow(t.Context(), `SELECT date_trunc('second',clock_timestamp())`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifyUntil := now.Add(24 * time.Hour)
	key := VerificationKey{KeyID: "revocation-integration-key", PublicKey: publicKey,
		NotBefore: now.Add(-24 * time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil}
	trust := mustTrustStore(t, key)
	signer := integrationSigner{id: key.KeyID, private: privateKey}
	service := NewService(pool, trust)
	if _, err := NewRevocationService(pool, trust).Restore(t.Context(), now); !errors.Is(err, ErrRevocationUnavailable) {
		t.Fatalf("restore without revocation LKG error = %v", err)
	}
	lease := integrationLease(now, 7)
	signedLease := signIntegrationLease(t, lease, signer)

	if _, err := service.Install(t.Context(), InstallBundle{InstallationID: lease.InstallationID,
		SignedLease: signedLease}, now); !errors.Is(err, ErrRevocationUnavailable) {
		t.Fatalf("install without revocation LKG error = %v", err)
	}
	first := acceptIntegrationRevocation(t, pool, trust, signer, now, now.Add(-2*time.Second), 1, nil)
	if first.Revision != 1 || first.AcceptedAt.IsZero() {
		t.Fatalf("first revocation snapshot = %#v", first)
	}
	restored, err := NewRevocationService(pool, trust).Restore(t.Context(), now)
	if err != nil || restored.ArtifactSHA256 != first.ArtifactSHA256 ||
		restored.Revision != first.Revision || restored.KeyID != first.KeyID ||
		!restored.IssuedAt.Equal(first.IssuedAt) || !restored.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("restored revocation snapshot = (%#v, %v)", restored, err)
	}
	installed, err := service.Install(t.Context(), InstallBundle{InstallationID: lease.InstallationID,
		SignedLease: signedLease}, now)
	if err != nil || installed.Status != entitlement.StatusValid {
		t.Fatalf("install with current revocation LKG = (%#v, %v)", installed, err)
	}

	second := acceptIntegrationRevocation(t, pool, trust, signer, now, now.Add(-time.Second), 2, []uint64{7})
	if second.Revision != 2 || len(second.RevokedSerials) != 1 || second.RevokedSerials[0] != 7 {
		t.Fatalf("second revocation snapshot = %#v", second)
	}
	replayed := acceptIntegrationRevocation(t, pool, trust, signer, now, now.Add(-time.Second), 2, []uint64{7})
	if replayed.ArtifactSHA256 != second.ArtifactSHA256 || !replayed.AcceptedAt.Equal(second.AcceptedAt) {
		t.Fatalf("exact replay changed snapshot: before=%#v after=%#v", second, replayed)
	}
	if snapshot, err := service.Install(t.Context(), InstallBundle{InstallationID: lease.InstallationID,
		SignedLease: signedLease}, now); err != nil || snapshot.Status != entitlement.StatusRevoked {
		t.Fatalf("same-serial lease replay = (%#v, %v)", snapshot, err)
	}
	var cachedStatus, controlStatus string
	var revokedCount int
	if err := pool.QueryRow(t.Context(), `SELECT lease.status,installation.last_status,
		(SELECT count(*) FROM control_entitlement_revoked_serials WHERE serial=7)
		FROM entitlement_cached_leases lease JOIN control_installation_entitlement installation
		ON installation.current_serial=lease.serial WHERE lease.serial=7`).Scan(
		&cachedStatus, &controlStatus, &revokedCount); err != nil {
		t.Fatal(err)
	}
	if cachedStatus != "revoked" || controlStatus != "revoked" || revokedCount != 1 {
		t.Fatalf("revoked persistence = lease=%q control=%q count=%d", cachedStatus, controlStatus, revokedCount)
	}

	conflict := signedIntegrationRevocation(t, signer, now.Add(-time.Second), 2, []uint64{7, 8})
	if _, err := NewRevocationService(pool, trust).Accept(t.Context(), conflict, now); !errors.Is(err, ErrRevocationConflict) {
		t.Fatalf("same revision conflict error = %v", err)
	}
	lower := signedIntegrationRevocation(t, signer, now.Add(-2*time.Second), 1, nil)
	if _, err := NewRevocationService(pool, trust).Accept(t.Context(), lower, now); !errors.Is(err, ErrRevocationRollback) {
		t.Fatalf("lower revision error = %v", err)
	}
	shrink := signedIntegrationRevocation(t, signer, now, 3, nil)
	if _, err := NewRevocationService(pool, trust).Accept(t.Context(), shrink, now); !errors.Is(err, ErrRevocationShrink) {
		t.Fatalf("shrinking revision error = %v", err)
	}
	expired := signedIntegrationRevocation(t, signer, now.Add(-16*time.Minute), 3, []uint64{7})
	if _, err := NewRevocationService(pool, trust).Accept(t.Context(), expired, now); !errors.Is(err, ErrRevocationExpired) {
		t.Fatalf("expired revision error = %v", err)
	}
	if _, err := NewRevocationService(pool, trust).Restore(t.Context(), now.Add(16*time.Minute)); !errors.Is(err, ErrRevocationExpired) {
		t.Fatalf("restore expired revocation LKG error = %v", err)
	}
}

func TestRevocationAcceptAndCheckFeatureSerializeOnSingleton(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.install(t, fixture.lease(71), fixture.now)
	acceptPool := namedRevocationPool(t, fixture.pool, "rv-control-accept")
	acceptService := NewRevocationService(acceptPool, fixture.trust)

	checker := fixture.begin(t)
	if _, err := fixture.guard().CheckFeature(t.Context(), checker, fixture.check("checker-first")); err != nil {
		t.Fatalf("CheckFeature(checker first) error = %v", err)
	}
	secondArtifact := signedIntegrationRevocation(t, fixture.signer, fixture.now.Add(-2*time.Minute), 2, []uint64{71})
	secondDone := make(chan error, 1)
	go func() {
		_, err := acceptService.Accept(context.Background(), secondArtifact, fixture.now)
		secondDone <- err
	}()
	acceptPID := waitForRevocationApplicationPID(t, fixture.pool, "rv-control-accept")
	waitForEntitlementBlock(t, fixture.pool, acceptPID)
	if err := checker.Commit(t.Context()); err != nil {
		t.Fatalf("commit checker-first transaction: %v", err)
	}
	if err := waitForRevocationResult(t, secondDone); err != nil {
		t.Fatalf("accept after checker error = %v", err)
	}

	fixture.install(t, fixture.lease(72), fixture.now)
	keyBlocker := fixture.begin(t)
	if _, err := keyBlocker.Exec(t.Context(), `
		SELECT key_id FROM entitlement_verification_keys WHERE key_id=$1 FOR UPDATE`, fixture.signer.id); err != nil {
		t.Fatalf("lock verification key: %v", err)
	}
	thirdArtifact := signedIntegrationRevocation(t, fixture.signer, fixture.now.Add(-time.Minute), 3, []uint64{71, 72})
	thirdDone := make(chan error, 1)
	go func() {
		_, err := acceptService.Accept(context.Background(), thirdArtifact, fixture.now)
		thirdDone <- err
	}()
	acceptPID = waitForRevocationApplicationPID(t, fixture.pool, "rv-control-accept")
	waitForEntitlementBlock(t, fixture.pool, acceptPID)

	waitingChecker := fixture.begin(t)
	var checkerPID int
	if err := waitingChecker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&checkerPID); err != nil {
		t.Fatalf("read checker backend PID: %v", err)
	}
	checkDone := make(chan error, 1)
	go func() {
		_, err := fixture.guard().CheckFeature(context.Background(), waitingChecker, fixture.check("accept-first"))
		checkDone <- err
	}()
	waitForEntitlementBlock(t, fixture.pool, checkerPID)
	if err := keyBlocker.Commit(t.Context()); err != nil {
		t.Fatalf("release verification key lock: %v", err)
	}
	if err := waitForRevocationResult(t, thirdDone); err != nil {
		t.Fatalf("accept before checker error = %v", err)
	}
	if err := waitForRevocationResult(t, checkDone); !errors.Is(err, ErrStateDenied) {
		t.Fatalf("CheckFeature(after revoke) error = %v, want ErrStateDenied", err)
	}
	if err := waitingChecker.Rollback(t.Context()); err != nil {
		t.Fatalf("rollback waiting checker: %v", err)
	}
}

func TestRevocationAcceptWaitsForKeysetProjectionRefresh(t *testing.T) {
	pool := isolatedEntitlementPool(t)
	var now time.Time
	if err := pool.QueryRow(t.Context(), `SELECT date_trunc('second',clock_timestamp())`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifyUntil := now.Add(24 * time.Hour)
	key := VerificationKey{KeyID: "revocation-refresh-race-key", PublicKey: publicKey,
		NotBefore: now.Add(-24 * time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil}
	trust := mustTrustStore(t, key)
	signer := integrationSigner{id: key.KeyID, private: privateKey}
	acceptIntegrationRevocation(t, pool, trust, signer, now, now.Add(-2*time.Second), 1, nil)

	var keyID, status string
	var projectedPublicKey, keysetDigest []byte
	var notBefore, acceptedAt time.Time
	var signUntil, projectedVerifyUntil *time.Time
	if err := pool.QueryRow(t.Context(), `SELECT key_id,public_key,status,not_before,sign_until,verify_until,
		keyset_payload_sha256,accepted_at FROM entitlement_signing_keyset_current_keys
		WHERE key_id=$1`, key.KeyID).Scan(&keyID, &projectedPublicKey, &status, &notBefore,
		&signUntil, &projectedVerifyUntil, &keysetDigest, &acceptedAt); err != nil {
		t.Fatal(err)
	}

	applicationSuffix := uuid.NewString()
	refreshPool := namedRevocationPool(t, pool, "rv-keyset-refresh-"+applicationSuffix)
	refreshTx, err := refreshPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer refreshTx.Rollback(t.Context())
	var refreshPID int
	if err := refreshTx.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&refreshPID); err != nil {
		t.Fatal(err)
	}
	if _, err := refreshTx.Exec(t.Context(),
		`LOCK TABLE entitlement_signing_keyset_lkg IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	var singleton bool
	if err := refreshTx.QueryRow(t.Context(), `SELECT singleton FROM entitlement_signing_keyset_lkg
		WHERE singleton=true FOR UPDATE`).Scan(&singleton); err != nil || !singleton {
		t.Fatalf("lock keyset LKG = %t, %v", singleton, err)
	}
	if _, err := refreshTx.Exec(t.Context(), `DELETE FROM entitlement_signing_keyset_current_keys`); err != nil {
		t.Fatal(err)
	}
	if _, err := refreshTx.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, keyID, projectedPublicKey, status, notBefore,
		signUntil, projectedVerifyUntil, keysetDigest, acceptedAt); err != nil {
		t.Fatal(err)
	}

	acceptApplicationName := "rv-projection-race-accept-" + applicationSuffix
	acceptPool := namedRevocationPool(t, pool, acceptApplicationName)
	acceptService := NewRevocationService(acceptPool, trust)
	artifact := signedIntegrationRevocation(t, signer, now.Add(-time.Second), 2, nil)
	acceptContext, cancelAccept := context.WithTimeout(t.Context(), 10*time.Second)
	acceptDone := make(chan error, 1)
	acceptJoined := false
	defer func() {
		cancelAccept()
		if acceptJoined {
			return
		}
		select {
		case <-acceptDone:
		case <-time.After(5 * time.Second):
			t.Errorf("revocation operation did not stop after cancellation")
		}
	}()
	go func() {
		_, acceptErr := acceptService.Accept(acceptContext, artifact, now)
		acceptDone <- acceptErr
	}()
	acceptPID := waitForRevocationApplicationPID(t, pool, acceptApplicationName)
	deadline := time.Now().Add(5 * time.Second)
	blockedByRefresh := false
	for time.Now().Before(deadline) {
		err := pool.QueryRow(t.Context(), `SELECT wait_event_type='Lock' AND $2=ANY(pg_blocking_pids($1))
			FROM pg_stat_activity WHERE pid=$1 AND datname=current_database() AND application_name=$3`,
			acceptPID, refreshPID, acceptApplicationName).Scan(&blockedByRefresh)
		if err == nil && blockedByRefresh {
			break
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("read revocation blocker: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blockedByRefresh {
		t.Fatalf("revocation backend %d was not blocked by refresh backend %d", acceptPID, refreshPID)
	}
	if err := refreshTx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	acceptErr := waitForRevocationResult(t, acceptDone)
	acceptJoined = true
	cancelAccept()
	if acceptErr != nil {
		t.Fatalf("accept across keyset projection refresh: %v", acceptErr)
	}
	var revision int64
	if err := pool.QueryRow(t.Context(), `SELECT revision FROM control_entitlement_revocation_lkg
		WHERE singleton=true`).Scan(&revision); err != nil || revision != 2 {
		t.Fatalf("revocation revision after projection refresh = %d, %v", revision, err)
	}
}

func namedRevocationPool(t *testing.T, source *pgxpool.Pool, applicationName string) *pgxpool.Pool {
	t.Helper()
	config := source.Config().Copy()
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatalf("open named revocation pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func waitForRevocationApplicationPID(t *testing.T, pool *pgxpool.Pool, applicationName string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var pid int
		err := pool.QueryRow(t.Context(), `
			SELECT pid FROM pg_stat_activity
			WHERE datname=current_database() AND application_name=$1 AND state='active'
			ORDER BY backend_start DESC LIMIT 1`, applicationName).Scan(&pid)
		if err == nil {
			return pid
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("read revocation application PID: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("revocation application %q never became active", applicationName)
	return 0
}

func waitForRevocationResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("revocation operation did not complete")
		return nil
	}
}

func signedIntegrationRevocation(t *testing.T, signer integrationSigner, issuedAt time.Time,
	revision uint64, revoked []uint64,
) []byte {
	t.Helper()
	verifyUntil := issuedAt.Add(24 * time.Hour)
	signed, err := entitlement.SignRevocationSet(context.Background(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: integrationCustomerID, InstallationID: integrationInstallationID,
		LicenseID: integrationLicenseID, Revision: revision, IssuedAt: issuedAt.Unix(),
		ExpiresAt:      issuedAt.Add(entitlement.RevocationSetWindow).Unix(),
		RevokedSerials: append([]uint64{}, revoked...),
	}, signer, entitlement.RevocationKeyWindow{NotBefore: issuedAt.Add(-24 * time.Hour),
		SignUntil: &verifyUntil, VerifyUntil: &verifyUntil})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}
