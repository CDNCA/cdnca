package certificateasset

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestImportACMEInTxCommitAndRollbackAreCallerControlled(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "acme-in-tx-atomicity")
	store := newACMEInTxStore(t, pool, &testEnvelopeCipher{}, audit.New(pool))
	ctx := context.Background()

	committedPKI := newCertificateFixture(t, leafOptions{domains: []string{"commit.example.com"}})
	committedOrder := insertValidatingCertificateOrder(t, pool, tenant.actor, []string{"commit.example.com"})
	committedRequest := newACMEInTxRequest(tenant.actor, committedOrder, committedPKI, "acme-in-tx-commit")
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE certificate_orders SET status='issuing',revision=revision+1 WHERE id=$1`, committedOrder); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	committed, err := store.ImportACMEInTx(ctx, tx, committedRequest)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if committed.Version.ACMEOrderID == nil || *committed.Version.ACMEOrderID != committedOrder {
		_ = tx.Rollback(ctx)
		t.Fatalf("ACME association = %#v", committed.Version)
	}
	var factsInside int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM certificate_asset_versions WHERE acme_order_id=$1`,
		committedOrder).Scan(&factsInside); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if factsInside != 1 || certificateRowCount(t, pool, "certificate_asset_versions") != 0 {
		_ = tx.Rollback(ctx)
		t.Fatalf("uncommitted facts inside=%d outside=%d", factsInside,
			certificateRowCount(t, pool, "certificate_asset_versions"))
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if certificateRowCount(t, pool, "certificate_assets") != 1 ||
		certificateRowCount(t, pool, "certificate_asset_versions") != 1 ||
		certificateRowCount(t, pool, "certificate_asset_private_key_envelope_facts") != 1 ||
		!certificateWriteExists(t, pool, committedRequest.Import.IdempotencyKey) {
		t.Fatal("caller commit did not atomically publish all certificate facts")
	}
	assertCertificateOrderStatus(t, pool, committedOrder, "issuing")

	rolledBackPKI := newCertificateFixture(t, leafOptions{domains: []string{"rollback.example.com"}})
	rolledBackOrder := insertValidatingCertificateOrder(t, pool, tenant.actor, []string{"rollback.example.com"})
	rolledBackRequest := newACMEInTxRequest(tenant.actor, rolledBackOrder, rolledBackPKI, "acme-in-tx-rollback")
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE certificate_orders SET status='issuing',revision=revision+1 WHERE id=$1`, rolledBackOrder); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := store.ImportACMEInTx(ctx, tx, rolledBackRequest); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if certificateRowCount(t, pool, "certificate_assets") != 1 ||
		certificateRowCount(t, pool, "certificate_asset_versions") != 1 ||
		certificateWriteExists(t, pool, rolledBackRequest.Import.IdempotencyKey) ||
		certificateAuditExists(t, pool, rolledBackRequest.Import.RequestID) {
		t.Fatal("caller rollback left certificate, idempotency, or audit facts")
	}
	assertCertificateOrderStatus(t, pool, rolledBackOrder, "validating")
}

func TestImportACMEInTxRejectsInvalidBoundaryAndOrderState(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "acme-in-tx-validation")
	otherTenant := createCertificateTenant(t, pool, "acme-in-tx-validation-other")
	store := newACMEInTxStore(t, pool, &testEnvelopeCipher{}, audit.New(pool))
	pki := newCertificateFixture(t, leafOptions{domains: []string{"valid.example.com"}})
	orderID := insertIssuingCertificateOrder(t, pool, tenant.actor, []string{"valid.example.com"})
	base := newACMEInTxRequest(tenant.actor, orderID, pki, "acme-in-tx-validation-base")

	if _, err := store.ImportACMEInTx(context.Background(), nil, base); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil transaction error = %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*ACMEImportRequest)
	}{
		{name: "plaintext private key", mutate: func(request *ACMEImportRequest) {
			request.Import.OpaquePrivateKey = nil
			request.Import.PrivateKeyPEM = pki.privateKeyPEM
		}},
		{name: "uploaded source", mutate: func(request *ACMEImportRequest) {
			request.Import.Source = SourceUploaded
			request.Import.ACMEOrderID = nil
		}},
		{name: "zero order", mutate: func(request *ACMEImportRequest) {
			zero := uuid.Nil
			request.Import.ACMEOrderID = &zero
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := newACMEInTxRequest(tenant.actor, orderID, pki, "acme-in-tx-invalid-"+test.name)
			test.mutate(&request)
			err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
				_, err := store.ImportACMEInTx(context.Background(), tx, request)
				return err
			})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	// An order no longer issuing (the runtime failed it) is refused.
	advanceCertificateOrder(t, pool, orderID, "failed")
	assertACMEInTxRejected(t, pool, store, base, ErrACMEOrderMismatch)

	crossOrder := insertIssuingCertificateOrder(t, pool, otherTenant.actor, []string{"valid.example.com"})
	crossRequest := newACMEInTxRequest(tenant.actor, crossOrder, pki, "acme-in-tx-cross-tenant")
	assertACMEInTxRejected(t, pool, store, crossRequest, ErrACMEOrderMismatch)

	mismatchOrder := insertIssuingCertificateOrder(t, pool, tenant.actor, []string{"missing.example.com"})
	mismatchRequest := newACMEInTxRequest(tenant.actor, mismatchOrder, pki, "acme-in-tx-san-mismatch")
	assertACMEInTxRejected(t, pool, store, mismatchRequest, ErrACMEOrderMismatch)

	inactiveOrder := insertIssuingCertificateOrder(t, pool, tenant.actor, []string{"valid.example.com"})
	inactiveRequest := newACMEInTxRequest(tenant.actor, inactiveOrder, pki, "acme-in-tx-inactive-actor")
	err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `UPDATE memberships SET status='suspended'
			WHERE scope_id=$1 AND user_id=$2`, tenant.actor.ScopeID, tenant.actor.UserID); err != nil {
			return err
		}
		_, err := store.ImportACMEInTx(context.Background(), tx, inactiveRequest)
		return err
	})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("inactive actor error = %v", err)
	}

	if certificateRowCount(t, pool, "certificate_assets") != 0 ||
		certificateRowCount(t, pool, "certificate_asset_write_requests") != 0 {
		t.Fatal("rejected ACME imports left certificate or write facts")
	}
}

func TestImportACMEInTxIdempotencyReplayAndConflict(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "acme-in-tx-idempotency")
	store := newACMEInTxStore(t, pool, &testEnvelopeCipher{}, audit.New(pool))
	pki := newCertificateFixture(t, leafOptions{domains: []string{"idempotent.example.com"}})
	orderID := insertIssuingCertificateOrder(t, pool, tenant.actor, []string{"idempotent.example.com"})
	request := newACMEInTxRequest(tenant.actor, orderID, pki, "acme-in-tx-idempotent")
	conflictingPKI := newCertificateFixture(t, leafOptions{domains: []string{"idempotent.example.com"}})
	conflict := newACMEInTxRequest(tenant.actor, orderID, conflictingPKI, "acme-in-tx-idempotent")

	var first, replay ImportResult
	err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		var err error
		first, err = store.ImportACMEInTx(context.Background(), tx, request)
		if err != nil {
			return err
		}
		replay, err = store.ImportACMEInTx(context.Background(), tx, request)
		if err != nil {
			return err
		}
		if _, err := store.ImportACMEInTx(context.Background(), tx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
			return errors.New("different certificate did not conflict with the reserved idempotency key")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Asset.ID == uuid.Nil || replay.Asset.ID != first.Asset.ID || !replay.Replayed {
		t.Fatalf("first=%#v replay=%#v", first, replay)
	}
	if certificateRowCount(t, pool, "certificate_asset_versions") != 1 ||
		certificateRowCount(t, pool, "certificate_asset_write_requests") != 1 {
		t.Fatal("idempotency replay duplicated certificate facts")
	}

	var replayAfterCommit ImportResult
	err = pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		var err error
		replayAfterCommit, err = store.ImportACMEInTx(context.Background(), tx, request)
		return err
	})
	if err != nil || !replayAfterCommit.Replayed || replayAfterCommit.Asset.ID != first.Asset.ID {
		t.Fatalf("replay after commit = %#v, error = %v", replayAfterCommit, err)
	}
}

func TestImportACMEInTxFailuresRollBackCallerTransaction(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "acme-in-tx-failures")

	envelopePKI := newCertificateFixture(t, leafOptions{domains: []string{"envelope-failure.example.com"}})
	envelopeOrder := insertIssuingCertificateOrder(t, pool, tenant.actor, []string{"envelope-failure.example.com"})
	envelopeRequest := newACMEInTxRequest(tenant.actor, envelopeOrder, envelopePKI, "acme-in-tx-envelope-failure")
	envelopeStore := newACMEInTxStore(t, pool, &testEnvelopeCipher{err: errors.New("injected envelope failure")}, audit.New(pool))
	err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		_, err := envelopeStore.ImportACMEInTx(context.Background(), tx, envelopeRequest)
		return err
	})
	if !errors.Is(err, ErrEnvelopeUnavailable) {
		t.Fatalf("envelope failure = %v", err)
	}

	auditPKI := newCertificateFixture(t, leafOptions{domains: []string{"audit-failure.example.com"}})
	auditOrder := insertIssuingCertificateOrder(t, pool, tenant.actor, []string{"audit-failure.example.com"})
	auditRequest := newACMEInTxRequest(tenant.actor, auditOrder, auditPKI, "acme-in-tx-audit-failure")
	auditStore := newACMEInTxStore(t, pool, &testEnvelopeCipher{}, failingCertificateAuditor{})
	err = pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		_, err := auditStore.ImportACMEInTx(context.Background(), tx, auditRequest)
		return err
	})
	if !errors.Is(err, errCertificateAuditInjected) {
		t.Fatalf("audit failure = %v", err)
	}

	if certificateRowCount(t, pool, "certificate_assets") != 0 ||
		certificateRowCount(t, pool, "certificate_asset_versions") != 0 ||
		certificateRowCount(t, pool, "certificate_asset_private_key_envelope_facts") != 0 ||
		certificateRowCount(t, pool, "certificate_asset_write_requests") != 0 ||
		certificateAuditExists(t, pool, envelopeRequest.Import.RequestID) ||
		certificateAuditExists(t, pool, auditRequest.Import.RequestID) {
		t.Fatal("failed ACME import left partial certificate, envelope, write, or audit facts")
	}
}

func newACMEInTxStore(
	t *testing.T,
	pool *pgxpool.Pool,
	enveloper PrivateKeyEnveloper,
	auditor AuditAppender,
) *Store {
	t.Helper()
	store, err := NewStoreWithDependencies(pool, enveloper, auditor, func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newACMEInTxRequest(
	actor Actor,
	orderID uuid.UUID,
	pki certificateFixture,
	key string,
) ACMEImportRequest {
	return ACMEImportRequest{Actor: actor, Import: ImportRequest{
		TenantScopeID:  actor.ScopeID,
		Name:           "ACME transaction certificate",
		Source:         SourceACME,
		ACMEOrderID:    &orderID,
		CertificatePEM: pki.certificatePEM,
		OpaquePrivateKey: &OpaquePrivateKey{
			KeyReference:       "kms-signer:" + key,
			PublicKeySPKIDER:   append([]byte(nil), pki.leaf.RawSubjectPublicKeyInfo...),
			WrappedKeyMaterial: bytes.Repeat([]byte{0x5a}, 64),
			Metadata:           []byte(`{"provider":"test-kms","format":"wrapped-key-v1"}`),
		},
		IdempotencyKey: key,
		RequestID:      "request-" + key,
	}}
}

func insertIssuingCertificateOrder(
	t *testing.T,
	pool *pgxpool.Pool,
	actor Actor,
	domains []string,
) uuid.UUID {
	t.Helper()
	id := insertValidatingCertificateOrder(t, pool, actor, domains)
	advanceCertificateOrder(t, pool, id, "issuing")
	return id
}

// insertValidatingCertificateOrder: a new order (pending) moved to validating.
func insertValidatingCertificateOrder(
	t *testing.T,
	pool *pgxpool.Pool,
	actor Actor,
	domains []string,
) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(), `INSERT INTO certificate_orders (
		id,scope_id,domains,challenge_type,status,auto_renew,created_by_user_id,updated_by_user_id
	) VALUES($1,$2,$3,'http-01','pending',true,$4,$4)`, id, actor.ScopeID, domains, actor.UserID)
	if err != nil {
		t.Fatal(err)
	}
	advanceCertificateOrder(t, pool, id, "validating")
	return id
}

func assertACMEInTxRejected(
	t *testing.T,
	pool *pgxpool.Pool,
	store *Store,
	request ACMEImportRequest,
	want error,
) {
	t.Helper()
	err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		_, err := store.ImportACMEInTx(context.Background(), tx, request)
		return err
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func assertCertificateOrderStatus(t *testing.T, pool *pgxpool.Pool, orderID uuid.UUID, want string) {
	t.Helper()
	var status string
	if err := pool.QueryRow(context.Background(), `SELECT status FROM certificate_orders WHERE id=$1`,
		orderID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != want {
		t.Fatalf("order status = %q, want %q", status, want)
	}
}

func certificateAuditExists(t *testing.T, pool *pgxpool.Pool, requestID string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS(
		SELECT 1 FROM audit_events WHERE request_id=$1
	)`, requestID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}
