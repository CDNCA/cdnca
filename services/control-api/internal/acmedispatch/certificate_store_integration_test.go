package acmedispatch

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPGKeyMaterialLoader(t *testing.T) {
	pool := isolatedDispatchPool(t)
	loader := NewPGKeyMaterialLoader()

	t.Run("loads wrapped material and locks the fact", func(t *testing.T) {
		key := newDispatchKey(t)
		spki := dispatchSPKI(t, &key.PublicKey)
		tenant := createDispatchTenant(t, pool, "key-loader-success")
		insertDispatchKeyFact(t, pool, tenant, "certificate/key", "certificate", spki, false)

		tx, err := pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		material, err := loader.LoadOpaquePrivateKey(
			context.Background(), tx, tenant.scopeID, "certificate/key", spki,
		)
		if err != nil {
			t.Fatalf("LoadOpaquePrivateKey() error = %v", err)
		}
		if material.KeyReference != "certificate/key" || !bytes.Equal(material.PublicKeySPKIDER, spki) ||
			len(material.WrappedKeyMaterial) != 64 {
			t.Fatalf("unexpected opaque key: ref=%q spki=%d wrapped=%d",
				material.KeyReference, len(material.PublicKeySPKIDER), len(material.WrappedKeyMaterial))
		}
		var metadata map[string]any
		if err := json.Unmarshal(material.Metadata, &metadata); err != nil ||
			metadata["schema"] != "cdnca.acme-wrapped-key.v1" ||
			metadata["wrapping_key_id"] != "dispatch-test-kek-v1" {
			t.Fatalf("unexpected opaque metadata: %s error=%v", material.Metadata, err)
		}

		second, err := pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = second.Rollback(context.Background()) }()
		_, err = second.Exec(context.Background(), `SELECT 1 FROM acme_tenant_key_facts
			WHERE tenant_scope_id=$1 AND key_ref=$2 FOR UPDATE NOWAIT`, tenant.scopeID, "certificate/key")
		var postgresError *pgconn.PgError
		if !errors.As(err, &postgresError) || postgresError.Code != "55P03" {
			t.Fatalf("second key lock error = %v, want SQLSTATE 55P03", err)
		}
	})

	t.Run("fails closed for ref purpose SPKI actor and external mismatches", func(t *testing.T) {
		key := newDispatchKey(t)
		spki := dispatchSPKI(t, &key.PublicKey)
		otherKey := newDispatchKey(t)
		otherSPKI := dispatchSPKI(t, &otherKey.PublicKey)

		tests := []struct {
			name       string
			purpose    string
			external   bool
			inactive   bool
			lookupRef  string
			lookupSPKI []byte
			want       error
		}{
			{name: "unknown ref", purpose: "certificate", lookupRef: "missing", lookupSPKI: spki, want: ErrConflict},
			{name: "account purpose", purpose: "account", lookupRef: "key", lookupSPKI: spki, want: ErrConflict},
			{name: "SPKI mismatch", purpose: "certificate", lookupRef: "key", lookupSPKI: otherSPKI, want: ErrConflict},
			{name: "inactive actor", purpose: "certificate", inactive: true, lookupRef: "key", lookupSPKI: spki, want: ErrConflict},
			{name: "external handle", purpose: "certificate", external: true, lookupRef: "key", lookupSPKI: spki, want: ErrUnsupportedKeyMaterial},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				tenant := createDispatchTenant(t, pool, "key-loader-"+strings.ReplaceAll(test.name, " ", "-"))
				insertDispatchKeyFact(t, pool, tenant, "key", test.purpose, spki, test.external)
				if test.inactive {
					if _, err := pool.Exec(context.Background(), `UPDATE memberships SET status='suspended'
						WHERE scope_id=$1 AND user_id=$2`, tenant.scopeID, tenant.userID); err != nil {
						t.Fatal(err)
					}
				}
				err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
					_, err := loader.LoadOpaquePrivateKey(
						context.Background(), tx, tenant.scopeID, test.lookupRef, test.lookupSPKI,
					)
					return err
				})
				if !errors.Is(err, test.want) {
					t.Fatalf("LoadOpaquePrivateKey() error = %v, want %v", err, test.want)
				}
			})
		}
	})
}

func TestCertificateStorePostgresTransaction(t *testing.T) {
	pool := isolatedDispatchPool(t)

	t.Run("commit load and exact issued replay", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{finalizing: true})
		if err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
		assertDispatchCommitted(t, fixture)

		loaded, found, err := fixture.store.Load(
			context.Background(), fixture.tenant.scopeID, fixture.request.OperationID,
		)
		if err != nil || !found {
			t.Fatalf("Load() found=%v error=%v", found, err)
		}
		assertIssuedCertificateEqual(t, loaded, fixture.certificate)

		before := dispatchCounts(t, fixture)
		if err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate); err != nil {
			t.Fatalf("exact replay Save() error = %v", err)
		}
		if after := dispatchCounts(t, fixture); after != before {
			t.Fatalf("exact replay changed facts: before=%+v after=%+v", before, after)
		}

		changedURL := fixture.certificate
		changedURL.CertificateURL = "https://ca.example/certificate/other"
		if err := fixture.store.Save(context.Background(), fixture.lease, changedURL); !errors.Is(err, ErrConflict) {
			t.Fatalf("URL replay error = %v, want ErrConflict", err)
		}
		changedCertificate := issueDispatchCertificate(
			t, fixture.privateKey, 2, fixture.databaseNow, 24*time.Hour, fixture.request.Domains,
		)
		changedCertificate.RequestDigest = fixture.lease.Digest
		changedCertificate.CertificateKeyRef = fixture.request.CertificateKeyRef
		changedCertificate.CertificateURL = fixture.certificate.CertificateURL
		if err := fixture.store.Save(context.Background(), fixture.lease, changedCertificate); !errors.Is(err, ErrConflict) {
			t.Fatalf("certificate replay error = %v, want ErrConflict", err)
		}
		if after := dispatchCounts(t, fixture); after != before {
			t.Fatalf("conflicting replay changed facts: before=%+v after=%+v", before, after)
		}
	})

	t.Run("platform admin order for a tenant is issued (migration 531)", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{finalizing: true, platformActor: true})
		if err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate); err != nil {
			t.Fatalf("platform actor Save() error = %v", err)
		}
		assertDispatchCommitted(t, fixture)
		var actorScopeKind string
		if err := pool.QueryRow(context.Background(), `SELECT scope.kind FROM certificate_asset_versions version
			JOIN access_scopes scope ON scope.id=version.actor_scope_id
			WHERE version.tenant_scope_id=$1 AND version.imported_by_user_id=$2`,
			fixture.tenant.scopeID, fixture.tenant.userID).Scan(&actorScopeKind); err != nil || actorScopeKind != "platform" {
			t.Fatalf("imported version actor scope kind = %q err=%v, want platform", actorScopeKind, err)
		}
		// fix-certowner: the certificate belongs to the tenant's user, not to
		// nobody ("历史归属未记录") and not to the platform admin.
		assertDispatchAssetOwner(t, fixture, fixture.tenant.ownerID)
	})

	t.Run("tenant member order records the member as owner (fix-certowner)", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{finalizing: true})
		if err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
		assertDispatchAssetOwner(t, fixture, fixture.tenant.userID)
	})

	t.Run("import failure rolls back", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{finalizing: true, failEnvelope: true})
		err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate)
		if err == nil || !strings.Contains(err.Error(), "certificate private key envelope unavailable") {
			t.Fatalf("import-failure Save() error = %v", err)
		}
		assertDispatchRolledBack(t, fixture)
	})

	t.Run("order update failure rolls back import and audit", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{finalizing: true, corruptImportResult: true})
		err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate)
		if err == nil || !strings.Contains(err.Error(), "finalize ACME certificate order") {
			t.Fatalf("order-update-failure Save() error = %v", err)
		}
		assertDispatchRolledBack(t, fixture)
	})

	t.Run("outer audit failure rolls back order asset envelope and importer audit", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{finalizing: true, failOuterAudit: true})
		err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate)
		if err == nil || !strings.Contains(err.Error(), "injected outer audit failure") {
			t.Fatalf("outer-audit-failure Save() error = %v", err)
		}
		assertDispatchRolledBack(t, fixture)
	})

	t.Run("stale lease is rejected without writes", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{finalizing: true})
		stale := fixture.lease
		stale.Token = uuid.New()
		if err := fixture.store.Save(context.Background(), stale, fixture.certificate); err == nil {
			t.Fatal("stale Save() unexpectedly succeeded")
		}
		assertDispatchRolledBack(t, fixture)
	})

	t.Run("expired lease is rejected without writes", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{
			finalizing: true, leaseDuration: 3 * time.Second,
		})
		waitForDispatchExpiry(t, pool, fixture.lease.ExpiresAt)
		if err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate); err == nil {
			t.Fatal("expired Save() unexpectedly succeeded")
		}
		assertDispatchRolledBack(t, fixture)
	})

	t.Run("non finalizing operation is rejected without writes", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{finalizing: false})
		if err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate); !errors.Is(err, ErrConflict) {
			t.Fatalf("non-finalizing Save() error = %v, want ErrConflict", err)
		}
		assertDispatchRolledBack(t, fixture)
	})

	t.Run("inactive actor is rejected without writes", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{finalizing: true})
		if _, err := pool.Exec(context.Background(), `UPDATE memberships SET status='suspended'
			WHERE scope_id=$1 AND user_id=$2`, fixture.tenant.scopeID, fixture.tenant.userID); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate); !errors.Is(err, ErrConflict) {
			t.Fatalf("inactive-actor Save() error = %v, want ErrConflict", err)
		}
		assertDispatchRolledBack(t, fixture)
	})

	t.Run("caller cancellation leaves no writes", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{finalizing: true})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := fixture.store.Save(ctx, fixture.lease, fixture.certificate); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled Save() error = %v, want context.Canceled", err)
		}
		assertDispatchRolledBack(t, fixture)
	})

	t.Run("durable renewal scheduling is atomic across contenders and restart", func(t *testing.T) {
		fixture := newDispatchFixture(t, pool, dispatchFixtureOptions{
			finalizing: true, certificateLifetime: dueRenewalLifetime,
		})
		if err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate); err != nil {
			t.Fatal(err)
		}
		activateDispatchFixture(t, fixture)
		notDue := newDispatchFixture(t, pool, dispatchFixtureOptions{
			finalizing: true, certificateLifetime: 31 * 24 * time.Hour,
		})
		if err := notDue.store.Save(context.Background(), notDue.lease, notDue.certificate); err != nil {
			t.Fatal(err)
		}
		activateDispatchFixture(t, notDue)

		store := dnsacme.NewStore(pool)
		if _, err := pool.Exec(context.Background(), `CREATE FUNCTION reject_test_renewal_outbox()
			RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test renewal outbox rejection'; END $$;
			CREATE TRIGGER reject_test_renewal_outbox_trigger BEFORE INSERT ON dns_acme_outbox
			FOR EACH ROW EXECUTE FUNCTION reject_test_renewal_outbox()`); err != nil {
			t.Fatal(err)
		}
		if scheduled, err := store.ScheduleDueRenewal(
			context.Background(), 30*24*time.Hour, 10*time.Minute,
		); err == nil || scheduled {
			t.Fatalf("injected rollback scheduling=%t error=%v", scheduled, err)
		}
		var rolledBackStatus string
		var rolledBackClaims, rolledBackChildren, rolledBackAudits int
		if err := pool.QueryRow(context.Background(), `SELECT
			(SELECT status FROM certificate_orders WHERE scope_id=$1 AND id=$2),
			(SELECT count(*) FROM acme_renewal_claim_facts WHERE tenant_scope_id=$1 AND source_order_id=$2),
			(SELECT count(*) FROM certificate_orders WHERE scope_id=$1 AND renewal_of_order_id=$2),
			(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='certificate.order.renew')`,
			fixture.tenant.scopeID, fixture.request.CertificateOrderID).Scan(
			&rolledBackStatus, &rolledBackClaims, &rolledBackChildren, &rolledBackAudits,
		); err != nil {
			t.Fatal(err)
		}
		if rolledBackStatus != "active" || rolledBackClaims != 0 || rolledBackChildren != 0 || rolledBackAudits != 0 {
			t.Fatalf("rollback status=%s claims=%d children=%d audits=%d",
				rolledBackStatus, rolledBackClaims, rolledBackChildren, rolledBackAudits)
		}
		if _, err := pool.Exec(context.Background(), `DROP TRIGGER reject_test_renewal_outbox_trigger
			ON dns_acme_outbox; DROP FUNCTION reject_test_renewal_outbox()`); err != nil {
			t.Fatal(err)
		}

		const contenders = 8
		start := make(chan struct{})
		results := make(chan bool, contenders)
		errorsSeen := make(chan error, contenders)
		var wait sync.WaitGroup
		for range contenders {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				scheduled, err := store.ScheduleDueRenewal(
					context.Background(), 30*24*time.Hour, 10*time.Minute,
				)
				if err != nil {
					errorsSeen <- err
					return
				}
				results <- scheduled
			}()
		}
		close(start)
		wait.Wait()
		close(results)
		close(errorsSeen)
		for err := range errorsSeen {
			t.Fatal(err)
		}
		var winners int
		for scheduled := range results {
			if scheduled {
				winners++
			}
		}
		if winners != 1 {
			t.Fatalf("renewal scheduling winners=%d, want 1", winners)
		}

		var sourceStatus string
		var childID, childScope, childActor uuid.UUID
		var childProvider *uuid.UUID
		var childDomains []string
		var childChallenge string
		var childAutoRenew bool
		if err := pool.QueryRow(context.Background(), `SELECT source.status,child.id,child.scope_id,
			child.dns_provider_id,child.domains,child.challenge_type,child.auto_renew,child.created_by_user_id
			FROM certificate_orders source
			JOIN certificate_orders child
			  ON child.scope_id=source.scope_id AND child.renewal_of_order_id=source.id
			WHERE source.scope_id=$1 AND source.id=$2`, fixture.tenant.scopeID,
			fixture.request.CertificateOrderID).Scan(
			&sourceStatus, &childID, &childScope, &childProvider, &childDomains,
			&childChallenge, &childAutoRenew, &childActor,
		); err != nil {
			t.Fatal(err)
		}
		if sourceStatus != "renewal_due" || childID == uuid.Nil || childScope != fixture.tenant.scopeID ||
			childProvider != nil || !equalDispatchStrings(childDomains, fixture.request.Domains) ||
			childChallenge != string(fixture.request.ChallengeType) || !childAutoRenew ||
			childActor != fixture.tenant.userID {
			t.Fatalf("source=%s child=%s scope=%s provider=%v domains=%v challenge=%s auto=%t actor=%s",
				sourceStatus, childID, childScope, childProvider, childDomains,
				childChallenge, childAutoRenew, childActor)
		}
		var outboxCount, claimCount, auditCount int
		var eventTypes []string
		if err := pool.QueryRow(context.Background(), `SELECT
			(SELECT count(*) FROM dns_acme_outbox WHERE scope_id=$1 AND aggregate_id=$2),
			(SELECT count(*) FROM acme_renewal_claim_facts WHERE tenant_scope_id=$1 AND source_order_id=$3),
			(SELECT array_agg(event_type ORDER BY revision) FROM acme_renewal_claim_facts
			  WHERE tenant_scope_id=$1 AND source_order_id=$3),
			(SELECT count(*) FROM audit_events WHERE scope_id=$1
			  AND action='certificate.order.renew' AND resource_id=$2::text)`,
			fixture.tenant.scopeID, childID, fixture.request.CertificateOrderID).Scan(
			&outboxCount, &claimCount, &eventTypes, &auditCount,
		); err != nil {
			t.Fatal(err)
		}
		if outboxCount != 1 || claimCount != 2 ||
			!equalDispatchStrings(eventTypes, []string{"claim_created", "completed"}) || auditCount != 1 {
			t.Fatalf("renewal facts outbox=%d claims=%d events=%v audits=%d",
				outboxCount, claimCount, eventTypes, auditCount)
		}
		if scheduled, err := store.ScheduleDueRenewal(
			context.Background(), 30*24*time.Hour, 10*time.Minute,
		); err != nil || scheduled {
			t.Fatalf("restart scheduling=%t error=%v", scheduled, err)
		}
		var notDueStatus string
		var notDueChildren int
		if err := pool.QueryRow(context.Background(), `SELECT source.status,
			count(child.id) FROM certificate_orders source
			LEFT JOIN certificate_orders child
			  ON child.scope_id=source.scope_id AND child.renewal_of_order_id=source.id
			WHERE source.scope_id=$1 AND source.id=$2 GROUP BY source.status`,
			notDue.tenant.scopeID, notDue.request.CertificateOrderID).Scan(
			&notDueStatus, &notDueChildren,
		); err != nil {
			t.Fatal(err)
		}
		if notDueStatus != "active" || notDueChildren != 0 {
			t.Fatalf("outside-window source status=%s children=%d", notDueStatus, notDueChildren)
		}
	})
}

func assertDispatchAssetOwner(t *testing.T, fixture dispatchFixture, want uuid.UUID) {
	t.Helper()
	var owner *uuid.UUID
	if err := fixture.pool.QueryRow(context.Background(), `SELECT asset.owner_user_id FROM certificate_assets asset
		JOIN certificate_orders certificate_order ON certificate_order.scope_id=asset.tenant_scope_id
		 AND certificate_order.issued_asset_id=asset.id
		WHERE certificate_order.scope_id=$1 AND certificate_order.id=$2`,
		fixture.tenant.scopeID, fixture.request.CertificateOrderID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner == nil || *owner != want {
		t.Fatalf("ACME asset owner = %v, want %s", owner, want)
	}
}

type dispatchFixtureOptions struct {
	finalizing          bool
	leaseDuration       time.Duration
	certificateLifetime time.Duration
	failEnvelope        bool
	corruptImportResult bool
	failOuterAudit      bool
	platformActor       bool // the order is placed by a platform admin, not a tenant member
}

type dispatchFixture struct {
	pool        *pgxpool.Pool
	tenant      dispatchTenant
	request     acmeworker.IssueRequest
	lease       acmeworker.OperationLease
	certificate acmeworker.IssuedCertificate
	privateKey  *ecdsa.PrivateKey
	databaseNow time.Time
	store       *CertificateStore
}

func newDispatchFixture(t *testing.T, pool *pgxpool.Pool, options dispatchFixtureOptions) dispatchFixture {
	t.Helper()
	if options.leaseDuration == 0 {
		options.leaseDuration = 5 * time.Minute
	}
	if options.certificateLifetime == 0 {
		options.certificateLifetime = 24 * time.Hour
	}
	tenant := createDispatchTenant(t, pool, "dispatch-"+strings.ReplaceAll(uuid.NewString(), "-", "")[:10])
	tenant.ownerID = tenant.userID
	if options.platformActor {
		tenant.userID = createDispatchPlatformAdmin(t, pool)
	}
	databaseNow := dispatchDatabaseNow(t, pool)
	privateKey := newDispatchKey(t)
	certificate := issueDispatchCertificate(
		t, privateKey, 1, databaseNow, options.certificateLifetime, []string{"example.test"},
	)
	certificateKeyRef := "certificate/" + uuid.NewString()
	accountKeyRef := "account/" + uuid.NewString()
	insertDispatchKeyFact(t, pool, tenant, certificateKeyRef, "certificate",
		dispatchSPKI(t, &privateKey.PublicKey), false)
	accountKeyID := insertDispatchKeyFact(t, pool, tenant, accountKeyRef, "account",
		dispatchSPKI(t, &newDispatchKey(t).PublicKey), true)

	orderID := uuid.New()
	request := acmeworker.IssueRequest{
		TenantID: tenant.tenantID, ScopeID: tenant.scopeID, OperationID: orderID.String(), CertificateOrderID: orderID,
		ActorUserID: tenant.userID, DirectoryURL: "https://ca.example/directory",
		AccountKeyRef: accountKeyRef, CertificateKeyRef: certificateKeyRef,
		Contacts: []string{"mailto:ops@example.test"}, AcceptTerms: true,
		Domains: []string{"example.test"}, ChallengeType: acmeworker.ChallengeHTTP01,
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO certificate_orders(
		id,scope_id,domains,challenge_type,created_by_user_id,updated_by_user_id
	) VALUES($1,$2,$3,'http-01',$4,$4)`, orderID, tenant.scopeID, request.Domains, tenant.userID); err != nil {
		t.Fatal(err)
	}
	operationStore, err := acmeworker.NewPGOperationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	digest := dispatchIssueDigest(request)
	claim, err := operationStore.Claim(
		context.Background(), request, digest, databaseNow, databaseNow.Add(options.leaseDuration),
	)
	if err != nil || claim.State != acmeworker.OperationClaimed {
		t.Fatalf("Claim() state=%s error=%v (%s)", claim.State, err, acmeworker.FailureDetail(err))
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO acme_account_registration_facts(
		tenant_scope_id,id,account_key_id,directory_url,account_uri,contacts,
		terms_agreed_at,registered_at,created_by_user_id
	) VALUES($1,$2,$3,$4,$5,$6,$7,$7,$8)`, tenant.scopeID, uuid.New(), accountKeyID,
		request.DirectoryURL, "https://ca.example/account/1", request.Contacts, databaseNow, tenant.userID); err != nil {
		t.Fatal(err)
	}
	lease := advanceDispatch(t, operationStore, claim.Lease, "account_registered", func(state *acmeworker.OperationState) {
		state.AccountURI = "https://ca.example/account/1"
	}, databaseNow)
	lease = advanceDispatch(t, operationStore, lease, "order_intent", func(state *acmeworker.OperationState) {
		state.OrderIntentPending = true
	}, databaseNow)
	lease = advanceDispatch(t, operationStore, lease, "order_created", func(state *acmeworker.OperationState) {
		state.Phase = acmeworker.PhaseOrdered
		state.OrderIntentPending = false
		state.OrderURL = "https://ca.example/order/" + orderID.String()
		state.FinalizeURL = "https://ca.example/finalize/" + orderID.String()
		state.AuthorizationURLs = []string{"https://ca.example/authorization/" + orderID.String()}
	}, databaseNow)
	lease = advanceDispatch(t, operationStore, lease, "authorizing", func(state *acmeworker.OperationState) {
		state.Phase = acmeworker.PhaseAuthorizing
	}, databaseNow)
	lease = advanceDispatch(t, operationStore, lease, "authorization_ready", func(state *acmeworker.OperationState) {
		state.Phase = acmeworker.PhaseReady
	}, databaseNow)
	if options.finalizing {
		lease = advanceDispatch(t, operationStore, lease, "finalize_intent", func(state *acmeworker.OperationState) {
			state.Phase = acmeworker.PhaseFinalizing
		}, databaseNow)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE certificate_orders
		SET status='validating',revision=revision+1,updated_at=statement_timestamp()
		WHERE scope_id=$1 AND id=$2`, tenant.scopeID, orderID); err != nil {
		t.Fatalf("advance certificate order to validating: %v", err)
	}
	certificate.RequestDigest = lease.Digest
	certificate.CertificateKeyRef = request.CertificateKeyRef
	certificate.CertificateURL = "https://ca.example/certificate/" + orderID.String()

	enveloper := &dispatchEnveloper{fail: options.failEnvelope}
	assetStore, err := certificateasset.NewStoreWithDependencies(pool, enveloper, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var importer CertificateImporter = assetStore
	if options.corruptImportResult {
		importer = corruptingDispatchImporter{delegate: importer}
	}
	var auditor AuditAppender = audit.New(pool)
	if options.failOuterAudit {
		auditor = failingDispatchAuditor{}
	}
	store, err := NewCertificateStoreWithAudit(
		pool, operationStore, importer, NewPGKeyMaterialLoader(), auditor,
	)
	if err != nil {
		t.Fatal(err)
	}
	return dispatchFixture{
		pool: pool, tenant: tenant, request: request, lease: lease, certificate: certificate,
		privateKey: privateKey, databaseNow: databaseNow, store: store,
	}
}

func advanceDispatch(
	t *testing.T,
	store acmeworker.OperationStore,
	lease acmeworker.OperationLease,
	event string,
	mutate func(*acmeworker.OperationState),
	now time.Time,
) acmeworker.OperationLease {
	t.Helper()
	next := lease.State
	next.AuthorizationURLs = append([]string(nil), lease.State.AuthorizationURLs...)
	mutate(&next)
	advanced, err := store.Advance(context.Background(), lease, event, next, now)
	if err != nil {
		t.Fatalf("Advance(%s) error = %v", event, err)
	}
	return advanced
}

func activateDispatchFixture(t *testing.T, fixture dispatchFixture) {
	t.Helper()
	for _, status := range []string{"deploying", "active"} {
		if _, err := fixture.pool.Exec(context.Background(), `UPDATE certificate_orders
			SET status=$3,revision=revision+1,updated_at=statement_timestamp()
			WHERE scope_id=$1 AND id=$2`, fixture.tenant.scopeID,
			fixture.request.CertificateOrderID, status); err != nil {
			t.Fatalf("activate source order at %s: %v", status, err)
		}
	}
}

type dispatchEnveloper struct {
	fail bool
}

func (*dispatchEnveloper) Seal(context.Context, certificateasset.PrivateKeySealRequest) (certificateasset.PrivateKeyEnvelope, error) {
	return certificateasset.PrivateKeyEnvelope{}, errors.New("plaintext sealing is not supported in dispatch tests")
}

func (enveloper *dispatchEnveloper) SealOpaque(
	_ context.Context,
	request certificateasset.OpaquePrivateKeySealRequest,
) (certificateasset.PrivateKeyEnvelope, error) {
	if enveloper.fail {
		return certificateasset.PrivateKeyEnvelope{}, errors.New("injected opaque envelope failure")
	}
	aad, err := request.Context.CanonicalAAD()
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, err
	}
	digest := sha256.Sum256(append(append([]byte(nil), aad...), request.WrappedKeyMaterial...))
	return certificateasset.PrivateKeyEnvelope{
		KeyID: "dispatch-asset-kek-v1", Ciphertext: digest[:], Nonce: bytes.Repeat([]byte{0x91}, 12),
		Metadata: json.RawMessage(`{"schema":"dispatch-test-envelope.v1"}`),
	}, nil
}

func (*dispatchEnveloper) Unseal(context.Context, certificateasset.PrivateKeyUnsealRequest) ([]byte, error) {
	return nil, errors.New("unseal is not supported in dispatch tests")
}

func (*dispatchEnveloper) Rewrap(
	context.Context,
	certificateasset.PrivateKeyRewrapRequest,
) (certificateasset.PrivateKeyEnvelope, error) {
	return certificateasset.PrivateKeyEnvelope{}, errors.New("rewrap is not supported in dispatch tests")
}

type corruptingDispatchImporter struct {
	delegate CertificateImporter
}

func (importer corruptingDispatchImporter) ImportACMEInTx(
	ctx context.Context,
	tx pgx.Tx,
	request certificateasset.ACMEImportRequest,
) (certificateasset.ImportResult, error) {
	result, err := importer.delegate.ImportACMEInTx(ctx, tx, request)
	if err == nil {
		result.Version.ID = uuid.New()
	}
	return result, err
}

type failingDispatchAuditor struct{}

func (failingDispatchAuditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("injected outer audit failure")
}

type dispatchTenant struct {
	tenantID uuid.UUID
	scopeID  uuid.UUID
	userID   uuid.UUID
	ownerID  uuid.UUID // the tenant's own user (userID is the platform admin for platformActor)
}

func createDispatchTenant(t *testing.T, pool *pgxpool.Pool, name string) dispatchTenant {
	t.Helper()
	tenant := dispatchTenant{tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New()}
	roleID := uuid.New()
	username := "dispatch-" + strings.ReplaceAll(tenant.userID.String(), "-", "")
	ctx := context.Background()
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{tenant.tenantID, name}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{tenant.scopeID, tenant.tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'test-hash')`, []any{tenant.userID, username, name}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{tenant.scopeID, tenant.userID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','dispatch test role',true)`, []any{roleID, tenant.scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'certificates.read'),($1,'certificates.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{tenant.scopeID, tenant.userID, roleID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed dispatch tenant: %v", err)
		}
	}
	return tenant
}

// createDispatchPlatformAdmin seeds an active platform member holding
// certificates.manage on the platform scope and no tenant membership.
func createDispatchPlatformAdmin(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var platformScopeID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY id LIMIT 1`).
		Scan(&platformScopeID); errors.Is(err, pgx.ErrNoRows) {
		platformScopeID = uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScopeID); err != nil {
			t.Fatalf("seed platform scope: %v", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	userID, roleID := uuid.New(), uuid.New()
	suffix := strings.ReplaceAll(userID.String(), "-", "")
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'platform admin','test-hash')`, []any{userID, "dispatch-admin-" + suffix}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{platformScopeID, userID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'dispatch platform role',true)`, []any{roleID, platformScopeID, "dispatch_admin_" + suffix[:12]}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'certificates.read'),($1,'certificates.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{platformScopeID, userID, roleID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed dispatch platform admin: %v", err)
		}
	}
	return userID
}

func insertDispatchKeyFact(
	t *testing.T,
	pool *pgxpool.Pool,
	tenant dispatchTenant,
	keyRef, purpose string,
	spki []byte,
	external bool,
) uuid.UUID {
	t.Helper()
	id := uuid.New()
	digest := sha256.Sum256(spki)
	if external {
		if _, err := pool.Exec(context.Background(), `INSERT INTO acme_tenant_key_facts(
			tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
			external_key_reference,created_by_user_id
		) VALUES($1,$2,$3,$4,'ecdsa',$5,$6,$7)`, tenant.scopeID, id, keyRef, purpose,
			digest[:], "kms://dispatch/"+id.String(), tenant.userID); err != nil {
			t.Fatal(err)
		}
		return id
	}
	aad := sha256.Sum256([]byte("dispatch-aad/" + id.String()))
	if _, err := pool.Exec(context.Background(), `INSERT INTO acme_tenant_key_facts(
		tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
		wrapped_key_ciphertext,wrapping_key_id,wrapping_nonce,wrapping_aad_sha256,created_by_user_id
	) VALUES($1,$2,$3,$4,'ecdsa',$5,$6,'dispatch-test-kek-v1',$7,$8,$9)`,
		tenant.scopeID, id, keyRef, purpose, digest[:], bytes.Repeat([]byte{0x5a}, 64),
		bytes.Repeat([]byte{0x17}, 12), aad[:], tenant.userID); err != nil {
		t.Fatal(err)
	}
	return id
}

func newDispatchKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func dispatchSPKI(t *testing.T, key *ecdsa.PublicKey) []byte {
	t.Helper()
	value, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func issueDispatchCertificate(
	t *testing.T,
	key *ecdsa.PrivateKey,
	serial int64,
	now time.Time,
	lifetime time.Duration,
	domains []string,
) acmeworker.IssuedCertificate {
	t.Helper()
	notBefore := now.UTC().Add(-time.Minute).Truncate(time.Second)
	notAfter := now.UTC().Add(lifetime).Truncate(time.Second)
	issuerKey := newDispatchKey(t)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1000 + serial), Subject: pkix.Name{CommonName: "Dispatch Test CA"},
		NotBefore: notBefore.Add(-time.Hour), NotAfter: notAfter.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
	}
	issuerDER, err := x509.CreateCertificate(
		rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains,
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(der)
	spkiDigest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	certificatePEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})...,
	)
	return acmeworker.IssuedCertificate{
		PublicKeySPKISHA256: "sha256:" + hex.EncodeToString(spkiDigest[:]),
		LeafDER:             der, ChainDER: [][]byte{der, issuerDER}, CertificatePEM: certificatePEM,
		SerialNumber: strings.ToLower(leaf.SerialNumber.Text(16)), DNSNames: append([]string(nil), domains...),
		NotBefore: notBefore, NotAfter: notAfter,
		LeafFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]),
	}
}

// dueRenewalLifetime makes a fixture certificate due for a 30-day renewBefore
// whatever its jitter: dnsacme delays the initial due by up to
// min(renewBefore/4, 24h) (renewalInitialDue, dnsacme/store.go), so the
// lifetime leaves that whole window plus a minute.
const dueRenewalLifetime = 30*24*time.Hour - 24*time.Hour - time.Minute

// dispatchIssueDigest mirrors acmeworker's issueRequestDigest (worker.go),
// which PGOperationStore.Claim requires the caller's digest to equal.
func dispatchIssueDigest(request acmeworker.IssueRequest) string {
	hash := sha256.New()
	for _, value := range []string{
		request.TenantID.String(), request.ScopeID.String(), request.OperationID, request.CertificateOrderID.String(),
		request.ActorUserID.String(), request.DirectoryURL, request.ProviderID.String(), request.ZoneID.String(),
		request.ProviderRef, request.AccountKeyRef, request.CertificateKeyRef, string(request.ChallengeType),
		strings.Join(request.Contacts, "\x00"), strconv.FormatBool(request.AcceptTerms),
		strings.Join(request.Domains, "\x00"),
	} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0xff})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

type dispatchFactCounts struct {
	assets    int
	versions  int
	envelopes int
	writes    int
	audits    int
}

func dispatchCounts(t *testing.T, fixture dispatchFixture) dispatchFactCounts {
	t.Helper()
	var result dispatchFactCounts
	queries := []struct {
		destination *int
		sql         string
	}{
		{&result.assets, `SELECT count(*) FROM certificate_assets WHERE tenant_scope_id=$1`},
		{&result.versions, `SELECT count(*) FROM certificate_asset_versions WHERE tenant_scope_id=$1`},
		{&result.envelopes, `SELECT count(*) FROM certificate_asset_private_key_envelope_facts WHERE tenant_scope_id=$1`},
		{&result.writes, `SELECT count(*) FROM certificate_asset_write_requests WHERE tenant_scope_id=$1`},
		{&result.audits, `SELECT count(*) FROM audit_events WHERE scope_id=$1`},
	}
	for _, query := range queries {
		if err := fixture.pool.QueryRow(context.Background(), query.sql, fixture.tenant.scopeID).Scan(query.destination); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func assertDispatchCommitted(t *testing.T, fixture dispatchFixture) {
	t.Helper()
	counts := dispatchCounts(t, fixture)
	if counts.assets != 1 || counts.versions != 1 || counts.envelopes != 1 || counts.writes != 1 || counts.audits != 3 {
		t.Fatalf("committed fact counts = %+v", counts)
	}
	var status, certificateURL string
	var assetID, versionID uuid.UUID
	if err := fixture.pool.QueryRow(context.Background(), `SELECT status,issued_asset_id,
		issued_asset_version_id,certificate_url FROM certificate_orders WHERE scope_id=$1 AND id=$2`,
		fixture.tenant.scopeID, fixture.request.CertificateOrderID,
	).Scan(&status, &assetID, &versionID, &certificateURL); err != nil {
		t.Fatal(err)
	}
	if status != "issued" || assetID == uuid.Nil || versionID == uuid.Nil || certificateURL != fixture.certificate.CertificateURL {
		t.Fatalf("unexpected committed order status=%s asset=%s version=%s URL=%q",
			status, assetID, versionID, certificateURL)
	}
	var versionOrderID uuid.UUID
	var versionKeyRef, envelopeKeyRef string
	var versionFingerprint, envelopeFingerprint []byte
	if err := fixture.pool.QueryRow(context.Background(), `SELECT version.acme_order_id,
		version.private_key_reference,envelope.private_key_reference,version.fingerprint_sha256,
		envelope.certificate_fingerprint_sha256
		FROM certificate_asset_versions version
		JOIN certificate_asset_private_key_envelope_facts envelope
		  ON envelope.tenant_scope_id=version.tenant_scope_id
		 AND envelope.asset_id=version.asset_id AND envelope.version_id=version.id
		WHERE version.tenant_scope_id=$1 AND version.asset_id=$2 AND version.id=$3`,
		fixture.tenant.scopeID, assetID, versionID,
	).Scan(&versionOrderID, &versionKeyRef, &envelopeKeyRef, &versionFingerprint, &envelopeFingerprint); err != nil {
		t.Fatal(err)
	}
	if versionOrderID != fixture.request.CertificateOrderID ||
		versionKeyRef != fixture.request.CertificateKeyRef || envelopeKeyRef != versionKeyRef ||
		!bytes.Equal(versionFingerprint, envelopeFingerprint) {
		t.Fatalf("asset/envelope provenance mismatch order=%s version-key=%q envelope-key=%q",
			versionOrderID, versionKeyRef, envelopeKeyRef)
	}
	var assetAudit, transitionAudit, orderAudit int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT
		count(*) FILTER (WHERE action='certificate.asset.import'),
		count(*) FILTER (WHERE action='certificate.order.transition'),
		count(*) FILTER (WHERE action='certificate.order.finalize_issued')
		FROM audit_events WHERE scope_id=$1`, fixture.tenant.scopeID).Scan(
		&assetAudit, &transitionAudit, &orderAudit,
	); err != nil {
		t.Fatal(err)
	}
	if assetAudit != 1 || transitionAudit != 1 || orderAudit != 1 {
		t.Fatalf("committed audit actions asset=%d transition=%d order=%d",
			assetAudit, transitionAudit, orderAudit)
	}
}

func assertDispatchRolledBack(t *testing.T, fixture dispatchFixture) {
	t.Helper()
	if counts := dispatchCounts(t, fixture); counts != (dispatchFactCounts{}) {
		t.Fatalf("rolled-back fact counts = %+v", counts)
	}
	var status string
	var revision int64
	if err := fixture.pool.QueryRow(context.Background(), `SELECT status,revision FROM certificate_orders
		WHERE scope_id=$1 AND id=$2`, fixture.tenant.scopeID, fixture.request.CertificateOrderID).
		Scan(&status, &revision); err != nil {
		t.Fatal(err)
	}
	if status != "validating" || revision != 2 {
		t.Fatalf("rolled-back order status=%s revision=%d, want validating/2", status, revision)
	}
}

func assertIssuedCertificateEqual(
	t *testing.T,
	actual, expected acmeworker.IssuedCertificate,
) {
	t.Helper()
	if actual.RequestDigest != expected.RequestDigest ||
		actual.CertificateKeyRef != expected.CertificateKeyRef ||
		actual.PublicKeySPKISHA256 != expected.PublicKeySPKISHA256 ||
		actual.CertificateURL != expected.CertificateURL ||
		actual.SerialNumber != expected.SerialNumber ||
		actual.LeafFingerprint != expected.LeafFingerprint ||
		!actual.NotBefore.Equal(expected.NotBefore) || !actual.NotAfter.Equal(expected.NotAfter) ||
		!equalDispatchStrings(actual.DNSNames, expected.DNSNames) ||
		!bytes.Equal(actual.CertificatePEM, expected.CertificatePEM) ||
		!bytes.Equal(actual.LeafDER, expected.LeafDER) ||
		len(actual.ChainDER) != len(expected.ChainDER) {
		t.Fatalf("loaded certificate differs:\nactual=%+v\nexpected=%+v", actual, expected)
	}
	for index := range actual.ChainDER {
		if !bytes.Equal(actual.ChainDER[index], expected.ChainDER[index]) {
			t.Fatalf("loaded certificate chain item %d differs", index)
		}
	}
}

func equalDispatchStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func waitForDispatchExpiry(t *testing.T, pool *pgxpool.Pool, expiresAt time.Time) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if dispatchDatabaseNow(t, pool).After(expiresAt) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("database clock did not pass lease expiry %s", expiresAt)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func dispatchDatabaseNow(t *testing.T, pool *pgxpool.Pool) time.Time {
	t.Helper()
	var now time.Time
	if err := pool.QueryRow(context.Background(), `SELECT statement_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now.UTC()
}

func isolatedDispatchPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "acmedispatch_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop dispatch schema: %v", err)
		}
		admin.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate dispatch schema: %v", err)
	}
	var version int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	// 迁移从 1 连续编号（internal/database/migrate.go 加载器校验），发布头随仓库增长，不写死。
	head, err := fs.Glob(controlmigrations.FS, "*.up.sql")
	if err != nil || len(head) == 0 {
		t.Fatalf("list embedded migrations: %d %v", len(head), err)
	}
	if version != len(head) {
		t.Fatalf("migration version=%d, want %d", version, len(head))
	}
	return pool
}

func TestCertificateStoreInputValidation(t *testing.T) {
	if _, err := NewCertificateStoreWithAudit(nil, nil, nil, nil, nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewCertificateStoreWithAudit() error = %v", err)
	}
	loader := NewPGKeyMaterialLoader()
	if _, err := loader.LoadOpaquePrivateKey(
		context.Background(), nil, uuid.Nil, "", nil,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid loader input error = %v", err)
	}
	if !strings.Contains(fmt.Sprint(ErrUnsupportedKeyMaterial), "unsupported") {
		t.Fatal("unsupported key material error is not stable")
	}
}
