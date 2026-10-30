//go:build integration

package acmedispatch

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Only the external CA is a call counter. Scheduler, outbox, dispatcher, keys,
// certificates, RBAC, toggles, transactions and audit use the production code.
type auditIssuerCounter struct{ calls int }

func (issuer *auditIssuerCounter) Issue(context.Context, acmeworker.IssueRequest) (acmeworker.IssueResult, error) {
	issuer.calls++
	return acmeworker.IssueResult{}, &acmeworker.Error{Code: acmeworker.CodeTimeout}
}

func auditAssetStore(t *testing.T, f dispatchFixture) (*certificateasset.Store, certificateasset.Actor) {
	t.Helper()
	store, err := certificateasset.NewStoreWithDependencies(f.pool, &dispatchEnveloper{}, audit.New(f.pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return store, certificateasset.Actor{UserID: f.tenant.userID, ScopeID: f.tenant.scopeID, ScopeKind: certificateasset.ScopeTenant}
}

func auditIssuedAsset(t *testing.T, f dispatchFixture) (uuid.UUID, uuid.UUID, int64) {
	t.Helper()
	var assetID, versionID uuid.UUID
	var revision int64
	if err := f.pool.QueryRow(t.Context(), `SELECT cert_order.issued_asset_id,cert_order.issued_asset_version_id,asset.revision
		FROM certificate_orders cert_order JOIN certificate_assets asset
		 ON asset.tenant_scope_id=cert_order.scope_id AND asset.id=cert_order.issued_asset_id
		WHERE cert_order.scope_id=$1 AND cert_order.id=$2`, f.tenant.scopeID, f.request.CertificateOrderID).
		Scan(&assetID, &versionID, &revision); err != nil {
		t.Fatal(err)
	}
	return assetID, versionID, revision
}

func TestAuditQueuedRenewalRespectsLatestAssetIntent(t *testing.T) {
	for _, mode := range []string{"disable_before_queue", "auto_renew_off_after_queue", "disable_after_queue"} {
		t.Run(mode, func(t *testing.T) {
			f := newDispatchFixture(t, databasetest.MigratedPool(t, nil), dispatchFixtureOptions{
				finalizing: true, certificateLifetime: dueRenewalLifetime,
			})
			if err := f.store.Save(t.Context(), f.lease, f.certificate); err != nil {
				t.Fatal(err)
			}
			activateDispatchFixture(t, f)
			assets, actor := auditAssetStore(t, f)
			assetID, _, revision := auditIssuedAsset(t, f)
			mutate := func() {
				t.Helper()
				var err error
				if mode == "auto_renew_off_after_queue" {
					_, err = assets.SetAutoRenew(t.Context(), actor, certificateasset.SetAutoRenewRequest{
						TenantScopeID: f.tenant.scopeID, AssetID: assetID, Enabled: false, ExpectedRevision: revision,
						IdempotencyKey: "audit-auto-off", RequestID: "audit-auto-off",
					})
				} else {
					_, err = assets.SetDisabled(t.Context(), actor, certificateasset.SetDisabledRequest{
						TenantScopeID: f.tenant.scopeID, AssetID: assetID, Disabled: true, ExpectedRevision: revision,
						IdempotencyKey: "audit-disable", RequestID: "audit-disable",
					})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "disable_before_queue" {
				mutate()
			}
			scheduled, err := dnsacme.NewStore(f.pool).ScheduleDueRenewal(t.Context(), 30*24*time.Hour, 10*time.Minute)
			if mode == "disable_before_queue" {
				if err != nil || scheduled {
					t.Fatalf("pre-queue disable scheduled=%t error=%v", scheduled, err)
				}
				t.Log("CONTROL disabled before scheduler: no child enqueued")
				return
			}
			if err != nil || !scheduled {
				t.Fatalf("queue scheduled=%t error=%v", scheduled, err)
			}
			var childID uuid.UUID
			if err := f.pool.QueryRow(t.Context(), `SELECT id FROM certificate_orders WHERE scope_id=$1 AND renewal_of_order_id=$2`,
				f.tenant.scopeID, f.request.CertificateOrderID).Scan(&childID); err != nil {
				t.Fatal(err)
			}
			mutate()
			keys, err := acmeruntime.NewKeyStore(f.pool, "audit-runtime-kek", make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			issuer := &auditIssuerCounter{}
			dispatcher, err := acmeruntime.NewDispatcher(f.pool, issuer, keys,
				acmeruntime.DefaultConfig("https://ca.example/directory", []string{"mailto:ops@example.test"}))
			if err != nil {
				t.Fatal(err)
			}
			result, err := dispatcher.DispatchOne(t.Context())
			var autoRenew, disabled bool
			var childStatus, parentStatus string
			if scanErr := f.pool.QueryRow(t.Context(), `SELECT asset.auto_renew,asset.disabled,child.status,parent.status
				FROM certificate_assets asset JOIN certificate_orders parent ON parent.scope_id=asset.tenant_scope_id AND parent.issued_asset_id=asset.id
				JOIN certificate_orders child ON child.scope_id=parent.scope_id AND child.renewal_of_order_id=parent.id
				WHERE asset.tenant_scope_id=$1 AND asset.id=$2`, f.tenant.scopeID, assetID).
				Scan(&autoRenew, &disabled, &childStatus, &parentStatus); scanErr != nil {
				t.Fatal(scanErr)
			}
			if err != nil || result.OrderID != childID {
				t.Fatalf("dispatcher did not examine scheduled child: %+v error=%v", result, err)
			}
			if issuer.calls != 0 {
				t.Fatalf("BUG latest asset intent ignored: mode=%s auto_renew=%t disabled=%t parent=%s child=%s ca_calls=%d outcome=%s code=%s",
					mode, autoRenew, disabled, parentStatus, childStatus, issuer.calls, result.Outcome, result.ErrorCode)
			}
		})
	}
}

// A controlled CA boundary, with production dispatcher-generated request/key
// references and production durable operation/asset stores. No network CA or
// edge node is claimed by this test.
type auditPersistingIssuer struct {
	t      *testing.T
	parent dispatchFixture
	keys   *acmeruntime.KeyStore
	child  dispatchFixture
}

func (issuer *auditPersistingIssuer) Issue(ctx context.Context, request acmeworker.IssueRequest) (acmeworker.IssueResult, error) {
	t, parent := issuer.t, issuer.parent
	childID := request.CertificateOrderID
	t.Helper()
	now := dispatchDatabaseNow(t, parent.pool)
	signer, err := issuer.keys.Signer(ctx, request.CertificateKeyRef)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("unexpected generated signer %T", signer)
	}
	accounts, err := acmeruntime.NewAccountStore(parent.pool, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.SaveAccount(ctx, request.DirectoryURL, request.AccountKeyRef, acmeworker.AccountRegistration{
		URI: "https://ca.example/account/renewal", Contact: request.Contacts,
	}); err != nil {
		t.Fatal(err)
	}
	operationStore, err := acmeworker.NewPGOperationStore(parent.pool)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := operationStore.Claim(t.Context(), request, dispatchIssueDigest(request), now, now.Add(5*time.Minute))
	if err != nil || claimed.State != acmeworker.OperationClaimed {
		t.Fatalf("claim real scheduler child state=%s error=%v", claimed.State, err)
	}
	lease := advanceDispatch(t, operationStore, claimed.Lease, "account_registered", func(s *acmeworker.OperationState) {
		s.AccountURI = "https://ca.example/account/renewal"
	}, now)
	lease = advanceDispatch(t, operationStore, lease, "order_intent", func(s *acmeworker.OperationState) {
		s.OrderIntentPending = true
	}, now)
	lease = advanceDispatch(t, operationStore, lease, "order_created", func(s *acmeworker.OperationState) {
		s.Phase, s.OrderIntentPending = acmeworker.PhaseOrdered, false
		s.OrderURL, s.FinalizeURL = "https://ca.example/order/"+childID.String(), "https://ca.example/finalize/"+childID.String()
		s.AuthorizationURLs = []string{"https://ca.example/authorization/" + childID.String()}
	}, now)
	lease = advanceDispatch(t, operationStore, lease, "authorizing", func(s *acmeworker.OperationState) { s.Phase = acmeworker.PhaseAuthorizing }, now)
	lease = advanceDispatch(t, operationStore, lease, "authorization_ready", func(s *acmeworker.OperationState) { s.Phase = acmeworker.PhaseReady }, now)
	lease = advanceDispatch(t, operationStore, lease, "finalize_intent", func(s *acmeworker.OperationState) { s.Phase = acmeworker.PhaseFinalizing }, now)
	certificate := issueDispatchCertificate(t, key, 2, now, 90*24*time.Hour, request.Domains)
	certificate.RequestDigest, certificate.CertificateKeyRef = lease.Digest, request.CertificateKeyRef
	certificate.CertificateURL = "https://ca.example/certificate/" + childID.String()
	child := parent
	child.request, child.lease, child.certificate, child.privateKey = request, lease, certificate, key
	if err := child.store.Save(ctx, lease, certificate); err != nil {
		return acmeworker.IssueResult{}, err
	}
	lease = advanceDispatch(t, operationStore, lease, "certificate_saved", func(s *acmeworker.OperationState) {
		s.Phase = acmeworker.PhaseCertificateSaved
		s.CertificateURL, s.CertificateSPKIDigest, s.LeafFingerprint = certificate.CertificateURL, certificate.PublicKeySPKISHA256, certificate.LeafFingerprint
	}, dispatchDatabaseNow(t, parent.pool))
	_ = advanceDispatch(t, operationStore, lease, "completed", func(s *acmeworker.OperationState) {
		s.Phase, s.Status = acmeworker.PhaseCompleted, acmeworker.OperationCompleted
	}, dispatchDatabaseNow(t, parent.pool))
	issuer.child = child
	return acmeworker.IssueResult{AccountURI: "https://ca.example/account/renewal", OrderURI: lease.State.OrderURL, Certificate: certificate}, nil
}

func auditActivateAndBindOriginal(t *testing.T, f dispatchFixture) (certificateasset.Actor, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	assets, actor := auditAssetStore(t, f)
	assetID, versionID, revision := auditIssuedAsset(t, f)
	actor.SessionID = uuid.New()
	digest := sha256.Sum256(actor.SessionID[:])
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,statement_timestamp()-interval '1 minute',statement_timestamp()+interval '1 hour')`,
		actor.SessionID, uuid.New(), actor.UserID, actor.ScopeID, digest[:]); err != nil {
		t.Fatal(err)
	}
	siteID := uuid.New()
	if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			VALUES($1,1,$2,$3,'example.test',ARRAY['origin.example.test:443'],ARRAY['origin.example.test'],$3,$3)`, siteID, actor.ScopeID, actor.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',443)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.Activate(t.Context(), actor, certificateasset.ActivateRequest{
		TenantScopeID: actor.ScopeID, AssetID: assetID, VersionID: versionID, ExpectedRevision: revision,
		IdempotencyKey: "audit-initial-activate", RequestID: "audit-initial-activate",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.Bind(t.Context(), actor, certificateasset.BindRequest{
		TenantScopeID: actor.ScopeID, SiteID: siteID, AssetID: assetID, VersionID: versionID, Default: true,
		IdempotencyKey: "audit-initial-bind", RequestID: "audit-initial-bind",
	}); err != nil {
		t.Fatal(err)
	}
	return actor, assetID, versionID, siteID
}

func TestAuditBoundIssuedCertificateEntersRenewalScheduler(t *testing.T) {
	f := newDispatchFixture(t, databasetest.MigratedPool(t, nil), dispatchFixtureOptions{
		finalizing: true, certificateLifetime: dueRenewalLifetime,
	})
	if err := f.store.Save(t.Context(), f.lease, f.certificate); err != nil {
		t.Fatal(err)
	}
	_, assetID, _, siteID := auditActivateAndBindOriginal(t, f)
	scheduled, err := dnsacme.NewStore(f.pool).ScheduleDueRenewal(t.Context(), 30*24*time.Hour, 10*time.Minute)
	var orderStatus, versionStatus string
	var autoRenew, renewalDue bool
	if err := f.pool.QueryRow(t.Context(), `SELECT status FROM certificate_orders WHERE id=$1 AND scope_id=$2`, f.request.CertificateOrderID, f.tenant.scopeID).Scan(&orderStatus); err != nil {
		t.Fatal(err)
	}
	assets, actor := auditAssetStore(t, f)
	asset, versions, getErr := assets.Get(t.Context(), actor, f.tenant.scopeID, assetID)
	if getErr != nil || len(versions) != 1 {
		t.Fatalf("read back certificate asset=%+v versions=%d error=%v", asset, len(versions), getErr)
	}
	autoRenew, versionStatus = asset.AutoRenew, versions[0].Status
	renewalDue = versions[0].RenewalDue
	if err != nil || !scheduled {
		t.Fatalf("BUG bound due certificate is not scheduled: order=%s version=%s auto_renew=%t renewal_due=%t site=%s scheduled=%t error=%v",
			orderStatus, versionStatus, autoRenew, renewalDue, siteID, scheduled, err)
	}
}

func TestAuditAutomaticRenewalKeepsWebsiteOnRenewedVersion(t *testing.T) {
	f := newDispatchFixture(t, databasetest.MigratedPool(t, nil), dispatchFixtureOptions{
		finalizing: true, certificateLifetime: dueRenewalLifetime,
	})
	if err := f.store.Save(t.Context(), f.lease, f.certificate); err != nil {
		t.Fatal(err)
	}
	activateDispatchFixture(t, f)
	actor, assetID, versionID, siteID := auditActivateAndBindOriginal(t, f)
	assets, _ := auditAssetStore(t, f)
	if scheduled, err := dnsacme.NewStore(f.pool).ScheduleDueRenewal(t.Context(), 30*24*time.Hour, 10*time.Minute); err != nil || !scheduled {
		t.Fatalf("schedule=%t error=%v", scheduled, err)
	}
	var childID uuid.UUID
	if err := f.pool.QueryRow(t.Context(), `SELECT id FROM certificate_orders WHERE scope_id=$1 AND renewal_of_order_id=$2`, actor.ScopeID, f.request.CertificateOrderID).Scan(&childID); err != nil {
		t.Fatal(err)
	}
	keys, err := acmeruntime.NewKeyStore(f.pool, "audit-runtime-kek", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	issuer := &auditPersistingIssuer{t: t, parent: f, keys: keys}
	dispatcher, err := acmeruntime.NewDispatcher(f.pool, issuer, keys,
		acmeruntime.DefaultConfig("https://ca.example/directory", []string{"mailto:ops@example.test"}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := dispatcher.DispatchOne(t.Context())
	if err != nil || result.Outcome != acmeruntime.OutcomeCompleted || result.OrderID != childID {
		t.Fatalf("scheduled child did not complete: result=%+v error=%v", result, err)
	}
	t.Logf("CONTROL scheduler child reached dispatch outcome=%s attempts=%d", result.Outcome, result.Attempt)
	// No manual activation (fix-dnscert3 卡 2-B): the renewal is a new version
	// of the bound certificate, waiting for the system delivery
	// (certificatepublish.RenewalDeliverer, renewal_delivery_integration_test.go)
	// to reach the nodes before the site switches; until then the site keeps
	// the original version.
	newAssetID, newVersionID, _ := auditIssuedAsset(t, issuer.child)
	_, versions, err := assets.Get(t.Context(), actor, actor.ScopeID, assetID)
	if err != nil {
		t.Fatal(err)
	}
	var renewedStatus string
	for _, version := range versions {
		if version.ID == newVersionID {
			renewedStatus = version.Status
		}
	}
	var currentAsset, currentVersion uuid.UUID
	if err := f.pool.QueryRow(t.Context(), `SELECT asset_id,version_id FROM certificate_site_binding_facts
		WHERE tenant_scope_id=$1 AND site_id=$2 ORDER BY sequence DESC LIMIT 1`, actor.ScopeID, siteID).
		Scan(&currentAsset, &currentVersion); err != nil {
		t.Fatal(err)
	}
	var due bool
	if err := f.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM certificate_orders cert_order
		WHERE cert_order.scope_id=$1 AND cert_order.id=$2 AND cert_order.status='issued'
		  AND cert_order.renewal_of_order_id IS NOT NULL AND cert_order.issued_asset_id=$3
		  AND NOT EXISTS (SELECT 1 FROM certificate_renewal_deliveries delivery
		    WHERE delivery.scope_id=cert_order.scope_id AND delivery.order_id=cert_order.id))`,
		actor.ScopeID, childID, assetID).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if newAssetID != assetID || renewedStatus != certificateasset.StatusPendingActivation ||
		currentAsset != assetID || currentVersion != versionID || !due {
		t.Fatalf("BUG renewal not handed to system delivery: original_asset=%s renewed_asset=%s renewed_status=%s current_asset=%s current_version=%s original_version=%s delivery_due=%t",
			assetID, newAssetID, renewedStatus, currentAsset, currentVersion, versionID, due)
	}
}
