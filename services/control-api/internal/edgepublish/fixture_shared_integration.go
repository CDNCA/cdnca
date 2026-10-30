//go:build integration

package edgepublish

// Publication fixture facts shared by the package's integration tests and
// the cross-process e2e harnesses (E2EPublisherForTest): tenant and platform
// identities, a sold package, an installed entitlement, a test signer and
// node rows. Integration builds only; not part of the service.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var publishTestClock = time.Now().UTC().Truncate(time.Minute)

type testSigner struct {
	id      string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	calls   atomic.Int64
	fail    atomic.Bool
}

func newTestSigner(t *testing.T, id string) *testSigner {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{id: id, public: publicKey, private: privateKey}
}

func (signer *testSigner) KeyID() string { return signer.id }

func (signer *testSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), signer.public...)
}

func (signer *testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	signer.calls.Add(1)
	if signer.fail.Load() {
		return nil, errors.New("forced signing failure")
	}
	return ed25519.Sign(signer.private, payload), nil
}

type testEntitlementAuthorizer struct {
	decision EntitlementDecision
	err      error
	calls    atomic.Int64
}

func (authorizer *testEntitlementAuthorizer) AuthorizePublication(
	_ context.Context,
	_ pgx.Tx,
	_ EntitlementRequest,
) (EntitlementDecision, error) {
	authorizer.calls.Add(1)
	return authorizer.decision, authorizer.err
}

type fixtureWriteAuthorizer struct{}

func (fixtureWriteAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) error {
	return authorizeActor(ctx, tx, actor, targetScopeID, permission)
}

func installPublishEntitlement(t *testing.T, pool *pgxpool.Pool) *entitlementguard.TrustStore {
	t.Helper()
	const (
		customerID     = "11111111-1111-4111-8111-111111111111"
		installationID = "22222222-2222-4222-8222-222222222222"
		licenseID      = "33333333-3333-4333-8333-333333333333"
	)
	signer := newTestSigner(t, "edge-publish-entitlement-key")
	// Migration 084 checks the revocation LKG against the database's physical
	// clock (issued_at-2s <= now < issued_at+15m). publishTestClock is frozen at
	// package start, so a long package run would seed an expired revocation
	// (P8408); anchor the entitlement facts to the database clock instead.
	var entitlementNow time.Time
	if err := pool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&entitlementNow); err != nil {
		t.Fatal(err)
	}
	entitlementNow = entitlementNow.UTC().Truncate(time.Second)
	verifyUntil := entitlementNow.Add(24 * time.Hour)
	keyNotBefore := entitlementNow.Add(-time.Hour)
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: signer.id, PublicKey: signer.public, NotBefore: keyNotBefore,
		SignUntil: &verifyUntil, VerifyUntil: &verifyUntil,
	}})
	if err != nil {
		t.Fatal(err)
	}
	keyFingerprint := sha256.Sum256(signer.public)
	keysetPayload := []byte(fmt.Sprintf(
		`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[`+
			`{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,`+
			`"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		signer.id, signer.id, base64.RawURLEncoding.EncodeToString(signer.public),
		base64.RawURLEncoding.EncodeToString(keyFingerprint[:]), keyNotBefore.Format(time.RFC3339Nano),
		verifyUntil.Format(time.RFC3339Nano), verifyUntil.Format(time.RFC3339Nano)))
	keysetDigest := sha256.Sum256(keysetPayload)
	if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_lkg(
		singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at
	) VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
		`"`+base64.RawURLEncoding.EncodeToString(keysetDigest[:])+`"`, signer.id,
		keysetPayload, keysetDigest[:], entitlementNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at
	) VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, signer.id, signer.public, keyNotBefore,
		verifyUntil, keysetDigest[:], entitlementNow); err != nil {
		t.Fatal(err)
	}
	issuedAt := entitlementNow.Add(-time.Minute)
	revocation, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: customerID, InstallationID: installationID,
		LicenseID: licenseID, Revision: 1, IssuedAt: issuedAt.Unix(),
		ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(), RevokedSerials: []uint64{},
	}, signer, entitlement.RevocationKeyWindow{
		NotBefore: keyNotBefore, SignUntil: &verifyUntil, VerifyUntil: &verifyUntil,
	})
	if err != nil {
		t.Fatal(err)
	}
	revocationArtifact, err := revocation.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewRevocationService(pool, trust).Accept(
		t.Context(), revocationArtifact, entitlementNow,
	); err != nil {
		t.Fatal(err)
	}
	lease := entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		CustomerID: customerID, InstallationID: installationID, LicenseID: licenseID, Serial: 1,
		NotBefore: entitlementNow.Add(-time.Hour).Unix(), ExpiresAt: entitlementNow.Add(time.Hour).Unix(), GraceUntil: entitlementNow.Add(2 * time.Hour).Unix(),
		Version:  entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features: []entitlement.Feature{{Code: entitlementguard.FeatureSitesManage}},
		Quotas:   []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: 100}},
	}
	signed, err := entitlement.Sign(context.Background(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(context.Background(), entitlementguard.InstallBundle{
		InstallationID: lease.InstallationID, SignedLease: signed,
	}, entitlementNow); err != nil {
		t.Fatal(err)
	}
	return trust
}

func seedPublishPackage(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantScopeID, tenantUserID, platformScopeID, platformUserID uuid.UUID,
) uuid.UUID {
	t.Helper()
	productID, subscriptionID := uuid.New(), uuid.New()
	// Catalog products always carry explicit limits; an absent stream_ports
	// counts as 0 at runtime and would refuse every stream.
	const spec = `{"limits":{"stream_ports":-1,"http_ports":-1,"root_domains":-1}}`
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_products(
			id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,'Edge publish L4 product',true,1,$4::jsonb,1,$2,$2,$3,$3)`,
			productID, platformUserID, publishTestClock, spec); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_product_versions(
			product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at)
			VALUES($1,1,'Edge publish L4 product',true,1,$4::jsonb,false,$2,$3)`,
			productID, platformUserID, publishTestClock, spec); err != nil {
			return err
		}
		if err := insertPublishCatalogAudit(t.Context(), tx, platformScopeID, platformUserID,
			productID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_subscriptions(
			id,tenant_scope_id,product_id,product_revision,product_snapshot,
			site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,
			custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,lifecycle_status,revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,1,jsonb_build_object('id',$7::text,'revision',1,'name','Edge publish L4 product','spec',$8::jsonb),
			10,10,10,-1,$4,$5,'UTC','monthly',0,1,1,'active',1,$6,$6,$4,$4)`,
			// The window outlives every request deadline (publishTestClock+1h),
			// so tests that move the clock to a deadline still see it active.
			subscriptionID, tenantScopeID, productID, publishTestClock.Add(-time.Hour),
			publishTestClock.Add(24*time.Hour), tenantUserID, productID.String(), spec); err != nil {
			return err
		}
		// Every opening path writes the active entitlement revision that
		// packageaddon.LockRuntimeLimits requires.
		_, err := tx.Exec(t.Context(), `INSERT INTO package_subscription_entitlement_versions(
			subscription_id,revision,supersedes_subscription_id,supersedes_revision,
			tenant_scope_id,effective_at,effective_until,product_id,product_revision,product_snapshot,
			site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,custom_cycle_days,
			tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,
			entitlement_status,source_order_id,operation,created_by_user_id,created_at)
			SELECT subscription.id,1,NULL,NULL,subscription.tenant_scope_id,subscription.starts_at,NULL,
			subscription.product_id,subscription.product_revision,subscription.product_snapshot,
			subscription.site_limit,subscription.domain_limit,subscription.node_limit,subscription.traffic_limit_bytes,
			subscription.timezone,subscription.cycle_kind,subscription.custom_cycle_days,
			subscription.tcp_factor_numerator,subscription.tcp_factor_denominator,NULL,NULL,'CNY',
			'active',NULL,'manual_open',$2,$3
			FROM package_subscriptions subscription WHERE subscription.id=$1`,
			subscriptionID, tenantUserID, publishTestClock)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return subscriptionID
}

func insertPublishCatalogAudit(
	ctx context.Context,
	tx pgx.Tx,
	platformScopeID, platformUserID, productID uuid.UUID,
) error {
	_, err := tx.Exec(ctx, `WITH previous AS (
		SELECT stream_position,event_hash FROM audit_events WHERE scope_id=$2
		ORDER BY stream_position DESC LIMIT 1
	)
	INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at)
	SELECT $1,$2,COALESCE(previous.stream_position,0)+1,$3,'package.product.create','package_product',$4,
		$5,'success','{"revision":1,"enabled":true}'::jsonb,previous.event_hash,$6,$7
	FROM (SELECT true) seed LEFT JOIN previous ON true`, uuid.New(), platformScopeID, platformUserID,
		productID.String(), "edge-publish-catalog-"+uuid.NewString(), make([]byte, sha256.Size), publishTestClock)
	return err
}

func validTestEntitlementDecision() EntitlementDecision {
	return EntitlementDecision{
		Allowed: true, LocallyVerified: true, Status: EntitlementStatusValid,
		LeaseSerial: 1, EvaluatedAt: publishTestClock,
	}
}

func seedPublishIdentity(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	tenantRoleID := uuid.New()
	platformScopeID, platformUserID, platformRoleID := uuid.New(), uuid.New(), uuid.New()
	username := "publish-" + strings.ReplaceAll(userID.String(), "-", "")[:20]
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `INSERT INTO tenants (id,display_name) VALUES ($1,'Edge publish tenant')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO access_scopes (id,kind,tenant_id) VALUES ($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO users (id,username,display_name,password_hash) VALUES ($1,$2,'Edge publish user','not-used')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO memberships (scope_id,user_id) VALUES ($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO roles (id,scope_id,name,description,system_role)
		VALUES ($1,$2,'tenant_owner','Edge publication cache test manager',true)`, tenantRoleID, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO role_permissions (role_id,permission_name) VALUES($1,'sites.manage')
		ON CONFLICT DO NOTHING`, tenantRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO role_assignments (scope_id,user_id,role_id) VALUES ($1,$2,$3)`, scopeID, userID, tenantRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO access_scopes (id,kind) VALUES ($1,'platform')`, platformScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id,username,display_name,password_hash)
		VALUES ($1,$2,'Edge publish platform owner','not-used')`, platformUserID,
		"publish-platform-"+strings.ReplaceAll(platformUserID.String(), "-", "")[:12]); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO memberships (scope_id,user_id) VALUES ($1,$2)`, platformScopeID, platformUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO roles (id,scope_id,name,description,system_role)
		VALUES ($1,$2,'platform_owner','Edge publication test owner',true)`, platformRoleID, platformScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO role_permissions (role_id,permission_name)
		SELECT $1,name FROM permissions
		WHERE name IN ('edge_publications.read','edge_publications.manage')`, platformRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO role_assignments (scope_id,user_id,role_id) VALUES ($1,$2,$3)`,
		platformScopeID, platformUserID, platformRoleID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return tenantID, scopeID, userID, platformScopeID, platformUserID
}

// publishNodeCreatedAt is when fixture nodes are created.
var publishNodeCreatedAt = publishTestClock.Add(-20 * time.Minute)

// insertPublishNode inserts an active node with a display ID drawn from the
// scope's node display sequence, as the node store does.
func insertPublishNode(t *testing.T, pool *pgxpool.Pool, scopeID, userID, nodeID uuid.UUID, name string) {
	t.Helper()
	createdAt := publishNodeCreatedAt
	if _, err := pool.Exec(context.Background(), `
		WITH allocated AS (
			INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at)
			VALUES($2,2,$5)
			ON CONFLICT(scope_id) DO UPDATE SET
				next_value=node_display_id_sequences.next_value+1,
				updated_at=EXCLUDED.updated_at
			RETURNING next_value-1 AS display_id
		)
		INSERT INTO nodes (id,display_id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at)
		SELECT $1,allocated.display_id,$2,$3,'active',$4,$5,$5 FROM allocated`, nodeID, scopeID,
		name, userID, createdAt); err != nil {
		t.Fatal(err)
	}
}
