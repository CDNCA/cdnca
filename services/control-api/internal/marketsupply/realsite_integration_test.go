package marketsupply

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/marketmanaged"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestHandleCommitsRealSite drives the real site.Service, so CNAME intents,
// permission checks, the entitlement guard and package quotas all apply.
// It installs a control entitlement, which is a singleton: run it against a
// fresh database (for example a clone of a migrated template database).
func TestHandleCommitsRealSite(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	var installed bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control_installation_entitlement)`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if installed {
		t.Skip("control entitlement already installed in this schema; needs a fresh database")
	}
	platform := platformScope(t, pool)
	now := time.Now().UTC()
	trust := installSiteEntitlement(t, pool, now)
	sites := site.NewService(site.NewStoreWithClock(pool, time.Now, trust))
	svc := newTestService(t, pool, time.Now)
	svc.cfg.CNAMEDomain = "cdn.leaf.example.net"
	svc.WithSites(sites, nil)
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	poolID := insertLineGroup(t, pool, platform, actor.userID)
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: poolID.String(),
		Limits:         spec.LimitSet{{Metric: spec.MetricDomains, Cap: 2, Action: spec.ActionRejectNew}},
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		Allocation: spec.Allocation{HTTPPorts: 2},
		IssuedAt:   now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	if out := mustSync(t, svc, g); out[0].Action != "opened" {
		t.Fatalf("sync = %+v", out[0])
	}
	cfg := siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.market-leaf.example.com"},
		HTTPPorts: []int{80}, Origins: []siteconf.Origin{{Host: "203.0.113.30", Port: 8080}}}
	call := func(op string, body any) siteconf.Reply {
		t.Helper()
		raw, _ := json.Marshal(body)
		reply, err := svc.Handle(ctx, envelope.Header{MessageID: uuid.New(), GrantID: g.GrantID, Operation: op,
			Domains: cfg.Domains}, raw)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return reply
	}
	siteID := uuid.New()
	prep := call(siteconf.OpPrepare, siteconf.CommitRequest{SiteID: siteID, Revision: 1, Config: cfg})
	if !prep.OK {
		t.Fatalf("prepare = %+v", prep)
	}
	commit := call(siteconf.OpCommit, siteconf.CommitRequest{SiteID: siteID, Revision: 1, Digest: prep.Digest, Config: cfg})
	if !commit.OK || commit.LeafSiteID == nil {
		t.Fatalf("commit = %+v", commit)
	}
	var scope, owner uuid.UUID
	var subscription, nodeGroup *uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT scope_id, owner_user_id, package_subscription_id, node_group_id
		FROM sites WHERE id=$1 AND deleted_at IS NULL`, *commit.LeafSiteID).Scan(&scope, &owner, &subscription, &nodeGroup); err != nil {
		t.Fatal(err)
	}
	var subScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_scope_id FROM package_subscriptions WHERE id=$1`, subscription).Scan(&subScope); err != nil ||
		subScope != scope || nodeGroup == nil || *nodeGroup != poolID {
		t.Fatalf("site scope=%s sub=%v subScope=%s node_group=%v err=%v", scope, subscription, subScope, nodeGroup, err)
	}
	// Retrying the same commit must not create a second site.
	if again := call(siteconf.OpCommit, siteconf.CommitRequest{SiteID: siteID, Revision: 1, Digest: prep.Digest, Config: cfg}); !again.OK || *again.LeafSiteID != *commit.LeafSiteID {
		t.Fatalf("retried commit = %+v", again)
	}
	refuseLocalStop(t, pool, sites, svc, platform, *commit.LeafSiteID, owner, cfg)
	if r := call(siteconf.OpDelete, siteconf.SiteRef{SiteID: siteID, LeafSiteID: *commit.LeafSiteID}); !r.OK {
		t.Fatalf("delete = %+v", r)
	}
}

type testSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (s testSigner) KeyID() string { return s.id }
func (s testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(s.private, payload), nil
}

// installSiteEntitlement mirrors the site package's addon fixture.
func installSiteEntitlement(t *testing.T, pool *pgxpool.Pool, now time.Time) *entitlementguard.TrustStore {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	until := now.Add(24 * time.Hour)
	signer := testSigner{id: "market-supply-test-key", private: private}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: signer.id, PublicKey: public,
		NotBefore: now.Add(-24 * time.Hour), SignUntil: &until, VerifyUntil: &until}})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(public)
	payload := []byte(fmt.Sprintf(
		`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[`+
			`{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,`+
			`"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		signer.id, signer.id, base64.RawURLEncoding.EncodeToString(public),
		base64.RawURLEncoding.EncodeToString(fingerprint[:]), now.Add(-24*time.Hour).Format(time.RFC3339Nano),
		until.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano)))
	digest := sha256.Sum256(payload)
	exec(t, pool, `INSERT INTO entitlement_signing_keyset_lkg(
		singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at
	) VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
		`"`+base64.RawURLEncoding.EncodeToString(digest[:])+`"`, signer.id, payload, digest[:], now)
	exec(t, pool, `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at
	) VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, signer.id, public, now.Add(-24*time.Hour), until, digest[:], now)
	const customer = "11111111-1111-4111-8111-111111111111"
	const installation = "22222222-2222-4222-8222-222222222222"
	const license = "33333333-3333-4333-8333-333333333333"
	issuedAt := now.Add(-time.Minute)
	revocation, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience, CustomerID: customer,
		InstallationID: installation, LicenseID: license, Revision: 1, IssuedAt: issuedAt.Unix(),
		ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(), RevokedSerials: []uint64{},
	}, signer, entitlement.RevocationKeyWindow{NotBefore: now.Add(-time.Hour), SignUntil: &until, VerifyUntil: &until})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := revocation.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewRevocationService(pool, trust).Accept(t.Context(), artifact, now); err != nil {
		t.Fatal(err)
	}
	lease := entitlement.Lease{Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience, CustomerID: customer,
		InstallationID: installation, LicenseID: license, Serial: 1, NotBefore: now.Add(-time.Hour).Unix(),
		ExpiresAt: now.Add(12 * time.Hour).Unix(), GraceUntil: now.Add(13 * time.Hour).Unix(),
		Version:  entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features: []entitlement.Feature{{Code: entitlementguard.FeatureSitesManage}},
		Quotas:   []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: 100}}}
	signed, err := entitlement.Sign(t.Context(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(t.Context(),
		entitlementguard.InstallBundle{InstallationID: installation, SignedLease: signed}, now); err != nil {
		t.Fatal(err)
	}
	return trust
}

// refuseLocalStop: ML-18 (ADR 0012 §18.4, U3). The leaf's own administrator
// cannot disable or delete a market subscriber's site or account; the
// market service account (relay supply.delete_site) still can.
func refuseLocalStop(t *testing.T, pool *pgxpool.Pool, sites *site.Service, svc *Service, platform, siteID, owner uuid.UUID,
	cfg siteconf.Config) {
	t.Helper()
	ctx := t.Context()
	admin, role := uuid.New(), uuid.New()
	exec(t, pool, `INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
		VALUES($1,$2,'ML18','unused',now(),now())`, admin, "ml18-"+admin.String()[:12])
	exec(t, pool, `INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,now())`, platform, admin)
	exec(t, pool, `INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES($1,$2,$3,'ML18',true,now())`,
		role, platform, "ml18-"+role.String()[:12])
	exec(t, pool, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'platform.admin')`, role)
	exec(t, pool, `INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,now())`, platform, admin, role)
	actor := site.Actor{UserID: admin, ScopeID: platform, ScopeKind: "platform"}
	current, err := sites.Get(ctx, actor, siteID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sites.Delete(ctx, actor, site.DeleteRequest{ID: siteID, ExpectedRevision: current.Revision,
		IdempotencyKey: "ml18-del", RequestID: "ml18-del"}); !errors.Is(err, marketmanaged.ErrManaged) {
		t.Fatalf("local delete of a market site: %v", err)
	}
	for _, action := range []string{site.BatchActionDisable, site.BatchActionDelete} {
		out, err := sites.BatchAction(ctx, actor, site.BatchActionRequest{Action: action,
			Items:          []site.BatchActionItem{{ID: siteID, ExpectedRevision: current.Revision}},
			IdempotencyKey: "ml18-batch-" + action, RequestID: "ml18-batch"})
		if err != nil || len(out.Items) != 1 || out.Items[0].Error == nil || out.Items[0].Error.Code != "market_managed" {
			t.Fatalf("local batch %s: %+v %v", action, out, err)
		}
	}
	fields, _ := siteFields(cfg, false)
	fields.PackageSubscriptionID, fields.NodeGroupID = current.PackageSubscriptionID, current.NodeGroupID
	if err := pool.QueryRow(ctx, `SELECT name FROM node_line_groups WHERE id=$1`, *current.NodeGroupID).Scan(&fields.NodeGroupName); err != nil {
		t.Fatal(err)
	}
	fields.Enabled = false
	if _, err := sites.Update(ctx, actor, site.UpdateRequest{ID: siteID, ExpectedRevision: current.Revision, Fields: fields,
		IdempotencyKey: "ml18-off", RequestID: "ml18-off"}); !errors.Is(err, marketmanaged.ErrManaged) {
		t.Fatalf("local disable of a market site: %v", err)
	}
	if after, err := sites.Get(ctx, actor, siteID); err != nil || !after.Enabled || after.Revision != current.Revision {
		t.Fatalf("site untouched: %+v %v", after, err)
	}
	users := svc.identity
	idActor := identity.Actor{UserID: admin, ScopeID: platform, ScopeKind: "platform"}
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT revision FROM users WHERE id=$1`, owner).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if err := users.DeleteUser(ctx, idActor, identity.DeleteUserInput{ID: owner, ExpectedRevision: revision,
		IdempotencyKey: "ml18-user-del", RequestID: "ml18-user-del"}); !errors.Is(err, marketmanaged.ErrManaged) {
		t.Fatalf("local delete of the market tenant owner: %v", err)
	}
	if err := marketmanaged.GuardUser(ctx, pool, admin, owner); !errors.Is(err, marketmanaged.ErrManaged) {
		t.Fatalf("user disable guard: %v", err)
	}
	service, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := marketmanaged.GuardScope(ctx, pool, service.userID, current.ScopeID); err != nil {
		t.Fatalf("the market service account may stop it: %v", err)
	}
}
