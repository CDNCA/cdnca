package main

// PA-18 part of the control-api half (PLUGIN_E2E_MARKET=1): the developer rule pack bought on the
// plugin market. The controller administrator confirms its installation authorization; the production
// artifact catalog consumer (artifactsync client + store + syncer against the license process) downloads
// the market_rule_pack/<plugin> entry and materializes it as a developer-layer local pack; the platform
// administrator enables it and a tenant site publishes its security.mounts.
//
// Node enforcement is not asserted: rule packs reach nodes through the site object security.mounts
// (ADR 0009 §8.4, g8c / dynamic routing D1), which does not read site_security_mounts yet. The run
// stops at the published control-plane mount.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	rulePackPluginID = "com.example.dev.sqli-extra"
	rulePackID       = "dev/com.example.dev/sqli-extra"
)

func runMarketRulePackFlow(t *testing.T, fixture licenseFixture, client, platformClient controlClient,
	pool *pgxpool.Pool, trust *entitlementguard.TrustStore) {
	t.Helper()
	ctx := t.Context()
	market, ok := fixture.Plugins[rulePackPluginID]
	if !ok {
		t.Fatal("license fixture has no market rule pack")
	}
	// 1. Installation: a rule pack is an instance-wide resource (signed resource_scope=platform). The tenant
	// neither sees nor confirms it; the controller's platform administrator does (报告 A).
	if client.list().find(market.AuthorizationID) != nil {
		t.Fatal("tenant scope offered the platform rule pack")
	}
	client = platformClient
	item := client.list().find(market.AuthorizationID)
	if item == nil || item.Status != "pending_confirmation" || item.Version != "1.0.0" {
		t.Fatalf("market rule pack not offered: %+v", item)
	}
	installed := client.mutate(item.AuthorizationID, "confirm", item.Revision, map[string]any{
		"verification_id": item.VerificationID, "approved_scopes": item.ApprovedScopes,
		"sensitive_permissions_confirmed": true, "new_permissions_confirmed": true}, http.StatusOK)
	if installed.Status != "enabled" {
		t.Fatalf("market rule pack install=%+v", installed)
	}

	// 2. Production artifact catalog consumer against the license process.
	roots := x509.NewCertPool()
	caPEM, err := os.ReadFile(fixture.BootstrapServerCA)
	if err != nil || !roots.AppendCertsFromPEM(caPEM) {
		t.Fatalf("license business CA: %v", err)
	}
	httpClient := &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	catalogClient, err := artifactsync.NewClient(fixture.BusinessURL, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := entitlementsync.LoadPrivateKey(fixture.InstallationKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	store := artifactsync.NewStore(pool, time.Now).WithFeatures(entitlementguard.NewGuard(pool, time.Now, trust))
	syncer, err := artifactsync.NewSyncer(artifactsync.SyncerConfig{Client: catalogClient, Store: store, Trust: trust,
		InstallationID: fixture.InstallationID, PrivateKey: privateKey, ControlVersion: "1.0.35",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("artifact catalog sync: %v", err)
	}
	local, err := store.Current(ctx, "market_rule_pack/"+rulePackPluginID)
	if err != nil || local == nil || local.Version != "1.0.0" {
		t.Fatalf("market rule pack not downloaded: %+v %v", local, err)
	}
	var layer, source string
	if err := pool.QueryRow(ctx, `SELECT pack.layer,artifact.source FROM rule_packs pack
		JOIN rule_pack_artifacts artifact ON artifact.pack_id=pack.pack_id AND artifact.version=pack.current_version
		WHERE pack.pack_id=$1`, rulePackID).Scan(&layer, &source); err != nil || layer != "developer" || source != "market" {
		t.Fatalf("materialized market pack layer=%s source=%s err=%v", layer, source, err)
	}

	// 3. Platform enables the developer pack; a tenant site publishes it in security.mounts.
	platform, tenant, siteID := rulePackE2EScopes(t, pool, client.tenantID)
	packs := rulepackcontrol.NewService(pool, time.Now)
	if _, _, err := packs.PutOverride(ctx, platform, rulepackcontrol.OverrideInput{Level: rulepack.LevelPlatform,
		PackID: rulePackID, State: rulepack.StateEnabled}); err != nil {
		t.Fatalf("enable market pack at platform level: %v", err)
	}
	mounted, err := packs.PublishSite(ctx, tenant, siteID)
	if err != nil {
		t.Fatalf("publish site mounts: %v", err)
	}
	if mounted.Published == nil || len(mounted.Published.Security.Mounts) != 1 {
		t.Fatalf("site mounts=%+v", mounted.Published)
	}
	mount := mounted.Published.Security.Mounts[0]
	if mount.PackID != rulePackID || mount.Layer != rulepack.LayerDeveloper || mount.SHA256 != local.SHA256 {
		t.Fatalf("site mount=%+v local=%+v", mount, local)
	}
	t.Logf("market rule pack %s mounted on site %s (resolved %s); node enforcement waits for the site object "+
		"security.mounts producer", rulePackID, siteID, mounted.Published.Security.ResolvedSHA256)
}

// rulePackE2EScopes adds a platform administrator and a site of the e2e tenant.
func rulePackE2EScopes(t *testing.T, pool *pgxpool.Pool, tenantScope uuid.UUID) (rulepackcontrol.Actor,
	rulepackcontrol.Actor, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	platformScope, platformUser, siteID := uuid.New(), uuid.New(), uuid.New()
	var tenantUser uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT user_id FROM memberships WHERE scope_id=$1 LIMIT 1`, tenantScope).Scan(&tenantUser); err != nil {
		t.Fatal(err)
	}
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO access_scopes(id,kind,tenant_id) SELECT $1,'platform',NULL
				WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL)`, []any{platformScope}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'rule-pack-platform','平台管理员','unused')`,
				[]any{platformUser}},
			{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,
				display_id) VALUES($1,$2,$3,'rulepack-e2e.example.test',ARRAY['origin.example.test:80'],
				ARRAY['origin.example.test'],$3,$3,9001)`, []any{siteID, tenantScope, tenantUser}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{siteID}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, []any{siteID}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platformScope)
	})
	if err != nil {
		t.Fatalf("rule pack e2e scopes: %v", err)
	}
	return rulepackcontrol.Actor{UserID: platformUser, ScopeID: platformScope, ScopeKind: "platform"},
		rulepackcontrol.Actor{UserID: tenantUser, ScopeID: tenantScope, ScopeKind: "tenant"}, siteID
}
