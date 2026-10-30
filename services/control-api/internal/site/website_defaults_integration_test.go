//go:build integration

package site

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
)

// 系统设置 > 网站默认 > 负载方式 and > HTTPS > HSTS were stored
// and never read. A new site without an origin pool takes the load
// balancing; a new HTTPS site gets HSTS (one year, no includeSubDomains or
// preload); a request naming its own pool keeps it.
func TestNewSiteInheritsWebsiteDefaults(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	service, err := systemconfig.NewServiceWithDependencies(f.pool, audit.New(f.pool), func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	manager, err := systemconfig.NewCategoryManager(service, nil)
	if err != nil {
		t.Fatal(err)
	}
	actor := systemconfig.Actor{UserID: f.admin.userID, ScopeID: f.admin.scopeID, ScopeKind: "platform"}
	configuration := systemconfig.ProjectBootstrapConfiguration()
	configuration.Defaults.Website.Other.LoadBalancing = "least_conn"
	configuration.Defaults.Website.HTTPS.HSTSEnabled = true
	draft, err := service.CreateDraft(ctx, actor, systemconfig.CreateDraftRequest{Configuration: configuration,
		IdempotencyKey: "ge-access-draft", RequestID: "ge-access-draft"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.PreflightRevision(ctx, actor, systemconfig.PreflightRevisionRequest{Revision: draft.Revision,
		SnapshotSHA256: draft.SnapshotSHA256, IdempotencyKey: "ge-access-preflight", RequestID: "ge-access-preflight"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Activate(ctx, actor, systemconfig.ActivateRequest{Revision: draft.Revision,
		IdempotencyKey: "ge-access-activate", RequestID: "ge-access-activate"}); err != nil {
		t.Fatal(err)
	}

	created, err := f.createSite(f.a, f.a, "defaults.example.test")
	if err != nil {
		t.Fatal(err)
	}
	var balance string
	if err := f.pool.QueryRow(ctx, `SELECT balance_method FROM site_origin_pools WHERE site_id=$1`, created.Site.ID).Scan(&balance); err != nil ||
		balance != "least_conn" {
		t.Fatalf("new site load balancing = %q %v, want least_conn", balance, err)
	}
	var rows int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM site_access_settings WHERE site_id=$1`, created.Site.ID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("plain HTTP site got access settings: %d %v", rows, err)
	}

	key := f.key("https-site")
	https, err := f.sites.Create(ctx, f.a.siteActor(), CreateRequest{
		TargetScopeID: f.a.scopeID, OwnerUserID: f.a.userID, IdempotencyKey: key, RequestID: key,
		Fields: SiteFields{Domains: []string{"secure-defaults.example.test"}, HTTPPorts: []string{"80"}, HTTPSPorts: []string{"443"},
			HTTPSEnabled: true, Origins: []string{"192.0.2.1"}, Enabled: true, Status: StatusActive},
		OriginPool: &OriginPool{Origins: []Origin{{Host: "192.0.2.1", Port: 80, Weight: 1, Enabled: true}},
			BalanceMethod: BalanceIPHash, FailoverTries: 1, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT balance_method FROM site_origin_pools WHERE site_id=$1`, https.Site.ID).Scan(&balance); err != nil ||
		balance != BalanceIPHash {
		t.Fatalf("named pool load balancing = %q %v, want ip_hash", balance, err)
	}
	var raw []byte
	if err := f.pool.QueryRow(ctx, `SELECT settings FROM site_access_settings WHERE site_id=$1`, https.Site.ID).Scan(&raw); err != nil {
		t.Fatalf("HTTPS site HSTS default: %v", err)
	}
	var settings struct {
		HSTS struct {
			MaxAge     int64 `json:"max_age_seconds"`
			Subdomains bool  `json:"include_subdomains"`
			Preload    bool  `json:"preload"`
		} `json:"hsts"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil || settings.HSTS.MaxAge != systemconfig.DefaultHSTSMaxAgeSeconds ||
		settings.HSTS.Subdomains || settings.HSTS.Preload {
		t.Fatalf("HSTS default = %s %v", raw, err)
	}
}
