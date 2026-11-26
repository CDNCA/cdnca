//go:build integration

package dnsproviderremotesource

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcilehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type reconcileZoneSessions map[string]dnsreconcilehttp.Principal

func (sessions reconcileZoneSessions) AuthenticateSession(_ context.Context, raw string) (dnsreconcilehttp.Principal, error) {
	principal, ok := sessions[raw]
	if !ok {
		return dnsreconcilehttp.Principal{}, dnsreconcilehttp.ErrUnauthenticated
	}
	return principal, nil
}

// reconcileZoneIAM grants every route of the principal's own tenant: the
// resolver itself must keep another tenant's site out.
type reconcileZoneIAM struct{}

func (reconcileZoneIAM) Authorize(_ context.Context, request dnsreconcilehttp.AuthorizationRequest) error {
	if request.TenantID != request.Principal.TenantID {
		return dnsreconcilehttp.ErrPermissionDenied
	}
	return nil
}

type reconcileZoneNoWorkloads struct{}

func (reconcileZoneNoWorkloads) Authenticate(*http.Request) (dnsreconcilehttp.WorkloadPrincipal, error) {
	return dnsreconcilehttp.WorkloadPrincipal{}, dnsreconcilehttp.ErrWorkloadUnauthenticated
}

type reconcileZoneAllow struct{}

func (reconcileZoneAllow) AuthorizeDNSReconcile(context.Context, dnsreconcile.EntitlementRequest) error {
	return nil
}
func (reconcileZoneAllow) ResolveChecker(context.Context, uuid.UUID, uuid.UUID) (*dnscheck.Checker, error) {
	return nil, dnsreconcile.ErrUnavailable
}
func (reconcileZoneAllow) ResolveProvider(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (dnscheck.ProviderAdapter, error) {
	return nil, dnsreconcile.ErrUnavailable
}

// ownerLister answers the provider records of an owner name.
type ownerLister struct {
	records map[string][]dnsproviderremote.ZoneRecord
	calls   []dnsproviderremote.ProviderConfig
}

func (lister *ownerLister) ListZoneRecords(_ context.Context, config dnsproviderremote.ProviderConfig,
	owner string) ([]dnsproviderremote.ZoneRecord, error) {
	lister.calls = append(lister.calls, config)
	return lister.records[owner], nil
}

// TestDNSReconcileDryRunResolvesOwnAccountZone covers
// a site whose own verified
// account hosts the domain (DNS 域名 lists it, no dns_zones row yet) gets a
// dry-run without naming a zone — the longest listed domain covering the name
// is bound once and the plan is built on its current records. A name that is
// not the site's, another tenant's site, the platform copy and an unlisted
// domain are refused; an apply on an older zone revision is 412 before
// anything is stored.
func TestDNSReconcileDryRunResolvesOwnAccountZone(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	cipher := mustSourceCipher(t, "reconcile-zone-key", 63)
	tenantA, tenantB := seedSourceTenant(t, pool, "rzone-a"), seedSourceTenant(t, pool, "rzone-b")
	grantSourceTenantPermissions(t, pool, tenantA, "dns.read", "dns.manage")
	account := insertSourceProvider(t, pool, tenantA, "dnspod_cn", "verified", cipher, `{"dp_id":"1","dp_key":"key-a"}`)
	platformCopy := insertSourceProvider(t, pool, tenantA, "dnspod_cn", "verified", cipher, `{"dp_id":"3","dp_key":"key-platform"}`)
	if _, err := pool.Exec(ctx, `UPDATE dns_providers SET managed_by='platform' WHERE id=$1`, platformCopy); err != nil {
		t.Fatal(err)
	}
	siteA := insertReconcileZoneSite(t, pool, tenantA, "www.a.example.org", account)
	siteCopy := insertReconcileZoneSite(t, pool, tenantA, "cdn.a.example.org", platformCopy)
	siteB := insertReconcileZoneSite(t, pool, tenantB, "www.b.example.org",
		insertSourceProvider(t, pool, tenantB, "dnspod_cn", "verified", cipher, `{"dp_id":"2","dp_key":"key-b"}`))

	lister := &ownerLister{records: map[string][]dnsproviderremote.ZoneRecord{
		"www.a.example.org.": {{ID: "rec-www", Name: "www.a.example.org.", Type: dnscheck.RecordCNAME,
			Value: "old.cdn.example.net.", TTL: 600}},
	}}
	source := New(pool, cipher)
	snapshot, err := NewOwnerSnapshot(source, lister)
	if err != nil {
		t.Fatal(err)
	}
	zones, err := NewSiteReconcileZones(source, snapshot, audit.New(pool))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(reconcileZoneHandler(t, pool, zones, map[string]sourceTenant{"token-a": tenantA, "token-b": tenantB}))
	defer server.Close()

	// The account's domain list is still empty: no zone hosts the name yet.
	status, body := reconcileZoneDryRun(t, server.URL, "token-a", siteA, "www.a.example.org")
	if status != http.StatusNotFound || errorCode(body) != "dns_reconcile_zone_not_found" {
		t.Fatalf("dry-run before the domain list = %d %s", status, body)
	}
	// 刷新托管范围 (DNS hub refresh) lists both the apex and a delegated subzone.
	hub, err := NewHub(source, &memoryHubRemote{domains: map[string][]string{
		"key-a": {"example.org", "a.example.org"}, "key-platform": {"example.org"},
	}}, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if results, err := hub.RefreshDomains(ctx, hubActor(tenantA), account); err != nil || results[0].State != "refreshed" {
		t.Fatalf("refresh = %+v, %v", results, err)
	}

	status, body = reconcileZoneDryRun(t, server.URL, "token-a", siteA, "www.a.example.org")
	if status != http.StatusOK {
		t.Fatalf("dry-run = %d %s", status, body)
	}
	var plan struct {
		ZoneID uuid.UUID `json:"zone_id"`
		Status string    `json:"status"`
		Plan   struct {
			PreconditionRevision int64 `json:"precondition_revision"`
			Operations           []struct {
				Action string `json:"action"`
			} `json:"operations"`
		} `json:"plan"`
		Provider json.RawMessage `json:"provider"`
	}
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatal(err)
	}
	var zoneName, zoneApex string
	var zoneProvider uuid.UUID
	var zoneDefault bool
	var zoneRevision int64
	if err := pool.QueryRow(ctx, `SELECT name,provider_zone_apex,provider_id,is_default,revision FROM dns_zones
		WHERE id=$1 AND scope_id=$2`, plan.ZoneID, tenantA.scopeID).Scan(&zoneName, &zoneApex, &zoneProvider, &zoneDefault,
		&zoneRevision); err != nil {
		t.Fatalf("bound zone %s: %v", plan.ZoneID, err)
	}
	// Longest listed domain, bound to the site's own account, outside CNAME allocation.
	if zoneName != "a.example.org" || zoneApex != "a.example.org" || zoneProvider != account || zoneDefault ||
		plan.Status != "dry_run" || plan.Plan.PreconditionRevision != zoneRevision ||
		len(plan.Plan.Operations) != 1 || plan.Plan.Operations[0].Action != "update" {
		t.Fatalf("plan = %+v zone %q/%q provider %s default %v revision %d", plan, zoneName, zoneApex, zoneProvider,
			zoneDefault, zoneRevision)
	}
	if len(lister.calls) != 1 || lister.calls[0].ProviderID != account || lister.calls[0].ProviderZoneName != "a.example.org" {
		t.Fatalf("record reads = %+v", lister.calls)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='dns.zone.create'
		AND resource_id=$2`, tenantA.scopeID, plan.ZoneID.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("zone binding audits = %d, %v", audits, err)
	}
	// A second check reuses the binding.
	if status, body := reconcileZoneDryRun(t, server.URL, "token-a", siteA, "www.a.example.org"); status != http.StatusOK {
		t.Fatalf("second dry-run = %d %s", status, body)
	}
	var bound int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM dns_zones WHERE scope_id=$1`, tenantA.scopeID).Scan(&bound); err != nil || bound != 1 {
		t.Fatalf("dns_zones rows = %d, %v", bound, err)
	}

	// Refusals: a name that is not the site's, another tenant's site, the
	// platform copy as the site's account.
	if status, body := reconcileZoneDryRun(t, server.URL, "token-a", siteA, "evil.a.example.org"); status != http.StatusForbidden {
		t.Fatalf("foreign name = %d %s", status, body)
	}
	if status, body := reconcileZoneDryRun(t, server.URL, "token-a", siteB, "www.b.example.org"); status != http.StatusForbidden {
		t.Fatalf("another tenant's site = %d %s", status, body)
	}
	if status, body := reconcileZoneDryRun(t, server.URL, "token-a", siteCopy, "cdn.a.example.org"); status != http.StatusNotFound ||
		errorCode(body) != "dns_reconcile_zone_not_found" {
		t.Fatalf("platform copy account = %d %s", status, body)
	}

	// Apply sends the snapshot back; a zone changed since is 412 and stores nothing.
	check := reconcileZoneCheck("www.a.example.org", plan.Provider)
	if _, err := pool.Exec(ctx, `UPDATE dns_zones SET revision=revision+1 WHERE id=$1`, plan.ZoneID); err != nil {
		t.Fatal(err)
	}
	status, body = reconcileZoneApply(t, server.URL, "token-a", siteA, plan.Plan.PreconditionRevision, check)
	if status != http.StatusPreconditionFailed || errorCode(body) != "revision_conflict" {
		t.Fatalf("stale apply = %d %s", status, body)
	}
	var tasks int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM dns_reconcile_tasks WHERE tenant_id=$1`, tenantA.tenantID).Scan(&tasks); err != nil || tasks != 0 {
		t.Fatalf("tasks after stale apply = %d, %v", tasks, err)
	}
	// Checking again picks up the current revision; that apply is accepted.
	status, body = reconcileZoneDryRun(t, server.URL, "token-a", siteA, "www.a.example.org")
	if err := json.Unmarshal(body, &plan); status != http.StatusOK || err != nil || plan.Plan.PreconditionRevision != zoneRevision+1 {
		t.Fatalf("re-check = %d %s", status, body)
	}
	status, body = reconcileZoneApply(t, server.URL, "token-a", siteA, plan.Plan.PreconditionRevision,
		reconcileZoneCheck("www.a.example.org", plan.Provider))
	if status != http.StatusAccepted {
		t.Fatalf("current apply = %d %s", status, body)
	}
}

func insertReconcileZoneSite(t *testing.T, pool *pgxpool.Pool, tenant sourceTenant, domain string, providerID uuid.UUID) uuid.UUID {
	t.Helper()
	siteID := insertSourceReconcileSite(t, pool, tenant, domain)
	if _, err := pool.Exec(t.Context(), `UPDATE sites SET cname='edge.cdn.example.net' WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO site_domain_facts(scope_id,site_id,site_revision,action,canonical_domain,
		actor_scope_id,actor_user_id,request_id,occurred_at) VALUES($1,$2,1,'activate',$3,$1,$4,'rzone-seed',now())`,
		tenant.scopeID, siteID, domain, tenant.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO site_auto_dns_tasks(site_id,scope_id,provider_id,state,completed_at)
		VALUES($1,$2,$3,'done',now())`, siteID, tenant.scopeID, providerID); err != nil {
		t.Fatal(err)
	}
	return siteID
}

func reconcileZoneHandler(t *testing.T, pool *pgxpool.Pool, zones *SiteReconcileZones, tenants map[string]sourceTenant) http.Handler {
	t.Helper()
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := dnsreconcile.NewPostgresStore(pool, jobs, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := dnsreconcile.NewRuntime(dnsreconcile.RuntimeConfig{
		ProviderAttempts: 1, ProviderTimeout: 5 * time.Second, PollAttempts: 3, RequiredConsecutive: 1,
		InitialBackoff: time.Second, MaximumBackoff: time.Second, OverallTimeout: time.Minute,
		ApplyLeaseDuration: 2 * time.Minute, CommitLeaseDuration: 2 * time.Minute, Now: time.Now,
	}, dnsreconcile.RuntimeDependencies{Store: store, CheckerResolver: reconcileZoneAllow{},
		ProviderResolver: reconcileZoneAllow{}, Entitlement: reconcileZoneAllow{}})
	if err != nil {
		t.Fatal(err)
	}
	sessions := reconcileZoneSessions{}
	for token, tenant := range tenants {
		sessions[token] = dnsreconcilehttp.Principal{SubjectID: tenant.userID, TenantID: tenant.tenantID,
			SessionID: uuid.New(), ScopeID: tenant.scopeID, ScopeKind: "tenant", Permissions: []string{"dns.read", "dns.manage"}}
	}
	handler, err := dnsreconcilehttp.NewHandler(dnsreconcilehttp.Dependencies{Sessions: sessions, IAM: reconcileZoneIAM{},
		Domain: runtime, Workloads: reconcileZoneNoWorkloads{}, Zones: zones}, dnsreconcilehttp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return dnsreconcilehttp.NewTenantHandler(handler)
}

func reconcileZoneCheck(name string, provider json.RawMessage) map[string]any {
	check := map[string]any{
		"name": name, "expected": []map[string]any{{"type": "CNAME", "values": []string{"edge.cdn.example.net"}}},
		"authoritative_ns": []string{}, "ttl": 300, "propagation_window_seconds": 900,
	}
	if provider != nil {
		check["provider"] = provider
	}
	return check
}

func reconcileZoneDryRun(t *testing.T, base, token string, siteID uuid.UUID, name string) (int, []byte) {
	t.Helper()
	return reconcileZonePost(t, base+"/v1/sites/"+siteID.String()+"/dns-reconcile/dry-run", token, nil,
		reconcileZoneCheck(name, nil))
}

func reconcileZoneApply(t *testing.T, base, token string, siteID uuid.UUID, revision int64, check map[string]any) (int, []byte) {
	t.Helper()
	return reconcileZonePost(t, base+"/v1/sites/"+siteID.String()+"/dns-reconcile/apply", token, map[string]string{
		"Idempotency-Key": "rzone-apply-" + uuid.NewString()[:8], "If-Match": `"` + strconv.FormatInt(revision, 10) + `"`,
	}, check)
}

func reconcileZonePost(t *testing.T, url, token string, headers map[string]string, body any) (int, []byte) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "rzone-"+uuid.NewString()[:8])
	request.Header.Set("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(response.Body); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, buffer.Bytes()
}

func errorCode(body []byte) string {
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &envelope)
	return envelope.Error.Code
}
