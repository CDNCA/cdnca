package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSiteOriginHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	key := newSiteTestKey(t, "control-site-origin-test-key")
	trust := newSiteTestTrust(t, key)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{serial: 1, limit: 100, key: key})
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	identityStore := identity.NewStore(pool)
	bootstrap, err := identityStore.BootstrapPlatformUser(
		context.Background(), "originadmin", "Origin Administrator", passwordHash, "site-origin-bootstrap",
	)
	if err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}
	tenantA := insertSiteTenant(t, pool, "tenant-origin-a", "origin-a-user", "Origin A User", passwordHash)
	tenantB := insertSiteTenant(t, pool, "tenant-origin-b", "origin-b-user", "Origin B User", passwordHash)
	insertSiteScopeUser(t, pool, tenantA.scopeID, "origin-reader", "Origin Reader", passwordHash, []string{"sites.read"})

	tokens, err := identity.NewTokenManager("site-origin-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CookieSecure: false, EntitlementTrust: trust}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	platformAuth, _ := loginOK(t, client, server.URL, "originadmin")
	tenantAAuth := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	tenantBAuth := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)
	readerAuth := loginForScope(t, client, server.URL, "origin-reader", tenantA.scopeID)

	created := createSite(t, client, server.URL, tenantAAuth.AccessToken, "origin-create", createSiteRequest{
		Basic: validSiteBasic("origin-flow.example", "192.0.2.10"),
	})
	if created.OriginPool.BalanceMethod != site.BalanceRoundRobin || len(created.OriginPool.Origins) != 1 ||
		created.OriginPool.Origins[0] != (site.Origin{Host: "192.0.2.10", Port: 80, Weight: 1, Enabled: true}) {
		t.Fatalf("created origin pool = %#v", created.OriginPool)
	}

	t.Run("all balance methods and compatibility projection", func(t *testing.T) {
		current := created
		for index, method := range []string{
			site.BalanceRoundRobin, site.BalanceIPHash, site.BalanceURLHash, site.BalanceLeastConn, site.BalanceRandom,
		} {
			pool := site.OriginPool{
				Origins: []site.Origin{
					{Host: "ORIGIN.Example.COM.", Port: 80, Weight: 30, Enabled: true},
					{Host: "2001:0DB8::1", Port: 8443, Weight: 70, Enabled: true},
				},
				BalanceMethod: method, FailoverTries: 2, ConnectTimeoutMS: 500, ReadTimeoutMS: 5000,
			}
			current = updateSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken, "origin-method-"+method,
				originUpdateRequest(current.Version, pool))
			if current.Version != int64(index+2) || current.OriginPool.BalanceMethod != method {
				t.Fatalf("updated method %s = %#v", method, current)
			}
			if got := current.Basic.Origins; len(got) != 2 || got[0] != "origin.example.com" || got[1] != "[2001:db8::1]:8443" {
				t.Fatalf("compatibility origins for %s = %#v", method, got)
			}
		}
		created = current
	})

	t.Run("forwarding settings round trip and are audited", func(t *testing.T) {
		forwarding := site.OriginPool{
			Origins: []site.Origin{
				{Host: "origin.example.com", Port: 80, Weight: 1, Enabled: true, MaxConns: 50},
				{Host: "192.0.2.20", Port: 80, Weight: 1, Enabled: true, Level: 1},
			},
			BalanceMethod: site.BalanceRoundRobin, FailoverTries: 2, ConnectTimeoutMS: 500, ReadTimeoutMS: 5000,
			RequestHost: site.OriginRequestHost{Mode: site.OriginRequestHostCustom, Value: "Bucket.Example.com"},
			Scheme:      site.OriginSchemeHTTPS, TLS: site.OriginTLS{Trust: site.OriginTrustSystem},
			WebSocket:         &site.OriginWebSocket{Enabled: true, AllowedOrigins: []string{"https://app.example.com"}},
			TrustedProxyCIDRs: []string{"10.0.0.1/8"},
		}
		updated := updateSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken, "origin-forwarding",
			originUpdateRequest(created.Version, forwarding))
		got := updated.OriginPool
		if got.RequestHost.Value != "bucket.example.com" || got.Scheme != site.OriginSchemeHTTPS || got.HTTPSPort != 443 ||
			got.Origins[1].Level != 1 || got.Origins[0].MaxConns != 50 || got.WebSocket == nil ||
			len(got.WebSocket.AllowedOrigins) != 1 || len(got.TrustedProxyCIDRs) != 1 || got.TrustedProxyCIDRs[0] != "10.0.0.0/8" {
			t.Fatalf("forwarding round trip = %#v", got)
		}
		if again := getSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken); again.OriginPool.Scheme != site.OriginSchemeHTTPS ||
			again.OriginPool.TrustedProxyCIDRs[0] != "10.0.0.0/8" {
			t.Fatalf("stored forwarding = %#v", again.OriginPool)
		}
		var changes string
		if err := pool.QueryRow(t.Context(), `SELECT changes::text FROM audit_events
			WHERE action='site.origin.update' AND resource_id=$1 ORDER BY occurred_at DESC LIMIT 1`, created.ID.String()).Scan(&changes); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`"field": "scheme"`, `"after": "https"`, `"field": "backup_origins"`, `"field": "trusted_proxy_cidrs"`} {
			if !strings.Contains(changes, want) {
				t.Fatalf("audit changes lack %s: %s", want, changes)
			}
		}
		created = updated
	})

	// tp-b3a-be (migration 490): 跟随协议和端口, 访问域名+端口, pool HTTP
	// 回源端口 inherited by an origin without its own, origin auth switch.
	t.Run("competitor origin settings round trip", func(t *testing.T) {
		off := false
		parity := site.OriginPool{
			Origins: []site.Origin{
				{Host: "origin.example.com", Port: 1, Weight: 1, Enabled: true, PortInherited: true},
				{Host: "192.0.2.21", Port: 9000, Weight: 1, Enabled: true},
			},
			BalanceMethod: site.BalanceRoundRobin, FailoverTries: 1, ConnectTimeoutMS: 500, ReadTimeoutMS: 5000,
			RequestHost: site.OriginRequestHost{Mode: site.OriginRequestHostVisitorPort},
			Scheme:      site.OriginSchemeHTTP, HTTPPort: 8080, OriginAuthEnabled: &off,
		}
		updated := updateSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken, "origin-parity",
			originUpdateRequest(created.Version, parity))
		got := getSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken)
		if got.OriginPool.HTTPPort != 8080 || got.OriginPool.RequestHost.Mode != site.OriginRequestHostVisitorPort ||
			got.OriginPool.OriginAuthEnabled == nil || *got.OriginPool.OriginAuthEnabled ||
			got.OriginPool.Origins[0] != (site.Origin{Host: "origin.example.com", Port: 8080, Weight: 1, Enabled: true, PortInherited: true}) ||
			got.OriginPool.Origins[1].Port != 9000 || got.OriginPool.Origins[1].PortInherited {
			t.Fatalf("stored parity settings = %#v", got.OriginPool)
		}
		if origins := got.Basic.Origins; len(origins) != 2 || origins[0] != "origin.example.com:8080" || origins[1] != "192.0.2.21:9000" {
			t.Fatalf("compatibility origins = %#v", origins)
		}

		parity.Scheme, parity.FollowPort, parity.HTTPPort = site.OriginSchemeFollow, true, 0
		updated = updateSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken, "origin-parity-follow",
			originUpdateRequest(updated.Version, parity))
		if updated.OriginPool.Scheme != site.OriginSchemeFollow || !updated.OriginPool.FollowPort ||
			updated.OriginPool.HTTPPort != 80 || updated.OriginPool.Origins[0].Port != 80 {
			t.Fatalf("follow protocol and port = %#v", updated.OriginPool)
		}
		var changes string
		if err := pool.QueryRow(t.Context(), `SELECT changes::text FROM audit_events
			WHERE action='site.origin.update' AND resource_id=$1 ORDER BY occurred_at DESC LIMIT 1`, created.ID.String()).Scan(&changes); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`"field": "follow_port"`, `"field": "scheme"`, `"field": "http_port"`} {
			if !strings.Contains(changes, want) {
				t.Fatalf("audit changes lack %s: %s", want, changes)
			}
		}
		// back to plain origin ports for the cases below (an inherited port
		// ignores the written one)
		on := true
		parity.Scheme, parity.FollowPort, parity.RequestHost, parity.OriginAuthEnabled = site.OriginSchemeHTTP, false, site.OriginRequestHost{}, &on
		parity.Origins[0].PortInherited, parity.Origins[0].Port = false, 80
		created = updateSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken, "origin-parity-reset",
			originUpdateRequest(updated.Version, parity))
	})

	t.Run("validation is strict and does not consume the version", func(t *testing.T) {
		valid := created.OriginPool
		tests := map[string]func(*site.OriginPool){
			"invalid host":       func(pool *site.OriginPool) { pool.Origins[0].Host = "https://origin.example/path" },
			"invalid port":       func(pool *site.OriginPool) { pool.Origins[0].Port = 0 },
			"invalid weight":     func(pool *site.OriginPool) { pool.Origins[0].Weight = 101 },
			"duplicate endpoint": func(pool *site.OriginPool) { pool.Origins[1] = pool.Origins[0] },
			"all disabled": func(pool *site.OriginPool) {
				for index := range pool.Origins {
					pool.Origins[index].Enabled = false
				}
			},
			"failover":        func(pool *site.OriginPool) { pool.FailoverTries = 3 },
			"connect timeout": func(pool *site.OriginPool) { pool.ConnectTimeoutMS = 49 },
			"read timeout":    func(pool *site.OriginPool) { pool.ReadTimeoutMS = 300001 },
		}
		for name, mutate := range tests {
			t.Run(name, func(t *testing.T) {
				candidate := valid
				candidate.Origins = append([]site.Origin(nil), valid.Origins...)
				mutate(&candidate)
				response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+created.ID.String(),
					originUpdateRequest(created.Version, candidate), tenantAAuth.AccessToken, "origin-invalid-"+strings.ReplaceAll(name, " ", "-"), "")
				assertError(t, response, http.StatusBadRequest, "validation_error", "")
				response.Body.Close()
			})
		}
		if current := getSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken); current.Version != created.Version {
			t.Fatalf("invalid origin writes changed version: got %d want %d", current.Version, created.Version)
		}
	})

	t.Run("RBAC and tenant isolation", func(t *testing.T) {
		readOnly := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+created.ID.String(),
			originUpdateRequest(created.Version, created.OriginPool), readerAuth.AccessToken, "origin-reader-denied", "")
		assertError(t, readOnly, http.StatusForbidden, "permission_denied", "")
		readOnly.Body.Close()

		crossTenant := createSite(t, client, server.URL, tenantBAuth.AccessToken, "origin-cross-create", createSiteRequest{
			Basic: validSiteBasic("origin-cross.example", "198.51.100.20"),
		})
		response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+crossTenant.ID.String(),
			originUpdateRequest(crossTenant.Version, crossTenant.OriginPool), tenantAAuth.AccessToken, "origin-cross-denied", "")
		assertError(t, response, http.StatusNotFound, "site_not_found", "")
		response.Body.Close()
	})

	t.Run("exact replay and changed payload conflict", func(t *testing.T) {
		pool := created.OriginPool
		pool.Origins[0].Weight = 29
		body := originUpdateRequest(created.Version, pool)
		updated := updateSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken, "origin-replay", body)
		replayed := updateSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken, "origin-replay", body)
		if replayed.Version != updated.Version || replayed.OriginPool.Origins[0].Weight != 29 {
			t.Fatalf("origin replay = %#v, first = %#v", replayed, updated)
		}
		changed := pool
		changed.Origins = append([]site.Origin(nil), pool.Origins...)
		changed.Origins[0].Weight = 28
		response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+created.ID.String(),
			originUpdateRequest(created.Version, changed), tenantAAuth.AccessToken, "origin-replay", "")
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
		response.Body.Close()
		created = updated
	})

	t.Run("basic writes preserve rich metadata and reject replacement", func(t *testing.T) {
		basic := created.Basic
		basic.CNAME = "preserved.edge.example"
		preserved := updateSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken, "origin-basic-preserve",
			updateSiteRequest{ExpectedVersion: created.Version, Section: "basic", Changes: basic})
		if preserved.OriginPool.BalanceMethod != created.OriginPool.BalanceMethod || preserved.OriginPool.Origins[0].Weight != 29 {
			t.Fatalf("basic write lost rich metadata: %#v", preserved.OriginPool)
		}
		created = preserved

		replacement := created.Basic
		replacement.Origins = []string{"203.0.113.50"}
		response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+created.ID.String(),
			updateSiteRequest{ExpectedVersion: created.Version, Section: "basic", Changes: replacement},
			tenantAAuth.AccessToken, "origin-basic-conflict", "")
		assertError(t, response, http.StatusConflict, "origin_section_conflict", "")
		response.Body.Close()
	})

	t.Run("same revision serializes to one success", func(t *testing.T) {
		target := createSite(t, client, server.URL, tenantAAuth.AccessToken, "origin-concurrent-create", createSiteRequest{
			Basic: validSiteBasic("origin-concurrent.example", "203.0.113.60"),
		})
		statuses := make([]int, 2)
		var wait sync.WaitGroup
		for index := range statuses {
			index := index
			wait.Add(1)
			go func() {
				defer wait.Done()
				pool := target.OriginPool
				pool.Origins = append([]site.Origin(nil), pool.Origins...)
				pool.Origins[0].Weight = index + 2
				response, requestErr := performSiteRequest(client, http.MethodPatch, server.URL+"/v1/sites/"+target.ID.String(),
					originUpdateRequest(target.Version, pool), tenantAAuth.AccessToken, "origin-concurrent-"+string(rune('a'+index)), "")
				if requestErr != nil {
					statuses[index] = -1
					return
				}
				statuses[index] = response.StatusCode
				response.Body.Close()
			}()
		}
		wait.Wait()
		if !((statuses[0] == http.StatusOK && statuses[1] == http.StatusConflict) ||
			(statuses[1] == http.StatusOK && statuses[0] == http.StatusConflict)) {
			t.Fatalf("concurrent statuses = %#v", statuses)
		}
	})

	t.Run("audit failure rolls back pool projection and idempotency claim", func(t *testing.T) {
		before := getSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken)
		if _, err := pool.Exec(context.Background(), `
			CREATE FUNCTION fail_site_origin_audit() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.action = 'site.origin.update' THEN RAISE EXCEPTION 'forced origin audit failure'; END IF;
				RETURN NEW;
			END; $$;
			CREATE TRIGGER fail_site_origin_audit_trigger BEFORE INSERT ON audit_events
			FOR EACH ROW EXECUTE FUNCTION fail_site_origin_audit()`); err != nil {
			t.Fatalf("install audit failure trigger: %v", err)
		}
		candidate := before.OriginPool
		candidate.Origins = append([]site.Origin(nil), candidate.Origins...)
		candidate.Origins[0].Weight = 27
		response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+created.ID.String(),
			originUpdateRequest(before.Version, candidate), tenantAAuth.AccessToken, "origin-audit-rollback", "")
		assertError(t, response, http.StatusInternalServerError, "internal_error", "")
		response.Body.Close()
		if _, err := pool.Exec(context.Background(), `DROP TRIGGER fail_site_origin_audit_trigger ON audit_events; DROP FUNCTION fail_site_origin_audit()`); err != nil {
			t.Fatalf("remove audit failure trigger: %v", err)
		}
		after := getSite(t, client, server.URL, created.ID, tenantAAuth.AccessToken)
		if after.Version != before.Version || after.OriginPool.Origins[0].Weight != before.OriginPool.Origins[0].Weight {
			t.Fatalf("origin changed despite audit rollback: before=%#v after=%#v", before, after)
		}
		var claims int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM site_origin_write_requests WHERE idempotency_key = 'origin-audit-rollback'`).Scan(&claims); err != nil {
			t.Fatalf("count rolled-back idempotency claims: %v", err)
		}
		if claims != 0 {
			t.Fatalf("rolled-back origin claim count = %d", claims)
		}
	})

	if bootstrap.ScopeID == uuid.Nil || platformAuth.AccessToken == "" {
		t.Fatal("platform origin test setup was not usable")
	}
}

func originUpdateRequest(version int64, pool site.OriginPool) updateSiteRequest {
	return updateSiteRequest{ExpectedVersion: version, Section: "origin", OriginChanges: &pool}
}

func TestSiteOriginMigration014(t *testing.T) {
	// Only 1..013: rolling the release head back crosses migration 268's
	// one-way down gate (P2682). The 013 schema predates the tenant fixture's
	// role projection, so seed the site owner directly.
	pool := migrationRoundTripPool(t, 13)
	tenant := struct{ scopeID, userID uuid.UUID }{scopeID: uuid.New()}
	tenantID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO tenants (id, display_name) VALUES ($1, 'tenant-origin-migration')`, tenantID); err != nil {
		t.Fatalf("insert site tenant: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, tenant.scopeID, tenantID); err != nil {
		t.Fatalf("insert site tenant scope: %v", err)
	}
	tenant.userID = insertTestUser(t, pool, tenant.scopeID, "origin-migration-user", "Origin Migration User", "unused", "active")

	activeID := uuid.New()
	deletedID := uuid.New()
	legacyOrigins := []string{"192.0.2.10", "origin.example:8080", "2001:db8::1", "[2001:db8::2]", "[2001:db8::3]:443"}
	legacyHosts := []string{"192.0.2.10", "origin.example", "2001:db8::1", "2001:db8::2", "2001:db8::3"}
	for _, record := range []struct {
		id        uuid.UUID
		domain    string
		origins   []string
		hosts     []string
		deletedAt any
	}{
		{activeID, "migration-origin.example", legacyOrigins, legacyHosts, nil},
		{deletedID, "migration-deleted.example", []string{"198.51.100.20:8443"}, []string{"198.51.100.20"}, time.Now().UTC()},
	} {
		if _, err := pool.Exec(context.Background(), `
			INSERT INTO sites (
				id, scope_id, owner_user_id, domain, origins, origin_hosts,
				created_by_user_id, updated_by_user_id, deleted_at
			) VALUES ($1,$2,$3,$4,$5,$6,$3,$3,$7)`,
			record.id, tenant.scopeID, tenant.userID, record.domain, record.origins, record.hosts, record.deletedAt); err != nil {
			t.Fatalf("insert legacy site %s: %v", record.domain, err)
		}
	}
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", 14); err != nil {
		t.Fatalf("Migrate(up 014) error = %v", err)
	}
	assertMigratedOrigins(t, pool, activeID, []site.Origin{
		{Host: "192.0.2.10", Port: 80, Weight: 1, Enabled: true},
		{Host: "origin.example", Port: 8080, Weight: 1, Enabled: true},
		{Host: "2001:db8::1", Port: 80, Weight: 1, Enabled: true},
		{Host: "2001:db8::2", Port: 80, Weight: 1, Enabled: true},
		{Host: "2001:db8::3", Port: 443, Weight: 1, Enabled: true},
	})
	assertMigratedOrigins(t, pool, deletedID, []site.Origin{{Host: "198.51.100.20", Port: 8443, Weight: 1, Enabled: true}})

	migrateSiteSchemaDownTo(t, pool, 13)
	var poolTable, validator *string
	if err := pool.QueryRow(context.Background(), `
		SELECT to_regclass('site_origin_pools')::text, to_regprocedure('validate_site_origin_pool(uuid)')::text`).Scan(&poolTable, &validator); err != nil {
		t.Fatalf("inspect origin migration cleanup: %v", err)
	}
	if poolTable != nil || validator != nil {
		t.Fatalf("origin migration objects remained after down: table=%v validator=%v", poolTable, validator)
	}
	var origins, hosts []string
	if err := pool.QueryRow(context.Background(), `SELECT origins, origin_hosts FROM sites WHERE id = $1`, activeID).Scan(&origins, &hosts); err != nil {
		t.Fatalf("read compatibility arrays after down: %v", err)
	}
	canonicalOrigins := []string{"192.0.2.10", "origin.example:8080", "2001:db8::1", "2001:db8::2", "[2001:db8::3]:443"}
	if strings.Join(origins, "|") != strings.Join(canonicalOrigins, "|") || strings.Join(hosts, "|") != strings.Join(legacyHosts, "|") {
		t.Fatalf("legacy arrays after down = %#v / %#v", origins, hosts)
	}
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", 14); err != nil {
		t.Fatalf("Migrate(up after 014 down) error = %v", err)
	}
	assertMigratedOrigins(t, pool, activeID, []site.Origin{
		{Host: "192.0.2.10", Port: 80, Weight: 1, Enabled: true},
		{Host: "origin.example", Port: 8080, Weight: 1, Enabled: true},
		{Host: "2001:db8::1", Port: 80, Weight: 1, Enabled: true},
		{Host: "2001:db8::2", Port: 80, Weight: 1, Enabled: true},
		{Host: "2001:db8::3", Port: 443, Weight: 1, Enabled: true},
	})

	if _, err := pool.Exec(context.Background(), `UPDATE site_origin_pools SET balance_method = 'least_conn' WHERE site_id = $1`, activeID); err != nil {
		t.Fatalf("set non-default origin pool: %v", err)
	}
	migrateSiteSchemaDownTo(t, pool, 14)
	if err := database.Migrate(context.Background(), pool, "down"); err == nil {
		t.Fatal("Migrate(down 014) accepted non-default origin metadata")
	}
	var version int64
	if err := pool.QueryRow(context.Background(), `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("read migration version after rejected down: %v", err)
	}
	if version != 14 {
		t.Fatalf("migration version after rejected down = %d, want 14", version)
	}
}

func TestSiteOriginLegacyIdempotencyReplayAfter014(t *testing.T) {
	pool := isolatedTestPool(t)
	key := newSiteTestKey(t, "control-site-origin-legacy-replay-key")
	trust := newSiteTestTrust(t, key)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{serial: 1, limit: 100, key: key})
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(
		context.Background(), "legacy-origin-admin", "Legacy Origin Admin", passwordHash, "legacy-origin-bootstrap",
	); err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}
	tenant := insertSiteTenant(t, pool, "tenant-origin-legacy", "origin-legacy-user", "Origin Legacy User", passwordHash)
	tokens, err := identity.NewTokenManager("site-origin-legacy-secret-at-least-thirty-two", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false, EntitlementTrust: trust, APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	auth := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)
	created := createSite(t, client, server.URL, auth.AccessToken, "legacy-origin-create", createSiteRequest{
		Basic: validSiteBasic("legacy-replay.example", "192.0.2.70"),
	})

	var stored []byte
	if err := pool.QueryRow(context.Background(), `
		SELECT response_body FROM site_write_requests
		WHERE actor_user_id = $1 AND operation = 'site.create' AND idempotency_key = 'legacy-origin-create'`, tenant.userID).Scan(&stored); err != nil {
		t.Fatalf("read source stored response: %v", err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(stored, &legacy); err != nil {
		t.Fatalf("decode source stored response: %v", err)
	}
	delete(legacy, "origin_pool")
	legacyResponse, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("encode legacy stored response: %v", err)
	}

	// site_write_requests is unchanged since migration 010, so a stored
	// response written by the 013 binary is seeded on the release head
	// directly; rolling the head back to 013 crosses migration 268's one-way
	// down gate (P2682).
	// Derive the stored request digest from the replayed basic section the
	// same way the update handler does, so it tracks SiteFields as it grows.
	fields, err := fieldsFromBasic(created.Basic)
	if err != nil {
		t.Fatalf("legacy replay fields: %v", err)
	}
	digestInput := struct {
		ID               uuid.UUID       `json:"id"`
		ExpectedRevision int64           `json:"expected_revision"`
		Fields           site.SiteFields `json:"fields"`
	}{created.ID, 1, fields}
	encodedDigestInput, err := json.Marshal(digestInput)
	if err != nil {
		t.Fatalf("encode legacy digest input: %v", err)
	}
	digest := sha256.Sum256(encodedDigestInput)
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO site_write_requests (
			id, actor_user_id, target_scope_id, operation, idempotency_key, request_digest,
			resource_id, response_status, response_body, completed_at
		) VALUES ($1,$2,$3,'site.update','legacy-origin-update',$4,$5,200,$6,now())`,
		uuid.New(), tenant.userID, tenant.scopeID, digest[:], created.ID, legacyResponse); err != nil {
		t.Fatalf("insert migration-013 stored response: %v", err)
	}

	rich := created.OriginPool
	rich.Origins = []site.Origin{{Host: "203.0.113.70", Port: 8443, Weight: 55, Enabled: true}}
	rich.BalanceMethod = site.BalanceLeastConn
	rich.ConnectTimeoutMS = 900
	rich.ReadTimeoutMS = 9000
	current := updateSite(t, client, server.URL, created.ID, auth.AccessToken, "legacy-origin-current-rich",
		originUpdateRequest(created.Version, rich))
	if current.Version != 2 || current.OriginPool.Origins[0].Host != "203.0.113.70" {
		t.Fatalf("current rich site = %#v", current)
	}

	replayed := updateSite(t, client, server.URL, created.ID, auth.AccessToken, "legacy-origin-update",
		updateSiteRequest{ExpectedVersion: 1, Section: "basic", Changes: created.Basic})
	if replayed.Version != 1 || replayed.Basic.Origins[0] != "192.0.2.70" ||
		replayed.OriginPool.BalanceMethod != site.BalanceRoundRobin || replayed.OriginPool.Origins[0].Host != "192.0.2.70" ||
		replayed.OriginPool.Origins[0].Port != 80 || replayed.OriginPool.Origins[0].Weight != 1 {
		t.Fatalf("legacy replay response = %#v", replayed)
	}
	after := getSite(t, client, server.URL, created.ID, auth.AccessToken)
	if after.Version != 2 || after.OriginPool.BalanceMethod != site.BalanceLeastConn || after.OriginPool.Origins[0].Host != "203.0.113.70" {
		t.Fatalf("legacy replay was polluted by or changed current site: %#v", after)
	}
}

func migrateSiteSchemaDownTo(t *testing.T, pool *pgxpool.Pool, target int64) {
	t.Helper()
	for {
		var version int64
		if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
			t.Fatalf("read current migration version: %v", err)
		}
		if version <= target {
			return
		}
		if err := database.Migrate(context.Background(), pool, "down"); err != nil {
			t.Fatalf("Migrate(down %d) error = %v", version, err)
		}
	}
}

func assertMigratedOrigins(t *testing.T, pool *pgxpool.Pool, siteID uuid.UUID, want []site.Origin) {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT host, port, weight, enabled FROM site_origins WHERE site_id = $1 ORDER BY position`, siteID)
	if err != nil {
		t.Fatalf("query migrated origins: %v", err)
	}
	defer rows.Close()
	var got []site.Origin
	for rows.Next() {
		var origin site.Origin
		if err := rows.Scan(&origin.Host, &origin.Port, &origin.Weight, &origin.Enabled); err != nil {
			t.Fatalf("scan migrated origin: %v", err)
		}
		got = append(got, origin)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migrated origins: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("migrated origins = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("migrated origin %d = %#v, want %#v", index, got[index], want[index])
		}
	}
}
