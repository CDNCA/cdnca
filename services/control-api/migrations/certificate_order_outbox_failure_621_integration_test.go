//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestCertificateOrderOutboxFailure621 seeds a production-shaped order at 620
// (pending, outbox failed with acme_dns_zone_unavailable, the provider hosting
// only another zone), a validating order whose outbox failed with
// acme_authorization_invalid, an order still retrying a timeout and an order
// already failed by hand; 621 fails only the first two.
func TestCertificateOrderOutboxFailure621(t *testing.T) {
	const version = 621
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID, providerID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", strings.Fields(query)[0], err)
		}
	}
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'Stuck order tenant')`, tenantID)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Stuck order user','test-hash')`,
		userID, "stuck621-"+strings.ReplaceAll(userID.String(), "-", "")[:12])
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,status,
		created_by_user_id,updated_by_user_id) VALUES($1,$2,'平台DNS配置','cloudflare','credential-key',$3,'verified',$4,$4)`,
		providerID, scopeID, make([]byte, 32), userID)
	exec(`INSERT INTO dns_zones(id,scope_id,provider_id,name,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'cdn.example.net',$4,$4)`, uuid.New(), scopeID, providerID, userID)

	order := func(domains []string, challenge string, provider *uuid.UUID) uuid.UUID {
		t.Helper()
		id := uuid.New()
		exec(`INSERT INTO certificate_orders(id,scope_id,dns_provider_id,domains,challenge_type,auto_renew,
			created_by_user_id,updated_by_user_id) VALUES($1,$2,$3,$4,$5,true,$6,$6)`,
			id, scopeID, provider, domains, challenge, userID)
		exec(`INSERT INTO dns_acme_outbox(id,scope_id,aggregate_type,aggregate_id,event_type,payload)
			VALUES($1,$2,'certificate_order',$3,'certificate.order.requested','{}')`, uuid.New(), scopeID, id)
		return id
	}
	// The outbox runtime trigger only accepts a leased worker's result; the
	// test writes the failed retry schedule directly.
	outboxFailed := func(orderID uuid.UUID, attempts int, code string, reason *string) {
		t.Helper()
		exec(`ALTER TABLE dns_acme_outbox DISABLE TRIGGER USER`)
		exec(`UPDATE dns_acme_outbox SET status='failed',attempts=$2,last_error_code=$3,last_error_reason=$4,
			lease_token=gen_random_uuid(),lease_expires_at=now(),updated_at=now(),
			next_attempt_at=now()+interval '1 hour' WHERE aggregate_id=$1`, orderID, attempts, code, reason)
		exec(`ALTER TABLE dns_acme_outbox ENABLE TRIGGER USER`)
	}
	zone := order([]string{"tenant.example.com", "*.tenant.example.com"}, "dns-01", &providerID)
	outboxFailed(zone, 4, "acme_dns_zone_unavailable", nil)
	caReason := "Invalid response from [url]: 404"
	authorization := order([]string{"auth.example.test"}, "http-01", nil)
	exec(`UPDATE certificate_orders SET status='validating',revision=revision+1,updated_at=now() WHERE id=$1`, authorization)
	outboxFailed(authorization, 1, "acme_authorization_invalid", &caReason)
	retrying := order([]string{"retry.example.test"}, "http-01", nil)
	outboxFailed(retrying, 2, "acme_timeout", nil)
	handled := order([]string{"handled.example.test"}, "dns-01", &providerID)
	outboxFailed(handled, 4, "acme_dns_zone_unavailable", nil)
	exec(`UPDATE certificate_orders SET status='failed',failure_code='acme_dns_zone_unavailable',revision=revision+1,
		updated_at=now() WHERE id=$1`, handled)

	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	type state struct {
		status   string
		code     *string
		reason   *string
		revision int64
	}
	read := func(id uuid.UUID) state {
		t.Helper()
		var value state
		if err := pool.QueryRow(ctx, `SELECT status,failure_code,failure_reason,revision FROM certificate_orders WHERE id=$1`,
			id).Scan(&value.status, &value.code, &value.reason, &value.revision); err != nil {
			t.Fatal(err)
		}
		return value
	}
	want := "所选 DNS API 下没有托管 tenant.example.com 的解析域，无法用 DNS 验证；请添加该域名所在 DNS 服务商的 API，或改用 HTTP 验证"
	if got := read(zone); got.status != "failed" || got.code == nil || *got.code != "acme_dns_zone_unavailable" ||
		got.reason == nil || *got.reason != want || got.revision != 2 {
		t.Fatalf("zone order = %+v reason=%v", got, got.reason)
	}
	if got := read(authorization); got.status != "failed" || got.code == nil || *got.code != "acme_authorization_invalid" ||
		got.reason == nil || *got.reason != caReason || got.revision != 3 {
		t.Fatalf("authorization order = %+v", got)
	}
	if got := read(retrying); got.status != "pending" || got.code != nil || got.revision != 1 {
		t.Fatalf("retrying order changed: %+v", got)
	}
	if got := read(handled); got.status != "failed" || got.reason != nil || got.revision != 2 {
		t.Fatalf("already failed order changed: %+v", got)
	}
	var events int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM domain_event_outbox_368 WHERE subject=$1 AND payload->>'status'='failed'`,
		"certificate_order/"+zone.String()).Scan(&events); err != nil || events != 1 {
		t.Fatalf("status events=%d error=%v", events, err)
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	if got := read(zone); got.status != "failed" || got.revision != 2 {
		t.Fatalf("down restored the order: %+v", got)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("re-up %d: %v", version, err)
	}
	if got := read(zone); got.revision != 2 {
		t.Fatalf("re-up changed the failed order: %+v", got)
	}
}
