package httpapi

// 同租户同域名集合已有正在签发的订单时拒绝新单
// （409 certificate_order_in_flight），避免 CA 复用 order。只有签发任务
// 租约有效的订单才挡；排队、等重试或卡住的旧单被新申请取代（acme_order_superseded）。

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

func TestCertificateOrderRefusedWhileSameDomainsInFlight(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind)
		SELECT gen_random_uuid(),'platform' WHERE NOT EXISTS(SELECT 1 FROM access_scopes WHERE kind='platform')`); err != nil {
		t.Fatal(err)
	}
	tenant := insertDNSTenant(t, pool, "inflight-tenant", "inflight-user", passwordHash, []string{
		"dns.read", "certificates.read", "certificates.manage",
	})
	other := insertDNSTenant(t, pool, "inflight-other", "inflight-other-user", passwordHash, []string{
		"dns.read", "certificates.read", "certificates.manage",
	})
	tokens, err := identity.NewTokenManager("inflight-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("inflight-test-v1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	leaseKey := newSiteTestKey(t, "inflight-test-key")
	trust := newSiteTestTrust(t, leaseKey)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{
		serial: 1, limit: 100, key: leaseKey, extraFeatures: []string{entitlementguard.FeatureCertificatesIssue},
	})
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x53}, 32),
		CookieSecure: false, DNSCredentialCipher: cipher, EntitlementTrust: trust,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	token := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID).AccessToken
	otherToken := loginForScope(t, client, server.URL, other.username, other.scopeID).AccessToken

	count := func(scopeID any) int {
		var n int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM certificate_orders WHERE scope_id=$1`, scopeID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	order := func(key string) dnsacme.CertificateOrder {
		t.Helper()
		return createCertificateOrder(t, client, server.URL, token, key, createCertificateOrderRequest{
			Domains: []string{"b.inflight.example.com", "a.inflight.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		})
	}
	// lease puts the order's outbox row in processing; expired: its lease ran out (the worker died).
	lease := func(orderID any, expired bool) {
		t.Helper()
		// The 048 lease contract needs created_at <= updated_at < lease_expires_at.
		window := "lease_expires_at=statement_timestamp()+interval '1 hour',updated_at=statement_timestamp()"
		if expired {
			window = "lease_expires_at=statement_timestamp(),updated_at=created_at"
		}
		for _, statement := range []string{`ALTER TABLE dns_acme_outbox DISABLE TRIGGER USER`,
			`UPDATE dns_acme_outbox SET status='processing',attempts=attempts+1,lease_token=gen_random_uuid(),` + window + `
				WHERE aggregate_id=$1`,
			`ALTER TABLE dns_acme_outbox ENABLE TRIGGER USER`} {
			args := []any{}
			if strings.Contains(statement, "$1") {
				args = append(args, orderID)
			}
			if _, err := pool.Exec(context.Background(), statement, args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	state := func(orderID any) (string, *string, *string) {
		t.Helper()
		var status string
		var code, reason *string
		if err := pool.QueryRow(context.Background(), `SELECT status,failure_code,failure_reason FROM certificate_orders WHERE id=$1`,
			orderID).Scan(&status, &code, &reason); err != nil {
			t.Fatal(err)
		}
		return status, code, reason
	}
	running := order("inflight-first")
	lease(running.ID, false)

	for _, status := range []string{"pending", "validating", "issuing"} {
		t.Run("same set refused while running "+status, func(t *testing.T) {
			// 新单即 pending；之后按单调顺序推进到 validating、issuing
			if status != "pending" {
				if _, err := pool.Exec(context.Background(), `UPDATE certificate_orders SET status=$2,revision=revision+1,updated_at=statement_timestamp() WHERE id=$1`, running.ID, status); err != nil {
					t.Fatal(err)
				}
			}
			// 顺序不同的同一集合也算同一申请
			response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/certificate-orders", createCertificateOrderRequest{
				Domains: []string{"a.inflight.example.com", "b.inflight.example.com"}, ChallengeType: "http-01", AutoRenew: true,
			}, token, "inflight-again-"+status, "")
			assertError(t, response, http.StatusConflict, "certificate_order_in_flight", "")
			response.Body.Close()
			if n := count(tenant.scopeID); n != 1 {
				t.Fatalf("refused order left %d orders", n)
			}
		})
	}

	t.Run("a different set and another tenant are not refused", func(t *testing.T) {
		createCertificateOrder(t, client, server.URL, token, "inflight-subset", createCertificateOrderRequest{
			Domains: []string{"a.inflight.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		})
		createCertificateOrder(t, client, server.URL, otherToken, "inflight-other-tenant", createCertificateOrderRequest{
			Domains: []string{"a.inflight.example.com", "b.inflight.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		})
	})

	// 失败或卡住的申请不能一直占用。租约过期（worker 已不在）的旧单被新申请取代。
	t.Run("a stalled order is superseded", func(t *testing.T) {
		lease(running.ID, true)
		replacement := order("inflight-after-stall")
		status, code, reason := state(running.ID)
		if status != "failed" || code == nil || *code != "acme_order_superseded" || reason == nil || *reason != "申请超时未完成，已被新的申请取代" {
			t.Fatalf("stalled order status=%s code=%v reason=%v", status, code, reason)
		}
		var audits int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE resource_id=$1
			AND action='certificate.order.transition' AND payload->>'operation'='supersede'`, running.ID.String()).Scan(&audits); err != nil || audits != 1 {
			t.Fatalf("supersede audits=%d error=%v", audits, err)
		}
		// 排队中（未被领取）的申请同样不挡新申请。
		third := order("inflight-after-queued")
		if status, code, _ := state(replacement.ID); status != "failed" || code == nil || *code != "acme_order_superseded" {
			t.Fatalf("queued order status=%s code=%v", status, code)
		}
		if status, _, _ := state(third.ID); status != "pending" {
			t.Fatalf("new order status=%s", status)
		}
	})
}
