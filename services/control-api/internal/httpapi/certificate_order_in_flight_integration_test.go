package httpapi

// 同租户同域名集合已有 pending/validating/issuing
// 订单时拒绝新单（409 certificate_order_in_flight），避免 CA 复用 order；订单结束后可再申请。

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
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
	first := createCertificateOrder(t, client, server.URL, token, "inflight-first", createCertificateOrderRequest{
		Domains: []string{"b.inflight.example.com", "a.inflight.example.com"}, ChallengeType: "http-01", AutoRenew: true,
	})

	for _, status := range []string{"pending", "validating", "issuing"} {
		t.Run("same set refused while "+status, func(t *testing.T) {
			// 新单即 pending；之后按单调顺序推进到 validating、issuing
			if status != "pending" {
				if _, err := pool.Exec(context.Background(), `UPDATE certificate_orders SET status=$2,revision=revision+1,updated_at=statement_timestamp() WHERE id=$1`, first.ID, status); err != nil {
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

	t.Run("a finished order no longer blocks", func(t *testing.T) {
		if _, err := pool.Exec(context.Background(), `UPDATE certificate_orders SET status='failed',failure_code='test',revision=revision+1,updated_at=statement_timestamp() WHERE id=$1`, first.ID); err != nil {
			t.Fatal(err)
		}
		createCertificateOrder(t, client, server.URL, token, "inflight-after-failed", createCertificateOrderRequest{
			Domains: []string{"a.inflight.example.com", "b.inflight.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		})
	})
}
