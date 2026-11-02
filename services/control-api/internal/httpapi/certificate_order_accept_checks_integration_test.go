package httpapi

// 调度只能判失败的申请在受理时就拒绝，并给出要改的域名：
// DNS-01 所选 DNS API 没有覆盖域名的解析域 → 422 certificate_dns_zone_unavailable（字段 dns_provider_id）；
// HTTP-01 域名不是在用站点或没有服务节点 → 422 certificate_http01_not_serving（字段 domains）；
// 解析指向别处只在受理结果里带 dns_warnings。

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestCertificateOrderAcceptChecks(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind)
		SELECT gen_random_uuid(),'platform' WHERE NOT EXISTS(SELECT 1 FROM access_scopes WHERE kind='platform')`); err != nil {
		t.Fatal(err)
	}
	tenant := insertDNSTenant(t, pool, "accept-tenant", "accept-user", passwordHash, []string{
		"dns.read", "certificates.read", "certificates.manage",
	})
	tokens, err := identity.NewTokenManager("accept-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("accept-test-v1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	leaseKey := newSiteTestKey(t, "accept-test-key")
	trust := newSiteTestTrust(t, leaseKey)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{
		serial: 1, limit: 100, key: leaseKey, extraFeatures: []string{entitlementguard.FeatureCertificatesIssue},
	})
	// The HTTP-01 rule itself is acmehttp01.OrderReadiness (its own test); here
	// only what the API does with its answer.
	readiness := func(_ context.Context, _ pgx.Tx, scopeID uuid.UUID, domains []string) (string, []string, error) {
		if scopeID != tenant.scopeID {
			t.Errorf("readiness scope = %s", scopeID)
		}
		var elsewhere []string
		for _, domain := range domains {
			switch domain {
			case "nosite.example.com":
				return domain, nil, nil
			case "elsewhere.example.com":
				elsewhere = append(elsewhere, domain)
			}
		}
		return "", elsewhere, nil
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x53}, 32),
		CookieSecure: false, DNSCredentialCipher: cipher, EntitlementTrust: trust, CertificateHTTP01Readiness: readiness,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	token := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID).AccessToken

	providerID := uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,status,
			created_by_user_id,updated_by_user_id) VALUES($1,$2,'my cloudflare','cloudflare','accept-test-v1',$3,'verified',$4,$4)`,
			[]any{providerID, tenant.scopeID, bytes.Repeat([]byte{1}, 32), tenant.userID}},
		{`INSERT INTO dns_zones(id,scope_id,provider_id,name,created_by_user_id,updated_by_user_id)
			VALUES($1,$2,$3,'cdn.example.net',$4,$4)`, []any{uuid.New(), tenant.scopeID, providerID, tenant.userID}},
	} {
		if _, err := pool.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	refusal := func(t *testing.T, key string, body createCertificateOrderRequest, code, field string) string {
		t.Helper()
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/certificate-orders", body, token, key, "")
		defer response.Body.Close()
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Domain  string `json:"domain"`
				Details struct {
					Field  string `json:"field"`
					Reason string `json:"reason"`
				} `json:"details"`
			} `json:"error"`
		}
		if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil || response.StatusCode != http.StatusUnprocessableEntity ||
			envelope.Error.Code != code || envelope.Error.Details.Field != field || envelope.Error.Details.Reason != "invalid" {
			t.Fatalf("status=%d envelope=%+v err=%v", response.StatusCode, envelope, err)
		}
		return envelope.Error.Domain
	}
	orders := func() int {
		var n int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM certificate_orders WHERE scope_id=$1`, tenant.scopeID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("dns-01 without a zone for the domain is refused", func(t *testing.T) {
		domain := refusal(t, "accept-zone", createCertificateOrderRequest{DNSProviderID: providerID.String(),
			Domains: []string{"tenant.example.com", "*.tenant.example.com"}, ChallengeType: "dns-01", AutoRenew: true},
			"certificate_dns_zone_unavailable", "dns_provider_id")
		if domain != "tenant.example.com" || orders() != 0 {
			t.Fatalf("domain=%q orders=%d", domain, orders())
		}
		// One zone must cover every domain: the second one is named.
		domain = refusal(t, "accept-zone-mixed", createCertificateOrderRequest{DNSProviderID: providerID.String(),
			Domains: []string{"a.cdn.example.net", "tenant.example.com"}, ChallengeType: "dns-01", AutoRenew: true},
			"certificate_dns_zone_unavailable", "dns_provider_id")
		if domain != "tenant.example.com" {
			t.Fatalf("mixed domain=%q", domain)
		}
		order := createCertificateOrder(t, client, server.URL, token, "accept-zone-ok", createCertificateOrderRequest{
			DNSProviderID: providerID.String(), Domains: []string{"*.cdn.example.net", "cdn.example.net"},
			ChallengeType: "dns-01", AutoRenew: true,
		})
		if order.Status != "pending" || len(order.DNSWarnings) != 0 {
			t.Fatalf("covered order = %+v", order)
		}
	})

	t.Run("http-01 needs a served site and warns when DNS points elsewhere", func(t *testing.T) {
		before := orders()
		if domain := refusal(t, "accept-http01", createCertificateOrderRequest{
			Domains: []string{"ok.example.com", "nosite.example.com"}, ChallengeType: "http-01", AutoRenew: true},
			"certificate_http01_not_serving", "domains"); domain != "nosite.example.com" || orders() != before {
			t.Fatalf("domain=%q orders=%d", domain, orders())
		}
		order := createCertificateOrder(t, client, server.URL, token, "accept-http01-warn", createCertificateOrderRequest{
			Domains: []string{"ok.example.com", "elsewhere.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		})
		if order.Status != "pending" || !slices.Equal(order.DNSWarnings, []string{"elsewhere.example.com"}) {
			t.Fatalf("warned order = %+v", order)
		}
		// The idempotent replay returns the same warnings.
		replay := createCertificateOrder(t, client, server.URL, token, "accept-http01-warn", createCertificateOrderRequest{
			Domains: []string{"ok.example.com", "elsewhere.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		})
		if replay.ID != order.ID || !slices.Equal(replay.DNSWarnings, order.DNSWarnings) {
			t.Fatalf("replay = %+v", replay)
		}
	})
}
