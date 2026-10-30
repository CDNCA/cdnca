package httpapi

// CERT-04（fp-cert2）：订单签发机构冻结、未配置 EAB 的 CA 返回 409、用户默认签发机构往返。
// 需要 PG（TEST_DATABASE_URL），待出包前全量跑。

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certdefaults"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestCertificateOrderIssuerFrozenAndDefaultsRoundTrip(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	// The platform default issuer is read from the platform scope, which every
	// installation has (bootstrap); the bare test database starts without one.
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind)
		SELECT gen_random_uuid(),'platform' WHERE NOT EXISTS(SELECT 1 FROM access_scopes WHERE kind='platform')`); err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	tenant := insertDNSTenant(t, pool, "issuer-tenant", "issuer-user", passwordHash, []string{
		"dns.read", "certificates.read", "certificates.manage",
	})
	tokens, err := identity.NewTokenManager("issuer-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("issuer-test-v1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	leaseKey := newSiteTestKey(t, "issuer-test-key")
	trust := newSiteTestTrust(t, leaseKey)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{
		serial: 1, limit: 100, key: leaseKey, extraFeatures: []string{entitlementguard.FeatureCertificatesIssue},
	})
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x53}, 32),
		CookieSecure: false, DNSCredentialCipher: cipher, EntitlementTrust: trust,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	auth := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)
	token := auth.AccessToken

	issuerOf := func(order dnsacme.CertificateOrder) string {
		if order.Issuer == nil {
			return ""
		}
		return *order.Issuer
	}

	t.Run("only configured CAs are offered", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/certificate-issuers", nil, token, "", "")
		var list struct {
			Items   []string `json:"items"`
			Default string   `json:"default"`
		}
		decodeResponse(t, response, http.StatusOK, &list)
		response.Body.Close()
		if len(list.Items) != 1 || list.Items[0] != "lets_encrypt" {
			t.Fatalf("issuers without EAB = %#v, want only lets_encrypt", list)
		}
	})

	t.Run("a CA without platform EAB is refused with 409 and nothing is created", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/certificate-orders", createCertificateOrderRequest{
			Domains: []string{"zerossl.example.com"}, ChallengeType: "http-01", AutoRenew: true, Issuer: "zerossl",
		}, token, "issuer-zerossl-unconfigured", "")
		assertError(t, response, http.StatusConflict, "certificate_issuer_unavailable", "")
		response.Body.Close()
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM certificate_orders WHERE scope_id=$1`, tenant.scopeID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("refused order left %d rows", count)
		}
	})

	explicit := createCertificateOrder(t, client, server.URL, token, "issuer-explicit", createCertificateOrderRequest{
		Domains: []string{"explicit.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		Issuer: "lets_encrypt", Name: "explicit", Remark: "frozen",
	})
	t.Run("the explicit issuer is frozen on the order", func(t *testing.T) {
		if issuerOf(explicit) != "lets_encrypt" {
			t.Fatalf("explicit order issuer = %q", issuerOf(explicit))
		}
		// 517 保护触发器：建单后签发机构、名称、备注不可改（P5171）
		_, err := pool.Exec(context.Background(), `UPDATE certificate_orders SET issuer='zerossl' WHERE id=$1`, explicit.ID)
		assertIssuerPGCode(t, err, "P5171")
		_, err = pool.Exec(context.Background(), `UPDATE certificate_orders SET remark='changed' WHERE id=$1`, explicit.ID)
		assertIssuerPGCode(t, err, "P5171")
	})

	t.Run("no issuer and no user default leaves the platform default (NULL)", func(t *testing.T) {
		order := createCertificateOrder(t, client, server.URL, token, "issuer-platform-default", createCertificateOrderRequest{
			Domains: []string{"platform.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		})
		if order.Issuer != nil {
			t.Fatalf("order without issuer froze %q", *order.Issuer)
		}
	})

	t.Run("the user default issuer round-trips and applies to new orders", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/certificate-defaults", nil, token, "", "")
		var initial certdefaults.Defaults
		decodeResponse(t, response, http.StatusOK, &initial)
		response.Body.Close()
		if initial.Issuer != nil {
			t.Fatalf("initial default issuer = %q", *initial.Issuer)
		}

		letsEncrypt, zerossl := "lets_encrypt", "zerossl"
		// 未配置 EAB 的 CA 保存默认设置时就 409（与建单同一规则），不写库、版本不变
		response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/certificate-defaults", certificateDefaultsRequest{
			CertificateType: "acme", Issuer: &zerossl, ExpectedRevision: initial.Revision,
		}, token, "defaults-zerossl", "")
		assertError(t, response, http.StatusConflict, "certificate_issuer_unavailable", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodGet, server.URL+"/v1/certificate-defaults", nil, token, "", "")
		var refused certdefaults.Defaults
		decodeResponse(t, response, http.StatusOK, &refused)
		response.Body.Close()
		if refused.Issuer != nil || refused.Revision != initial.Revision {
			t.Fatalf("refused zerossl default was stored: %#v", refused)
		}

		response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/certificate-defaults", certificateDefaultsRequest{
			CertificateType: "acme", Issuer: &letsEncrypt, ExpectedRevision: initial.Revision,
		}, token, "defaults-lets-encrypt", "")
		var saved certdefaults.Defaults
		decodeResponse(t, response, http.StatusOK, &saved)
		response.Body.Close()
		if saved.Issuer == nil || *saved.Issuer != letsEncrypt || saved.Revision != initial.Revision+1 {
			t.Fatalf("saved defaults = %#v", saved)
		}

		response = siteRequest(t, client, http.MethodGet, server.URL+"/v1/certificate-defaults", nil, token, "", "")
		var reread certdefaults.Defaults
		decodeResponse(t, response, http.StatusOK, &reread)
		response.Body.Close()
		if reread.Issuer == nil || *reread.Issuer != letsEncrypt || reread.Revision != saved.Revision {
			t.Fatalf("reread defaults = %#v", reread)
		}

		order := createCertificateOrder(t, client, server.URL, token, "issuer-from-default", createCertificateOrderRequest{
			Domains: []string{"default.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		})
		if issuerOf(order) != letsEncrypt {
			t.Fatalf("order from default issuer = %q, want %q", issuerOf(order), letsEncrypt)
		}

		// 上传类型的默认设置不带签发机构；之后新订单回到平台默认
		response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/certificate-defaults", certificateDefaultsRequest{
			CertificateType: "uploaded", Issuer: &letsEncrypt, ExpectedRevision: saved.Revision,
		}, token, "defaults-uploaded", "")
		var uploaded certdefaults.Defaults
		decodeResponse(t, response, http.StatusOK, &uploaded)
		response.Body.Close()
		if uploaded.Issuer != nil || uploaded.CertificateType != "uploaded" {
			t.Fatalf("uploaded defaults = %#v", uploaded)
		}
		order = createCertificateOrder(t, client, server.URL, token, "issuer-after-uploaded-default", createCertificateOrderRequest{
			Domains: []string{"after.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		})
		if order.Issuer != nil {
			t.Fatalf("order after uploaded default froze %q", *order.Issuer)
		}
	})
}

func assertIssuerPGCode(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("error = %v, want SQLSTATE %s", err, code)
	}
}
