package errorpagecontrol

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard/guardtest"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestVerifiedLeaseLimitsMapValidLeaseAndApplyHardBounds(t *testing.T) {
	lease := verifiedLeaseForLimits(time.Now().UTC(), 1)
	setVerifiedLeaseQuota(&lease, entitlement.QuotaErrorPageAssetBytes, MaxEdgeResourceBytes+1)
	setVerifiedLeaseQuota(&lease, entitlement.QuotaErrorPageAssetsCount, 17)
	setVerifiedLeaseQuota(&lease, entitlement.QuotaErrorPageTotalBytes, 32<<20)
	setVerifiedLeaseQuota(&lease, entitlement.QuotaErrorPageRulesPerScope, MaxEdgeRulesPerScope+1)
	setVerifiedLeaseQuota(&lease, entitlement.QuotaErrorPagePublicationSites, MaxPublicationSites+1)
	setVerifiedLeaseQuota(&lease, entitlement.QuotaErrorPagePublicationBytes, MaxEdgePolicyBytes+1)

	limits, err := limitsFromVerifiedLease(entitlement.Result{Lease: lease, Status: entitlement.StatusValid})
	if err != nil {
		t.Fatalf("limitsFromVerifiedLease() error = %v", err)
	}
	want := EntitlementLimits{
		FeatureEnabled: true,
		AssetQuota: AssetQuota{
			MaxAssetBytes: MaxEdgeResourceBytes,
			MaxAssets:     17,
			MaxTotalBytes: 32 << 20,
		},
		MaxRulesPerScope:    MaxEdgeRulesPerScope,
		MaxPublicationSites: MaxPublicationSites,
		MaxPublicationBytes: MaxEdgePolicyBytes,
	}
	if limits != want {
		t.Fatalf("limitsFromVerifiedLease() = %#v, want %#v", limits, want)
	}
}

func TestVerifiedLeaseLimitsRejectIntOverflowBeforeConversion(t *testing.T) {
	if uint64(^uint(0)>>1) >= uint64(entitlement.MaxQuotaLimit) {
		t.Skip("the verified lease quota range fits in int on this architecture")
	}
	lease := verifiedLeaseForLimits(time.Now().UTC(), 1)
	setVerifiedLeaseQuota(&lease, entitlement.QuotaErrorPageRulesPerScope, entitlement.MaxQuotaLimit)

	_, err := limitsFromVerifiedLease(entitlement.Result{Lease: lease, Status: entitlement.StatusValid})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("int overflow error = %v, want ErrUnavailable", err)
	}
}

func TestVerifiedLeaseLimitsAllowGrace(t *testing.T) {
	now := time.Now().UTC()
	limits, err := limitsFromVerifiedLease(entitlement.Result{Lease: verifiedLeaseForLimits(now, 1), Status: entitlement.StatusGrace})
	if err != nil || !limits.FeatureEnabled {
		t.Fatalf("grace limits = (%#v, %v), want lease limits", limits, err)
	}
}

func TestVerifiedLeaseLimitsRejectNonValidIncompleteAndUnknownResults(t *testing.T) {
	now := time.Now().UTC()
	for _, status := range []entitlement.Status{
		entitlement.StatusExpired, entitlement.StatusRevoked,
	} {
		t.Run(string(status), func(t *testing.T) {
			_, err := limitsFromVerifiedLease(entitlement.Result{Lease: verifiedLeaseForLimits(now, 1), Status: status})
			if !errors.Is(err, ErrEntitlementDenied) {
				t.Fatalf("status %s error = %v, want ErrEntitlementDenied", status, err)
			}
		})
	}

	t.Run("missing feature", func(t *testing.T) {
		lease := verifiedLeaseForLimits(now, 1)
		lease.Features = nil
		_, err := limitsFromVerifiedLease(entitlement.Result{Lease: lease, Status: entitlement.StatusValid})
		if !errors.Is(err, ErrEntitlementDenied) {
			t.Fatalf("missing feature error = %v, want ErrEntitlementDenied", err)
		}
	})

	quotaCodes := []string{
		entitlement.QuotaErrorPageAssetBytes,
		entitlement.QuotaErrorPageAssetsCount,
		entitlement.QuotaErrorPagePublicationBytes,
		entitlement.QuotaErrorPagePublicationSites,
		entitlement.QuotaErrorPageRulesPerScope,
		entitlement.QuotaErrorPageTotalBytes,
	}
	for _, code := range quotaCodes {
		t.Run("missing "+code, func(t *testing.T) {
			lease := verifiedLeaseForLimits(now, 1)
			lease.Quotas = removeVerifiedLeaseQuota(lease.Quotas, code)
			_, err := limitsFromVerifiedLease(entitlement.Result{Lease: lease, Status: entitlement.StatusValid})
			if !errors.Is(err, ErrEntitlementDenied) {
				t.Fatalf("missing %s error = %v, want ErrEntitlementDenied", code, err)
			}
		})
		t.Run("zero "+code, func(t *testing.T) {
			lease := verifiedLeaseForLimits(now, 1)
			setVerifiedLeaseQuota(&lease, code, 0)
			_, err := limitsFromVerifiedLease(entitlement.Result{Lease: lease, Status: entitlement.StatusValid})
			if !errors.Is(err, ErrEntitlementDenied) {
				t.Fatalf("zero %s error = %v, want ErrEntitlementDenied", code, err)
			}
		})
	}

	t.Run("unknown quota", func(t *testing.T) {
		lease := verifiedLeaseForLimits(now, 1)
		lease.Quotas = append(lease.Quotas, entitlement.Quota{Code: "unknown.quota", Limit: 1})
		_, err := limitsFromVerifiedLease(entitlement.Result{Lease: lease, Status: entitlement.StatusValid})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("unknown quota error = %v, want ErrUnavailable", err)
		}
	})
}

func TestNewVerifiedLeaseLimitProviderRejectsInvalidDependencies(t *testing.T) {
	pool := new(pgxpool.Pool)
	if provider, err := NewVerifiedLeaseLimitProvider(nil, nil, time.Now); provider != nil || !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewVerifiedLeaseLimitProvider(nil pool) = (%T,%v)", provider, err)
	}
	if provider, err := NewVerifiedLeaseLimitProvider(pool, nil, time.Now); provider != nil || !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewVerifiedLeaseLimitProvider(nil trust) = (%T,%v)", provider, err)
	}
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: "limits-key", PublicKey: publicKey}})
	if err != nil {
		t.Fatal(err)
	}
	if provider, err := NewVerifiedLeaseLimitProvider(pool, trust, nil); provider != nil || !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewVerifiedLeaseLimitProvider(nil clock) = (%T,%v)", provider, err)
	}
	var provider *VerifiedLeaseLimitProvider
	if _, err := provider.Limits(t.Context(), nil, EntitlementCheck{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("typed nil provider error = %v, want ErrUnavailable", err)
	}
	configured, err := NewVerifiedLeaseLimitProvider(pool, trust, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configured.Limits(t.Context(), nil, EntitlementCheck{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil transaction error = %v, want ErrUnavailable", err)
	}
}

func TestVerifiedLeaseLimitProviderVerifiesCachedLeaseInCallerTransaction(t *testing.T) {
	fixture := newVerifiedLeaseLimitFixture(t)
	provider, err := NewVerifiedLeaseLimitProvider(fixture.database.pool, fixture.trust, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	replacement := fixture.lease
	setVerifiedLeaseQuota(&replacement, entitlement.QuotaErrorPageAssetsCount, 29)
	encoded := encodeVerifiedLease(t, signVerifiedLease(t, replacement, fixture.signer))
	if _, err := tx.Exec(t.Context(), `UPDATE entitlement_cached_leases SET signed_lease=$1 WHERE serial=$2`,
		encoded, int64(replacement.Serial)); err != nil {
		t.Fatal(err)
	}
	limits, err := provider.Limits(t.Context(), tx, EntitlementCheck{Expands: true})
	if err != nil || limits.AssetQuota.MaxAssets != 29 {
		t.Fatalf("Limits(uncommitted cache) = (%#v,%v), want assets=29", limits, err)
	}
	var persisted []byte
	if err := fixture.database.pool.QueryRow(t.Context(),
		`SELECT signed_lease FROM entitlement_cached_leases WHERE serial=$1`, int64(replacement.Serial)).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	outside, err := entitlement.Decode(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := outside.Lease.Quota(entitlement.QuotaErrorPageAssetsCount); value != 10 {
		t.Fatalf("outside transaction observed uncommitted quota %d", value)
	}
}

func TestVerifiedLeaseLimitProviderLocksInstallationInCallerTransaction(t *testing.T) {
	fixture := newVerifiedLeaseLimitFixture(t)
	provider, err := NewVerifiedLeaseLimitProvider(fixture.database.pool, fixture.trust, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	locked, err := fixture.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Rollback(context.Background())
	if _, err := provider.Limits(t.Context(), locked, EntitlementCheck{Expands: true}); err != nil {
		t.Fatal(err)
	}

	contender, err := fixture.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer contender.Rollback(context.Background())
	if _, err := contender.Exec(t.Context(), `SET LOCAL lock_timeout = '100ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = contender.Exec(t.Context(),
		`UPDATE control_installation_entitlement SET updated_at=updated_at WHERE singleton=true`)
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "55P03" {
		t.Fatalf("contending update error = %v, want lock timeout 55P03", err)
	}
}

func TestVerifiedLeaseLimitProviderRejectsExpiredMissingAndInvalidCache(t *testing.T) {
	t.Run("missing LKG", func(t *testing.T) {
		database := openErrorPageDatabase(t)
		publicKey, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: "missing-key", PublicKey: publicKey}})
		if err != nil {
			t.Fatal(err)
		}
		provider, err := NewVerifiedLeaseLimitProvider(database.pool, trust, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		assertVerifiedLeaseProviderError(t, database, provider, ErrUnavailable)
	})

	t.Run("expired", func(t *testing.T) {
		fixture := newVerifiedLeaseLimitFixture(t)
		provider, err := NewVerifiedLeaseLimitProvider(fixture.database.pool, fixture.trust,
			func() time.Time { return fixture.now.Add(3 * time.Hour) })
		if err != nil {
			t.Fatal(err)
		}
		assertVerifiedLeaseProviderError(t, fixture.database, provider, ErrEntitlementDenied)
	})

	corruptions := map[string]func(*testing.T, verifiedLeaseLimitFixture) []byte{
		"invalid envelope": func(_ *testing.T, _ verifiedLeaseLimitFixture) []byte { return []byte("{") },
		"invalid signature": func(t *testing.T, fixture verifiedLeaseLimitFixture) []byte {
			signed := signVerifiedLease(t, fixture.lease, fixture.signer)
			signed.Lease.Quotas[1].Limit++
			return encodeVerifiedLease(t, signed)
		},
		"wrong audience": func(t *testing.T, fixture verifiedLeaseLimitFixture) []byte {
			lease := fixture.lease
			lease.Audience = "another-control-plane"
			return encodeVerifiedLease(t, signVerifiedLease(t, lease, fixture.signer))
		},
		"wrong installation": func(t *testing.T, fixture verifiedLeaseLimitFixture) []byte {
			lease := fixture.lease
			lease.InstallationID = "another-installation"
			return encodeVerifiedLease(t, signVerifiedLease(t, lease, fixture.signer))
		},
		"unknown quota": func(t *testing.T, fixture verifiedLeaseLimitFixture) []byte {
			signed := signVerifiedLease(t, fixture.lease, fixture.signer)
			signed.Lease.Quotas = append(signed.Lease.Quotas, entitlement.Quota{Code: "unknown.quota", Limit: 1})
			encoded, err := json.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}
			return encoded
		},
	}
	for name, corrupt := range corruptions {
		t.Run(name, func(t *testing.T) {
			fixture := newVerifiedLeaseLimitFixture(t)
			if _, err := fixture.database.pool.Exec(t.Context(),
				`UPDATE entitlement_cached_leases SET signed_lease=$1 WHERE serial=$2`,
				corrupt(t, fixture), int64(fixture.lease.Serial)); err != nil {
				t.Fatal(err)
			}
			provider, err := NewVerifiedLeaseLimitProvider(fixture.database.pool, fixture.trust, func() time.Time { return fixture.now })
			if err != nil {
				t.Fatal(err)
			}
			assertVerifiedLeaseProviderError(t, fixture.database, provider, ErrUnavailable)
		})
	}
}

// Grace keeps error pages manageable while the license service is unreachable;
// it yields the lease limits and no reject audit.
func TestVerifiedLeaseLimitProviderAllowsGrace(t *testing.T) {
	fixture := newVerifiedLeaseLimitFixture(t)
	_, scopeID := seedPlatformActor(t, fixture.database.pool)
	provider, err := NewVerifiedLeaseLimitProvider(
		fixture.database.pool, fixture.trust, func() time.Time { return fixture.now.Add(90 * time.Minute) },
	)
	if err != nil {
		t.Fatal(err)
	}
	assertVerifiedLeaseProviderCheckError(t, fixture.database, provider,
		EntitlementCheck{Operation: operationAssetInitiate, ScopeID: scopeID, Expands: true}, nil)
	var count int
	if err := fixture.database.pool.QueryRow(t.Context(), `
		SELECT count(*) FROM audit_events WHERE action='entitlement.guard.reject'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("grace reject audit count = %d, want 0", count)
	}
}

func TestVerifiedLeaseLimitProviderValidDoesNotEmitRejectAudit(t *testing.T) {
	fixture := newVerifiedLeaseLimitFixture(t)
	_, scopeID := seedPlatformActor(t, fixture.database.pool)
	provider, err := NewVerifiedLeaseLimitProvider(
		fixture.database.pool, fixture.trust, func() time.Time { return fixture.now },
	)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Limits(t.Context(), tx, EntitlementCheck{
		Operation: operationAssetInitiate, ScopeID: scopeID, Expands: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := fixture.database.pool.QueryRow(t.Context(), `
		SELECT count(*) FROM audit_events WHERE action='entitlement.guard.reject'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("valid reject audit count = %d, want 0", count)
	}
}

type verifiedLeaseLimitFixture struct {
	database integrationFixture
	trust    *entitlementguard.TrustStore
	signer   verifiedLeaseSigner
	lease    entitlement.Lease
	now      time.Time
}

type verifiedLeaseSigner struct {
	keyID   string
	private ed25519.PrivateKey
}

func (signer verifiedLeaseSigner) KeyID() string { return signer.keyID }

func (signer verifiedLeaseSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func newVerifiedLeaseLimitFixture(t *testing.T) verifiedLeaseLimitFixture {
	t.Helper()
	database := openErrorPageDatabase(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := verifiedLeaseSigner{keyID: "error-page-limit-key", private: privateKey}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: signer.keyID, PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	lease := verifiedLeaseForLimits(now, 1)
	guardtest.AcceptRevocation(t, database.pool, trust, signer, lease, now)
	signed := signVerifiedLease(t, lease, signer)
	if _, err := entitlementguard.NewService(database.pool, trust).Install(t.Context(), entitlementguard.InstallBundle{
		InstallationID: lease.InstallationID,
		SignedLease:    signed,
	}, now); err != nil {
		t.Fatalf("install cached lease: %v", err)
	}
	return verifiedLeaseLimitFixture{database: database, trust: trust, signer: signer, lease: lease, now: now}
}

func verifiedLeaseForLimits(now time.Time, serial uint64) entitlement.Lease {
	return entitlement.Lease{
		Schema:   entitlement.SchemaV1,
		Audience: entitlement.ControlAudience,
		// Canonical UUIDs: revocation sets only accept those (libs/entitlement/revocation.go).
		CustomerID:     "77777777-7777-4777-8777-777777777777",
		InstallationID: "88888888-8888-4888-8888-888888888888",
		LicenseID:      "99999999-9999-4999-8999-999999999999",
		Serial:         serial,
		NotBefore:      now.Add(-time.Hour).Unix(),
		ExpiresAt:      now.Add(time.Hour).Unix(),
		GraceUntil:     now.Add(2 * time.Hour).Unix(),
		Version:        entitlement.VersionRange{Channel: "stable", Min: "1.0.0", Max: "2.0.0"},
		Features:       []entitlement.Feature{{Code: entitlement.FeatureErrorPagesManage}},
		Quotas: []entitlement.Quota{
			{Code: entitlement.QuotaErrorPageAssetBytes, Limit: MaxEdgeResourceBytes},
			{Code: entitlement.QuotaErrorPageAssetsCount, Limit: 10},
			{Code: entitlement.QuotaErrorPagePublicationBytes, Limit: MaxEdgePolicyBytes},
			{Code: entitlement.QuotaErrorPagePublicationSites, Limit: MaxPublicationSites},
			{Code: entitlement.QuotaErrorPageRulesPerScope, Limit: MaxEdgeRulesPerScope},
			{Code: entitlement.QuotaErrorPageTotalBytes, Limit: 16 << 20},
		},
	}
}

func setVerifiedLeaseQuota(lease *entitlement.Lease, code string, limit int64) {
	for index := range lease.Quotas {
		if lease.Quotas[index].Code == code {
			lease.Quotas[index].Limit = limit
			return
		}
	}
}

func removeVerifiedLeaseQuota(quotas []entitlement.Quota, code string) []entitlement.Quota {
	result := make([]entitlement.Quota, 0, len(quotas)-1)
	for _, quota := range quotas {
		if quota.Code != code {
			result = append(result, quota)
		}
	}
	return result
}

func signVerifiedLease(t *testing.T, lease entitlement.Lease, signer verifiedLeaseSigner) entitlement.SignedLease {
	t.Helper()
	signed, err := entitlement.Sign(t.Context(), lease, signer)
	if err != nil {
		t.Fatalf("sign lease: %v", err)
	}
	return signed
}

func encodeVerifiedLease(t *testing.T, signed entitlement.SignedLease) []byte {
	t.Helper()
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatalf("encode lease: %v", err)
	}
	return encoded
}

func assertVerifiedLeaseProviderError(
	t *testing.T,
	database integrationFixture,
	provider *VerifiedLeaseLimitProvider,
	want error,
) {
	t.Helper()
	assertVerifiedLeaseProviderCheckError(t, database, provider, EntitlementCheck{Expands: true}, want)
}

func assertVerifiedLeaseProviderCheckError(
	t *testing.T,
	database integrationFixture,
	provider *VerifiedLeaseLimitProvider,
	check EntitlementCheck,
	want error,
) {
	t.Helper()
	err := pgx.BeginFunc(t.Context(), database.pool, func(tx pgx.Tx) error {
		_, limitErr := provider.Limits(t.Context(), tx, check)
		return limitErr
	})
	if !errors.Is(err, want) {
		t.Fatalf("Limits() error = %v, want %v", err, want)
	}
}
