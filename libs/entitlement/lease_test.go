package entitlement

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
	"time"
)

type errorPageSigner struct {
	private ed25519.PrivateKey
}

func (signer errorPageSigner) KeyID() string { return "error-page-key-1" }

func (signer errorPageSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func TestErrorPageEntitlementVocabulary(t *testing.T) {
	if FeatureErrorPagesManage != "error_pages.manage" {
		t.Fatalf("FeatureErrorPagesManage = %q", FeatureErrorPagesManage)
	}
	codes := []string{
		QuotaErrorPageAssetBytes,
		QuotaErrorPageAssetsCount,
		QuotaErrorPagePublicationBytes,
		QuotaErrorPagePublicationSites,
		QuotaErrorPageRulesPerScope,
		QuotaErrorPageTotalBytes,
	}
	want := []string{
		"error_pages.asset_bytes",
		"error_pages.assets_count",
		"error_pages.publication_bytes",
		"error_pages.publication_sites",
		"error_pages.rules_per_scope",
		"error_pages.total_bytes",
	}
	if !reflect.DeepEqual(codes, want) {
		t.Fatalf("error-page quota codes = %#v, want %#v", codes, want)
	}
	for _, code := range codes {
		if !IsSupportedQuotaCode(code) {
			t.Fatalf("IsSupportedQuotaCode(%q) = false", code)
		}
	}
	if IsSupportedQuotaCode("error_pages.unknown") {
		t.Fatal("unknown error-page quota must fail closed")
	}
	if err := ValidatePolicy(errorPageVersion(), []Feature{{Code: FeatureErrorPagesManage}}, nil); err != nil {
		t.Fatalf("ValidatePolicy(error-page feature) error = %v", err)
	}
}

func TestErrorPageQuotaPolicyBoundariesAndOrdering(t *testing.T) {
	allCodes := []string{
		QuotaDomainsCount,
		QuotaErrorPageAssetBytes,
		QuotaErrorPageAssetsCount,
		QuotaErrorPagePublicationBytes,
		QuotaErrorPagePublicationSites,
		QuotaErrorPageRulesPerScope,
		QuotaErrorPageTotalBytes,
		QuotaExtensionsWebhooksCount,
		QuotaMonthlyTrafficBytes,
		QuotaNodesCount,
		QuotaPackagesCount,
		QuotaReleaseChannelsCount,
		QuotaSitesCount,
	}
	want := []string{
		"domains.count",
		"error_pages.asset_bytes",
		"error_pages.assets_count",
		"error_pages.publication_bytes",
		"error_pages.publication_sites",
		"error_pages.rules_per_scope",
		"error_pages.total_bytes",
		"extensions.webhooks.count",
		"monthly_traffic_bytes",
		"nodes.count",
		"packages.count",
		"release_channels.count",
		"sites.count",
	}
	if !reflect.DeepEqual(allCodes, want) {
		t.Fatalf("canonical quota vocabulary = %#v, want %#v", allCodes, want)
	}
	quotas := errorPageQuotas()
	quotas[0].Limit = 0
	quotas[len(quotas)-1].Limit = MaxQuotaLimit
	if err := ValidatePolicy(errorPageVersion(), nil, quotas); err != nil {
		t.Fatalf("ValidatePolicy(boundaries) error = %v", err)
	}

	cases := []struct {
		name   string
		mutate func([]Quota) []Quota
	}{
		{name: "negative", mutate: func(values []Quota) []Quota { values[0].Limit = -1; return values }},
		{name: "unsafe integer", mutate: func(values []Quota) []Quota { values[0].Limit = MaxQuotaLimit + 1; return values }},
		{name: "duplicate", mutate: func(values []Quota) []Quota { return append(values, values[len(values)-1]) }},
		{name: "unsorted", mutate: func(values []Quota) []Quota { values[0], values[1] = values[1], values[0]; return values }},
		{name: "unknown", mutate: func(values []Quota) []Quota { values[0].Code = "error_pages.unknown"; return values }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidatePolicy(errorPageVersion(), nil, test.mutate(errorPageQuotas())); !errors.Is(err, ErrInvalidLease) {
				t.Fatalf("ValidatePolicy() error = %v", err)
			}
		})
	}
}

func TestExtensionsWebhookEntitlementVocabularyAndOrdering(t *testing.T) {
	if FeatureExtensionsWebhooks != "extensions.webhooks" {
		t.Fatalf("FeatureExtensionsWebhooks = %q", FeatureExtensionsWebhooks)
	}
	if QuotaExtensionsWebhooksCount != "extensions.webhooks.count" {
		t.Fatalf("QuotaExtensionsWebhooksCount = %q", QuotaExtensionsWebhooksCount)
	}
	featureCode := FeatureExtensionsWebhooks
	quotaCode := QuotaExtensionsWebhooksCount
	if !IsSupportedQuotaCode(quotaCode) {
		t.Fatalf("IsSupportedQuotaCode(%q) = false", quotaCode)
	}
	version := VersionRange{Channel: "stable", Min: "5.8.0", Max: "5.9.0"}
	features := []Feature{{Code: FeatureErrorPagesManage}, {Code: featureCode}}
	quotas := []Quota{
		{Code: QuotaErrorPageTotalBytes, Limit: 10},
		{Code: quotaCode, Limit: 20},
		{Code: QuotaMonthlyTrafficBytes, Limit: 30},
	}
	if err := ValidatePolicy(version, features, quotas); err != nil {
		t.Fatalf("ValidatePolicy(webhook vocabulary) error = %v", err)
	}
	for _, test := range []struct {
		name     string
		features []Feature
		quotas   []Quota
	}{
		{name: "features unsorted", features: []Feature{{Code: featureCode}, {Code: FeatureErrorPagesManage}}, quotas: quotas},
		{name: "features duplicate", features: []Feature{{Code: featureCode}, {Code: featureCode}}, quotas: quotas},
		{name: "quotas unsorted", features: features, quotas: []Quota{{Code: quotaCode, Limit: 1}, {Code: QuotaErrorPageTotalBytes, Limit: 1}}},
		{name: "quotas duplicate", features: features, quotas: []Quota{{Code: quotaCode, Limit: 1}, {Code: quotaCode, Limit: 1}}},
		{name: "quota unknown", features: features, quotas: []Quota{{Code: "extensions.webhooks.unknown", Limit: 1}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidatePolicy(version, test.features, test.quotas); !errors.Is(err, ErrInvalidLease) {
				t.Fatalf("ValidatePolicy() error = %v", err)
			}
		})
	}
}

func TestExtensionsWebhookLeaseCanonicalRoundTripAndVerification(t *testing.T) {
	featureCode := FeatureExtensionsWebhooks
	quotaCode := QuotaExtensionsWebhooksCount
	now := time.Unix(1_900_200_000, 0).UTC()
	private := ed25519.NewKeyFromSeed([]byte("webhook-lease-key-seed-32-bytes!"))
	lease := errorPageLease(now)
	lease.Features = append(lease.Features, Feature{Code: featureCode})
	lease.Quotas = append(lease.Quotas, Quota{Code: quotaCode, Limit: 107})
	signer := errorPageSigner{private: private}
	signed, err := Sign(context.Background(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := decoded.Encode()
	if err != nil || !reflect.DeepEqual(encoded, reencoded) {
		t.Fatalf("webhook lease canonical roundtrip changed bytes: %v", err)
	}
	ring := NewKeyRing()
	if err := ring.Add(signer.KeyID(), private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	verified, err := ring.Verify(decoded, VerifyOptions{Now: now.Add(time.Minute), ExpectedAudience: ControlAudience, ExpectedInstallationID: lease.InstallationID})
	if err != nil || verified.Status != StatusValid || !verified.Lease.HasFeature(featureCode) {
		t.Fatalf("Verify(webhook lease) = (%#v, %v)", verified, err)
	}
	if limit, ok := verified.Lease.Quota(quotaCode); !ok || limit != 107 {
		t.Fatalf("Quota(%q) = (%d, %v), want 107", quotaCode, limit, ok)
	}

	featureTampered := decoded
	featureTampered.Lease.Features = append([]Feature(nil), decoded.Lease.Features...)
	featureTampered.Lease.Features[1].Code = "extensions.webhooks.changed"
	if _, err := ring.Verify(featureTampered, VerifyOptions{Now: now.Add(time.Minute), ExpectedAudience: ControlAudience, ExpectedInstallationID: lease.InstallationID}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(feature tamper) error = %v", err)
	}
	quotaTampered := decoded
	quotaTampered.Lease.Quotas = append([]Quota(nil), decoded.Lease.Quotas...)
	quotaTampered.Lease.Quotas[6].Limit++
	if _, err := ring.Verify(quotaTampered, VerifyOptions{Now: now.Add(time.Minute), ExpectedAudience: ControlAudience, ExpectedInstallationID: lease.InstallationID}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(quota tamper) error = %v", err)
	}
	unknown := decoded
	unknown.Lease.Quotas = append([]Quota(nil), decoded.Lease.Quotas...)
	unknown.Lease.Quotas[6].Code = "extensions.webhooks.unknown"
	if _, err := unknown.Encode(); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("Encode(unknown webhook quota) error = %v", err)
	}
}

func TestErrorPageLeaseCanonicalRoundTripAndVerification(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	private := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	lease := errorPageLease(now)
	signer := errorPageSigner{private: private}

	first, err := Sign(context.Background(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Sign(context.Background(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	firstEncoded, err := first.Encode()
	if err != nil {
		t.Fatal(err)
	}
	secondEncoded, err := second.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstEncoded, secondEncoded) {
		t.Fatal("identical error-page leases produced different bytes")
	}
	decoded, err := Decode(firstEncoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := decoded.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstEncoded, reencoded) || !reflect.DeepEqual(decoded.Lease.Quotas, lease.Quotas) {
		t.Fatal("error-page lease canonical roundtrip changed bytes or quotas")
	}

	ring := NewKeyRing()
	if err := ring.Add(signer.KeyID(), private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	verified, err := ring.Verify(decoded, VerifyOptions{Now: now.Add(time.Minute), ExpectedAudience: ControlAudience, ExpectedInstallationID: lease.InstallationID})
	if err != nil || verified.Status != StatusValid || !verified.Lease.HasFeature(FeatureErrorPagesManage) {
		t.Fatalf("Verify() = (%#v, %v)", verified, err)
	}
	for _, quota := range errorPageQuotas() {
		if limit, ok := verified.Lease.Quota(quota.Code); !ok || limit != quota.Limit {
			t.Fatalf("Quota(%q) = (%d, %v), want %d", quota.Code, limit, ok, quota.Limit)
		}
	}
}

func TestErrorPageQuotaTamperFailsVerification(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	private := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	signed, err := Sign(context.Background(), errorPageLease(now), errorPageSigner{private: private})
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyRing()
	_ = ring.Add(signed.KeyID, private.Public().(ed25519.PublicKey))
	tampered := signed
	tampered.Lease.Quotas = append([]Quota(nil), signed.Lease.Quotas...)
	tampered.Lease.Quotas[0].Limit++
	if _, err := ring.Verify(tampered, VerifyOptions{Now: now.Add(time.Minute), ExpectedAudience: ControlAudience, ExpectedInstallationID: signed.Lease.InstallationID}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(tampered) error = %v", err)
	}
	unknown := signed
	unknown.Lease.Quotas = append([]Quota(nil), signed.Lease.Quotas...)
	unknown.Lease.Quotas[0].Code = "error_pages.unknown"
	if _, err := unknown.Encode(); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("Encode(unknown quota) error = %v", err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(append([]byte(" "), encoded...)); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Decode(non-canonical) error = %v", err)
	}
}

func TestLegacyV1LeaseRoundTripRemainsCompatible(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	private := ed25519.NewKeyFromSeed([]byte("abcdef0123456789abcdef0123456789"))
	encoded := []byte(`{"algorithm":"Ed25519","key_id":"error-page-key-1","lease":{"schema":"cdnca.entitlement.lease/v1","audience":"cdnca-control-plane","customer_id":"customer-error-page","installation_id":"installation-error-page","license_id":"license-error-page","serial":7,"not_before":1900000000,"expires_at":1900003600,"grace_until":1900007200,"version":{"channel":"stable","min":"5.8.0","max":"5.9.0"},"features":[{"code":"sites.manage"}],"quotas":[{"code":"domains.count","limit":100},{"code":"nodes.count","limit":10}]},"signature":"r0nBiKEEqI_sCMPJLVdrmT_bxSbvX2UsH-q6DtWMz6wN04oeT5KCKrLAb6xa5NLC0Va3wSx8bLkh8e8d-mSDCg"}`)
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyRing()
	if err := ring.Add(decoded.KeyID, private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	verified, err := ring.Verify(decoded, VerifyOptions{
		Now: now.Add(time.Minute), ExpectedAudience: ControlAudience, ExpectedInstallationID: "installation-error-page",
	})
	if err != nil || verified.Status != StatusValid {
		t.Fatalf("Verify(legacy v1 golden) = (%#v, %v)", verified, err)
	}
	reencoded, err := decoded.Encode()
	wantQuotas := []Quota{{Code: QuotaDomainsCount, Limit: 100}, {Code: QuotaNodesCount, Limit: 10}}
	if err != nil || !reflect.DeepEqual(encoded, reencoded) || !reflect.DeepEqual(decoded.Lease.Quotas, wantQuotas) {
		t.Fatalf("legacy v1 roundtrip changed bytes or semantics: %v", err)
	}
}

func errorPageVersion() VersionRange {
	return VersionRange{Channel: "stable", Min: "5.8.0", Max: "5.9.0"}
}

func errorPageQuotas() []Quota {
	return []Quota{
		{Code: QuotaErrorPageAssetBytes, Limit: 101},
		{Code: QuotaErrorPageAssetsCount, Limit: 102},
		{Code: QuotaErrorPagePublicationBytes, Limit: 103},
		{Code: QuotaErrorPagePublicationSites, Limit: 104},
		{Code: QuotaErrorPageRulesPerScope, Limit: 105},
		{Code: QuotaErrorPageTotalBytes, Limit: 106},
	}
}

func errorPageLease(now time.Time) Lease {
	return Lease{
		Schema: SchemaV1, Audience: ControlAudience, CustomerID: "customer-error-page",
		InstallationID: "installation-error-page", LicenseID: "license-error-page", Serial: 7,
		NotBefore: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), GraceUntil: now.Add(2 * time.Hour).Unix(),
		Version: errorPageVersion(), Features: []Feature{{Code: FeatureErrorPagesManage}}, Quotas: errorPageQuotas(),
	}
}
