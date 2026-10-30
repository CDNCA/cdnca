package dashboard

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

func TestEntitlementNodeLimitReadsSignedQuota(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signed := entitlement.SignedLease{
		Algorithm: entitlement.Algorithm,
		KeyID:     "key-1",
		Lease: entitlement.Lease{
			Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
			CustomerID: "customer-1", InstallationID: "installation-1", LicenseID: "license-1", Serial: 7,
			NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), GraceUntil: now.Add(2 * time.Hour).Unix(),
			Version: entitlement.VersionRange{Channel: "stable", Min: "v1.0.0", Max: "v9.9.9"},
			Quotas:  []entitlement.Quota{{Code: entitlement.QuotaNodesCount, Limit: 30}},
		},
		Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatalf("encode signed lease: %v", err)
	}
	limit, err := entitlementNodeLimit(encoded)
	if err != nil {
		t.Fatalf("entitlementNodeLimit: %v", err)
	}
	if limit == nil || *limit != 30 {
		t.Fatalf("node limit = %v, want 30", limit)
	}
}

func TestEntitlementNodeLimitDoesNotInventMissingQuota(t *testing.T) {
	limit, err := entitlementNodeLimit(nil)
	if err != nil {
		t.Fatalf("entitlementNodeLimit(empty): %v", err)
	}
	if limit != nil {
		t.Fatalf("empty lease node limit = %v, want nil", *limit)
	}
}
