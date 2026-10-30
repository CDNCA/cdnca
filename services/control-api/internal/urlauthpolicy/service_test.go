package urlauthpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizeFieldsRejectsWeakAndAmbiguousInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PolicyFields)
	}{
		{"MD5 downgrade", func(fields *PolicyFields) { fields.Algorithm = "md5" }},
		{"duplicate auth parameter", func(fields *PolicyFields) { fields.KeyIDParameter = fields.SignatureParameter }},
		{"auth parameter exclusion", func(fields *PolicyFields) { fields.ExcludedQueryParameters = []string{fields.SignatureParameter} }},
		{"duplicate exclusion", func(fields *PolicyFields) { fields.ExcludedQueryParameters = []string{"utm", "utm"} }},
		{"invalid proxy", func(fields *PolicyFields) { fields.TrustedProxyCIDRs = []string{"10.0.0.999/24"} }},
		{"IPv4 mapped proxy", func(fields *PolicyFields) { fields.TrustedProxyCIDRs = []string{"::ffff:192.0.2.1/128"} }},
		{"excess clock skew", func(fields *PolicyFields) { fields.MaxClockSkewSeconds = 301 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := validFields()
			test.mutate(&fields)
			if err := normalizeFields(&fields); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalizeFields error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestNormalizeFieldsCanonicalizesOrdering(t *testing.T) {
	fields := validFields()
	fields.ExcludedQueryParameters = []string{"z", "a"}
	fields.TrustedProxyCIDRs = []string{"2001:db8:0:1::1/64", "10.0.0.18/24"}
	if err := normalizeFields(&fields); err != nil {
		t.Fatalf("normalizeFields: %v", err)
	}
	if fields.ExcludedQueryParameters[0] != "a" || fields.ExcludedQueryParameters[1] != "z" {
		t.Fatalf("excluded parameters = %v", fields.ExcludedQueryParameters)
	}
	if fields.TrustedProxyCIDRs[0] != "10.0.0.0/24" || fields.TrustedProxyCIDRs[1] != "2001:db8:0:1::/64" {
		t.Fatalf("trusted proxies = %v", fields.TrustedProxyCIDRs)
	}
}

func TestEdgeSnapshotIsDeterministicAndCompatible(t *testing.T) {
	created := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	item := Policy{
		ID: uuid.MustParse("01983a20-0000-7000-8000-000000000001"), tenantID: uuid.MustParse("01983a20-0000-7000-8000-000000000002"),
		Site: SiteReference{ID: uuid.MustParse("01983a20-0000-7000-8000-000000000003")}, Algorithm: AlgorithmHMACSHA256,
		SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid", BindClientIP: true,
		MaxClockSkewSeconds: 30, MaxValiditySeconds: 600, MaxSignatureUses: 1,
		ExcludedQueryParameters: []string{"utm_campaign", "utm_source"}, TrustedProxyCIDRs: []string{"10.0.0.0/8", "2001:db8::/32"},
		CurrentKey: KeyMetadata{KeyID: "k-current", CreatedAt: created}, PreviousKey: &KeyMetadata{KeyID: "k-previous", CreatedAt: created}, Revision: 7,
	}
	first, firstDigest, err := edgeSnapshot(item)
	if err != nil {
		t.Fatalf("edgeSnapshot: %v", err)
	}
	second, secondDigest, err := edgeSnapshot(item)
	if err != nil {
		t.Fatalf("edgeSnapshot second: %v", err)
	}
	if !bytes.Equal(first, second) || firstDigest != secondDigest {
		t.Fatal("edge snapshot is not deterministic")
	}
	var decoded EdgePolicy
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if decoded.SchemaVersion != SchemaVersion || decoded.PolicyVersion != 7 || decoded.PreviousKey == nil || decoded.CurrentKey.KeyFile != "/var/lib/cdnca-edge/urlauth/keys/01983a20-0000-7000-8000-000000000001/k-current.key" {
		t.Fatalf("snapshot = %#v", decoded)
	}
}

func validFields() PolicyFields {
	return PolicyFields{
		SiteID: uuid.New(), Name: "URL auth", Enabled: true, Algorithm: AlgorithmHMACSHA256,
		SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid",
		MaxClockSkewSeconds: 30, MaxValiditySeconds: 600, MaxSignatureUses: 1,
		ExcludedQueryParameters: []string{}, TrustedProxyCIDRs: []string{},
	}
}
