package certificateasset

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCertificateOwnerDigestPreservesLegacy(t *testing.T) {
	store := &Store{now: func() time.Time { return certificateTestNow }}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeTenant}
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	request := ImportRequest{TenantScopeID: actor.ScopeID, Name: "legacy", Source: SourceUploaded,
		CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
		IdempotencyKey: "legacy", RequestID: "legacy"}
	prepared, digest, err := store.prepareImport(actor, &request, false)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(prepared.CanonicalPrivateKey)
	// This is the original pre-owner digest schema, including its JSON field order.
	legacy, err := digestRequest(struct {
		TenantScopeID         uuid.UUID  `json:"tenant_scope_id"`
		AssetID               *uuid.UUID `json:"asset_id,omitempty"`
		ExpectedRevision      int64      `json:"expected_revision"`
		Name                  string     `json:"name"`
		Source                string     `json:"source"`
		ACMEOrderID           *uuid.UUID `json:"acme_order_id,omitempty"`
		Fingerprint           string     `json:"fingerprint_sha256"`
		PrivateKeyReference   string     `json:"private_key_reference"`
		KeyMaterialKind       string     `json:"key_material_kind"`
		WrappedMaterialSHA256 string     `json:"wrapped_material_sha256,omitempty"`
		OpaqueMetadataSHA256  string     `json:"opaque_metadata_sha256,omitempty"`
	}{request.TenantScopeID, nil, 0, request.Name, request.Source, nil, fingerprintHex(prepared.Fingerprint), prepared.PrivateKeyReference, "plaintext_pkcs8", "", ""})
	if err != nil || digest != legacy || request.OwnerUserID != nil {
		t.Fatal("omitted owner changed legacy request identity")
	}
	request.OwnerUserID = &actor.UserID
	explicit, newDigest, err := store.prepareImport(actor, &request, false)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(explicit.CanonicalPrivateKey)
	if newDigest == legacy {
		t.Fatal("explicit owner was omitted from idempotency identity")
	}
	var replay ImportResult
	if err := decodeReplay([]byte(`{"asset":{"id":"11111111-1111-4111-8111-111111111111","created_by":"22222222-2222-4222-8222-222222222222"},"version":{}}`), &replay); err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.Asset.Owner != nil || replay.Asset.OwnerStatus != "legacy_unknown" {
		t.Fatal("legacy receipt acquired invented ownership")
	}
	encoded, err := json.Marshal(replay.Asset)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["created_by"] != "22222222-2222-4222-8222-222222222222" {
		t.Fatal("creator changed on replay")
	}
}
