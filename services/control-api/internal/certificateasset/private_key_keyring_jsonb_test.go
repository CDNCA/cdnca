package certificateasset

import (
	"encoding/json"
	"strings"
	"testing"
)

// fix-transfer: the envelope metadata is stored in a jsonb column, which
// reads back with its keys reordered and spaced ({"kind": "pkcs8",
// "schema": ...}). Unsealing what the database returns must still work.
func TestPrivateKeyKeyringUnsealsJSONBReformattedMetadata(t *testing.T) {
	keyring, err := NewAESGCMPrivateKeyEnvelopeKeyring(PrivateKeyWrappingKey{ID: "acme-kek-v2", Material: keyringMaterial(0x41)})
	if err != nil {
		t.Fatal(err)
	}
	contextValue := keyringEnvelopeContext()
	sealed, err := keyring.Seal(t.Context(), PrivateKeySealRequest{Context: contextValue, PlaintextPKCS8: []byte("pkcs8-key")})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal(sealed.Metadata, &fields); err != nil {
		t.Fatal(err)
	}
	stored := sealed
	stored.Metadata = json.RawMessage(`{"kind": "` + fields["kind"] + `", "schema": "` + fields["schema"] + `"}`)
	plaintext, err := keyring.Unseal(t.Context(), PrivateKeyUnsealRequest{Context: contextValue, Envelope: stored})
	if err != nil || string(plaintext) != "pkcs8-key" {
		t.Fatalf("Unseal(jsonb metadata) = (%q,%v)", plaintext, err)
	}
	clear(plaintext)
	// Other metadata (a different kind) still fails authentication.
	stored.Metadata = json.RawMessage(`{"kind": "opaque_wrapped", "schema": "` + fields["schema"] + `"}`)
	if _, err := keyring.Unseal(t.Context(), PrivateKeyUnsealRequest{Context: contextValue, Envelope: stored}); err == nil {
		t.Fatal("Unseal accepted different metadata")
	}
}

// an ACME envelope (opaque_wrapped) carries the wrapped-key
// metadata in "source". jsonb reorders that nested object too (keys by
// length: wrapping_nonce before wrapping_key_id), so re-marshalling the outer
// struct alone keeps the reordered source and the AAD never matches. The
// stored value below is PostgreSQL 17's jsonb text output for the sealed
// metadata (the shape production read back).
func TestPrivateKeyKeyringUnsealsJSONBReorderedOpaqueSource(t *testing.T) {
	keyring, err := NewAESGCMPrivateKeyEnvelopeKeyring(PrivateKeyWrappingKey{
		ID: "native-certificate-wrapping-v1", Material: keyringMaterial(0x41),
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := json.Marshal(ACMEWrappedKeyMetadata{
		Schema: ACMEWrappedKeySchema, Algorithm: "ecdsa", WrappingKeyID: "native-certificate-wrapping-v1",
		WrappingNonce: []byte{0, 1, 2}, WrappingAADSHA256: []byte{3, 4, 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	contextValue := keyringEnvelopeContext()
	sealed, err := keyring.SealOpaque(t.Context(), OpaquePrivateKeySealRequest{
		Context: contextValue, WrappedKeyMaterial: []byte("wrapped-key"), Metadata: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored := sealed
	stored.Metadata = json.RawMessage(`{"kind": "opaque_wrapped", "schema": "cdnca.acme-certificate-envelope.v1", ` +
		`"source": {"schema": "cdnca.acme-wrapped-key.v1", "algorithm": "ecdsa", "wrapping_nonce": "AAEC", ` +
		`"wrapping_key_id": "native-certificate-wrapping-v1", "wrapping_aad_sha256": "AwQF"}}`)
	plaintext, err := keyring.Unseal(t.Context(), PrivateKeyUnsealRequest{Context: contextValue, Envelope: stored})
	if err != nil || string(plaintext) != "wrapped-key" {
		t.Fatalf("Unseal(jsonb opaque metadata) = (%q,%v)", plaintext, err)
	}
	clear(plaintext)
	// A changed source value still fails authentication.
	stored.Metadata = json.RawMessage(strings.Replace(string(stored.Metadata), `"AAEC"`, `"AAED"`, 1))
	if _, err := keyring.Unseal(t.Context(), PrivateKeyUnsealRequest{Context: contextValue, Envelope: stored}); err == nil {
		t.Fatal("Unseal accepted a different source")
	}
}
