package certificateasset

import (
	"encoding/json"
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
