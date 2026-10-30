package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// sealRawHeader seals with exactly headerBytes, as a newer sender that adds
// header fields would.
func sealRawHeader(t *testing.T, headerBytes, payload, recipientPub []byte, key ed25519.PrivateKey) Sealed {
	t.Helper()
	ephPriv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(ephPriv); err != nil {
		t.Fatal(err)
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := deriveAEAD(ephPriv, recipientPub, ephPub, recipientPub, hkdfInfo)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	s := Sealed{HeaderBytes: headerBytes, Ephemeral: ephPub, Nonce: nonce}
	s.Ciphertext = aead.Seal(nil, nonce, payload, headerBytes)
	s.Signature = ed25519.Sign(key, s.signedMessage())
	return s
}

// A newer controller may add header fields; relays and receivers built from
// this version must still authenticate and open the message (the signature
// and AEAD cover the verbatim header bytes, so nothing is re-encoded).
func TestInspectOpenTolerateUnknownHeaderFields(t *testing.T) {
	b, a := newMember(t), newMember(t)
	raw, err := json.Marshal(header(b, a))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["trace_id"] = "future-field"
	future, _ := json.Marshal(fields)
	sealed := sealRawHeader(t, future, []byte("payload"), a.boxPub, b.signPriv)
	if _, err := Inspect(sealed, registry(a, b)); err != nil {
		t.Fatalf("relay inspect of a newer header: %v", err)
	}
	got, payload, err := Open(sealed, registry(a, b), a.id, a.boxPriv)
	if err != nil || !bytes.Equal(payload, []byte("payload")) || got.SenderMemberID != b.id {
		t.Fatalf("open of a newer header: %v", err)
	}
	// Unknown fields never loosen the known checks.
	fields["schema"] = "cdnca.market.envelope/v2"
	v2, _ := json.Marshal(fields)
	if _, err := Inspect(sealRawHeader(t, v2, []byte("x"), a.boxPub, b.signPriv), registry(a, b)); err == nil {
		t.Fatal("unknown schema accepted")
	}
}
