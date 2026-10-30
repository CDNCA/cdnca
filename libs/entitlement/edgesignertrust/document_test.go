package edgesignertrust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func publicPEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func testDocument(t *testing.T) Document {
	t.Helper()
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Document{Schema: DocumentSchema, Revision: 3, IssuedAt: "2026-10-17T08:00:00Z",
		TrustedKeys: []TrustedKey{
			{KeyID: "cdnca-native-node-20261101", PublicKeyPEM: publicPEM(t, testKey("new release").Public())},
			{KeyID: "cdnca-ecdsa", PublicKeyPEM: publicPEM(t, &ecdsaKey.PublicKey)},
		},
		RevokedKeys: []RevokedKey{{KeyID: "cdnca-native-node-20261008", RevokedAt: "2026-10-17T07:00:00Z",
			Reason: "signer_compromise"}}}
}

func TestSignVerifyRoundTripAndPins(t *testing.T) {
	root := testKey("offline root")
	document, err := Normalize(testDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	if document.TrustedKeys[0].KeyID != "cdnca-ecdsa" {
		t.Fatalf("not sorted: %v", document.TrustedKeys)
	}
	encoded, err := Sign(document, "offline-root", 2, root)
	if err != nil {
		t.Fatal(err)
	}
	pin := RootPin{KeyID: "offline-root", Generation: 2, PublicKey: root.Public().(ed25519.PublicKey)}
	signed, err := Verify(encoded, []RootPin{pin})
	if err != nil || signed.Document.Revision != 3 {
		t.Fatalf("verify = %#v, %v", signed, err)
	}
	for name, pins := range map[string][]RootPin{
		"none":       nil,
		"generation": {{KeyID: pin.KeyID, Generation: 3, PublicKey: pin.PublicKey}},
		"key":        {{KeyID: pin.KeyID, Generation: 2, PublicKey: testKey("other").Public().(ed25519.PublicKey)}},
	} {
		if _, err := Verify(encoded, pins); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
	if _, err := Decode(bytes.Replace(encoded, []byte(`"revoked_keys":[`), []byte(`"revoked_keys":null,"x":[`), 1)); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("null list error = %v", err)
	}
	tampered := bytes.Replace(encoded, []byte(`"revision":3`), []byte(`"revision":4`), 1)
	if _, err := Verify(tampered, []RootPin{pin}); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("tampered digest error = %v", err)
	}
	for name, candidate := range map[string][]byte{
		"whitespace": append([]byte(" "), encoded...),
		"trailing":   append(append([]byte(nil), encoded...), '{', '}'),
		"unknown":    bytes.Replace(encoded, []byte(`{"document":`), []byte(`{"x":1,"document":`), 1),
	} {
		if _, err := Decode(candidate); !errors.Is(err, ErrInvalidDocument) {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
}

func TestDocumentValidationAndRevokes(t *testing.T) {
	revokedKey := testKey("revoked")
	fingerprint, err := PublicKeySHA256(revokedKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	base := testDocument(t)
	base.RevokedKeys = append(base.RevokedKeys, RevokedKey{KeyID: "renamed-old", PublicKeySHA256: fingerprint,
		RevokedAt: "2026-10-17T07:00:00Z", Reason: "signer_compromise"})
	document, err := Normalize(base)
	if err != nil {
		t.Fatal(err)
	}
	if !document.Revokes("cdnca-native-node-20261008", nil) || !document.Revokes("any-id", revokedKey.Public()) ||
		document.Revokes("cdnca-native-node-20261101", testKey("new release").Public()) {
		t.Fatal("revocation matching is wrong")
	}
	for name, mutate := range map[string]func(*Document){
		"schema":           func(d *Document) { d.Schema = "x" },
		"revision zero":    func(d *Document) { d.Revision = 0 },
		"time":             func(d *Document) { d.IssuedAt = "2026-10-17T08:00:00.5Z" },
		"bad pem":          func(d *Document) { d.TrustedKeys[0].PublicKeyPEM = "x" },
		"duplicate":        func(d *Document) { d.TrustedKeys[1].KeyID = d.TrustedKeys[0].KeyID },
		"reason":           func(d *Document) { d.RevokedKeys[0].Reason = "Bad Reason" },
		"fingerprint":      func(d *Document) { d.RevokedKeys[0].PublicKeySHA256 = strings.Repeat("A", 64) },
		"trusted revoked":  func(d *Document) { d.RevokedKeys[0].KeyID = "cdnca-native-node-20261101" },
		"trusted by print": func(d *Document) { d.TrustedKeys[0].PublicKeyPEM = publicPEM(t, revokedKey.Public()) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.TrustedKeys = append([]TrustedKey(nil), base.TrustedKeys...)
			candidate.RevokedKeys = append([]RevokedKey(nil), base.RevokedKeys...)
			mutate(&candidate)
			if _, err := Normalize(candidate); !errors.Is(err, ErrInvalidDocument) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	unsorted := document
	unsorted.RevokedKeys = []RevokedKey{document.RevokedKeys[1], document.RevokedKeys[0]}
	if _, err := Sign(unsorted, "offline-root", 1, testKey("root")); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("unsorted sign error = %v", err)
	}
}

func TestBundleOpenAndReceipt(t *testing.T) {
	root, control := testKey("root"), testKey("control publisher")
	document, _ := Normalize(testDocument(t))
	encoded, err := Sign(document, "offline-root", 1, root)
	if err != nil {
		t.Fatal(err)
	}
	trusted := func(keyID string) (ed25519.PublicKey, bool) {
		if keyID == "edge-publish" {
			return control.Public().(ed25519.PublicKey), true
		}
		return nil, false
	}
	seal := func(nodeID, keyID string, key ed25519.PrivateKey) []byte {
		t.Helper()
		bundle, err := NewBundle(nodeID, encoded, keyID, time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		payload, err := BundleSigningPayload(bundle)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := SealBundle(bundle, ed25519.Sign(key, payload))
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	wire := seal("node-1", "edge-publish", control)
	bundle, signed, documentBytes, err := OpenBundle(wire, "node-1", trusted)
	if err != nil || bundle.Revision != 3 || signed.Document.Revision != 3 || !bytes.Equal(documentBytes, encoded) {
		t.Fatalf("open = %v", err)
	}
	if _, _, _, err := OpenBundle(wire, "node-2", trusted); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("wrong node error = %v", err)
	}
	if _, _, _, err := OpenBundle(seal("node-1", "edge-publish", testKey("attacker")), "node-1", trusted); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("forged error = %v", err)
	}
	if _, _, _, err := OpenBundle(seal("node-1", "unknown", control), "node-1", trusted); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("unknown key error = %v", err)
	}
	var mutated Bundle
	_ = json.Unmarshal(wire, &mutated)
	mutated.Revision = 4
	payload, _ := BundleSigningPayload(mutated)
	mismatch, _ := SealBundle(mutated, ed25519.Sign(control, payload))
	if _, _, _, err := OpenBundle(mismatch, "node-1", trusted); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("revision mismatch error = %v", err)
	}
	receipt := Receipt{Schema: ReceiptSchema, NodeID: "node-1", BundleSHA256: Digest(wire), Revision: 3,
		Result: ResultApplied, ReportedAt: "2026-10-17T09:00:01Z"}
	receiptBytes, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeReceipt(receiptBytes); err != nil || decoded != receipt {
		t.Fatalf("receipt = %#v, %v", decoded, err)
	}
	receipt.Result, receipt.Reason = ResultRejected, ""
	if _, err := EncodeReceipt(receipt); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("rejected receipt without reason error = %v", err)
	}
}

func TestInstallationBanKeyUsage(t *testing.T) {
	document := testDocument(t)
	banKey := testKey("license lease")
	document.TrustedKeys = append(document.TrustedKeys, TrustedKey{KeyID: "license-lease-1",
		PublicKeyPEM: publicPEM(t, banKey.Public()), Usage: UsageInstallationBan})
	normalized, err := Normalize(document)
	if err != nil {
		t.Fatal(err)
	}
	keys := normalized.InstallationBanKeys()
	if len(keys) != 1 || !keys["license-lease-1"].Equal(banKey.Public()) {
		t.Fatalf("InstallationBanKeys = %v", keys)
	}
	for _, trusted := range normalized.TrustedKeys {
		if trusted.ArtifactKey() == (trusted.KeyID == "license-lease-1") {
			t.Fatalf("ArtifactKey(%s) wrong", trusted.KeyID)
		}
	}
	encoded, err := Sign(normalized, "offline-root", 2, testKey("offline root"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatalf("decode with usage: %v", err)
	}
	unknown := testDocument(t)
	unknown.TrustedKeys[0].Usage = "artifact"
	if _, err := Normalize(unknown); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("unknown usage error = %v", err)
	}
	ecdsaBan := testDocument(t)
	for index := range ecdsaBan.TrustedKeys {
		if ecdsaBan.TrustedKeys[index].KeyID == "cdnca-ecdsa" {
			ecdsaBan.TrustedKeys[index].Usage = UsageInstallationBan
		}
	}
	if _, err := Normalize(ecdsaBan); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("ecdsa ban key error = %v", err)
	}
	revoked := normalized
	revoked.RevokedKeys = append([]RevokedKey{}, normalized.RevokedKeys...)
	revoked.RevokedKeys = append(revoked.RevokedKeys, RevokedKey{KeyID: "license-lease-0",
		RevokedAt: "2026-10-17T07:00:00Z", Reason: "rotated"})
	if len(revoked.InstallationBanKeys()) != 1 {
		t.Fatal("unrelated revocation dropped the ban key")
	}
}
