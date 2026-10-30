package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

func TestRevocationCheckpointConvergesAcrossGatewaysAndRejectsReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	wire := gatewaySignedCheckpoint(t, privateKey, gatewayCheckpointBody{
		Schema: revocationCheckpointSchema, InstallationID: "01HZXNODE10INSTALLATION", Revision: 72,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "revocation-key-1",
		Certificates: []gatewayRevokedCertificate{{NodeID: "d318940f-bbe5-453c-b6a6-bd04bc31e5c7", SerialNumber: "1", AuthorizationRevision: 8}},
		CAEpochs:     []gatewayRevokedCAEpoch{{EpochID: "504daf70-aed6-4b89-afbe-947e4e3ea344", Epoch: 3}},
	})
	first, err := NewRevocationCheckpointCache("01HZXNODE10INSTALLATION", map[string]ed25519.PublicKey{"revocation-key-1": publicKey}, func() time.Time { return now }, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRevocationCheckpointCache("01HZXNODE10INSTALLATION", map[string]ed25519.PublicKey{"revocation-key-1": publicKey}, func() time.Time { return now }, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	left, err := first.ApplyRevocationCheckpoint(wire)
	if err != nil {
		t.Fatal(err)
	}
	right, err := second.ApplyRevocationCheckpoint(wire)
	if err != nil || left.Revision != right.Revision || left.Digest != right.Digest {
		t.Fatalf("gateways diverged: left=%+v right=%+v err=%v", left, right, err)
	}
	if _, err := first.ApplyRevocationCheckpoint(wire); !errors.Is(err, ErrRevocationCheckpointReplay) {
		t.Fatalf("replay error = %v", err)
	}
	if !first.CertificateRevoked("d318940f-bbe5-453c-b6a6-bd04bc31e5c7", "1", 8) || !first.CAEpochRevoked(3) {
		t.Fatal("checkpoint revocation facts were not queryable")
	}
}

func TestIdentityTrustOverlapAcceptsOldAndNewChainsThenRetiresOld(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPKI, newPKI := newTestPKI(t), newTestPKI(t)
	now := time.Now().UTC()
	clock := now
	overlapUntil := now.Add(time.Hour)
	body := IdentityTrustUpdate{Schema: identityTrustSchema, InstallationID: "01HZXNODE10INSTALLATION", Revision: 9, CurrentEpoch: 2,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(2 * time.Hour), KeyID: "identity-trust-key",
		Epochs: []IdentityTrustEpoch{{Epoch: 1, Status: "overlap", ChainPEM: []string{gatewayCertificatePEM(oldPKI.caCertificate)}, OverlapUntil: &overlapUntil},
			{Epoch: 2, Status: "active", ChainPEM: []string{gatewayCertificatePEM(newPKI.caCertificate)}}}}
	wire := gatewaySignedIdentityTrust(t, privateKey, body)
	validator, err := NewIdentityTrustValidator(body.InstallationID, map[string]ed25519.PublicKey{body.KeyID: publicKey}, func() time.Time { return clock }, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.ApplyIdentityTrustUpdate(wire); err != nil {
		t.Fatal(err)
	}
	oldLeaf := gatewayLeaf(t, oldPKI.client(t, 101, nodeSPIFFEPrefix+"d318940f-bbe5-453c-b6a6-bd04bc31e5c7", now.Add(-time.Minute), now.Add(3*time.Hour)))
	newLeaf := gatewayLeaf(t, newPKI.client(t, 102, nodeSPIFFEPrefix+"d318940f-bbe5-453c-b6a6-bd04bc31e5c7", now.Add(-time.Minute), now.Add(3*time.Hour)))
	if err := validator.ValidateNodeCertificate(oldLeaf); err != nil {
		t.Fatalf("old overlap chain error = %v", err)
	}
	if err := validator.ValidateNodeCertificate(newLeaf); err != nil {
		t.Fatalf("new active chain error = %v", err)
	}
	clock = overlapUntil.Add(time.Second)
	if err := validator.ValidateNodeCertificate(oldLeaf); !errors.Is(err, ErrIdentityTrustInvalid) {
		t.Fatalf("retired old chain error = %v", err)
	}
	if err := validator.ValidateNodeCertificate(newLeaf); err != nil {
		t.Fatalf("new chain after overlap error = %v", err)
	}
	clock = body.ExpiresAt.Add(3 * time.Minute)
	if err := validator.ValidateNodeCertificate(newLeaf); !errors.Is(err, ErrIdentityTrustInvalid) {
		t.Fatalf("expired trust update error = %v", err)
	}
}

func gatewayCertificatePEM(certificate *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
}
func gatewayLeaf(t *testing.T, certificate tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
func gatewaySignedIdentityTrust(t *testing.T, key ed25519.PrivateKey, body IdentityTrustUpdate) []byte {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(key, append(append([]byte{}, identityTrustSignatureDomain...), bodyBytes...))
	wire, err := json.Marshal(signedIdentityTrustUpdate{Body: bodyBytes, Signature: base64.RawStdEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func gatewaySignedCheckpoint(t *testing.T, key ed25519.PrivateKey, body gatewayCheckpointBody) []byte {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	document := gatewaySignedCheckpointDocument{Body: bodyBytes, Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(revocationCheckpointSignatureDomain), bodyBytes...)))}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
