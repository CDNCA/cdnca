package nodecertlifecycle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIdentityTrustIssuerProducesDeterministicSignedFullState(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	signer := newIdentityTrustTestSigner(t, "hsm:identity-trust:5")
	issuer, err := NewIdentityTrustIssuer(signer, signer.KeyID(), IdentityTrustIssuerConfig{
		Clock: func() time.Time { return now }, MaximumClockSkew: 2 * time.Minute, MaximumTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldRoot := identityTrustTestCA(t, nil, nil, 1, "old root", now.Add(-time.Hour), now.Add(48*time.Hour))
	newRoot := identityTrustTestCA(t, nil, nil, 2, "new root", now.Add(-time.Hour), now.Add(72*time.Hour))
	newIntermediate := identityTrustTestCA(t, newRoot.certificate, newRoot.key, 3, "new intermediate", now.Add(-time.Hour), now.Add(48*time.Hour))
	overlapUntil := now.Add(30 * time.Minute)
	retiredAt := now.Add(-time.Minute)
	revokedAt := now.Add(-time.Hour)
	request := IdentityTrustCheckpointRequest{
		InstallationID: "01HZXNODE10INSTALLATION", TargetNodeID: uuid.MustParse("d318940f-bbe5-453c-b6a6-bd04bc31e5c7"),
		TargetState: IdentityTrustTargetDraining, PreviousRevision: 40, Revision: 41,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		Epochs: []IdentityTrustCAEpochFact{
			{ID: uuid.New(), Epoch: 3, Status: EpochActive, ChainPEM: [][]byte{newIntermediate.pem, newRoot.pem}, NotBefore: newIntermediate.certificate.NotBefore, NotAfter: newIntermediate.certificate.NotAfter},
			{ID: uuid.New(), Epoch: 1, Status: EpochRevoked, RevokedAt: &revokedAt, RevocationRevision: 39},
			{ID: uuid.New(), Epoch: 2, Status: EpochRetired, ChainPEM: [][]byte{oldRoot.pem}, NotBefore: oldRoot.certificate.NotBefore, NotAfter: oldRoot.certificate.NotAfter, RetiredAt: &retiredAt, OverlapUntil: &overlapUntil},
		},
	}
	first, err := issuer.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	second, err := issuer.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue(replay materialization) error = %v", err)
	}
	if !bytes.Equal(first.WireBytes, second.WireBytes) || first.Digest != second.Digest {
		t.Fatal("identical source facts did not produce deterministic checkpoint bytes")
	}
	document, body := decodeIdentityTrustCheckpoint(t, first.WireBytes)
	if body.Schema != identityTrustCheckpointSchema || body.Revision != 41 || body.CurrentEpoch != 3 || len(body.Epochs) != 2 {
		t.Fatalf("checkpoint body = %+v", body)
	}
	if body.Epochs[0].Epoch != 2 || body.Epochs[0].Status != "overlap" || body.Epochs[1].Epoch != 3 || body.Epochs[1].Status != "active" || len(body.Epochs[1].ChainPEM) != 2 {
		t.Fatalf("checkpoint epochs = %+v", body.Epochs)
	}
	signature, err := base64.RawStdEncoding.DecodeString(document.Signature)
	if err != nil || !ed25519.Verify(signer.publicKey, identityTrustSigningMessage(document.Body), signature) {
		t.Fatal("checkpoint signature was not valid for its canonical body")
	}
}

func TestIdentityTrustIssuerRejectsInvalidTimeAndRevisionFacts(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	signer := newIdentityTrustTestSigner(t, "hsm:identity-trust:5")
	issuer, err := NewIdentityTrustIssuer(signer, signer.KeyID(), IdentityTrustIssuerConfig{Clock: func() time.Time { return now }, MaximumClockSkew: 2 * time.Minute, MaximumTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	root := identityTrustTestCA(t, nil, nil, 1, "root", now.Add(-time.Hour), now.Add(2*time.Hour))
	valid := IdentityTrustCheckpointRequest{
		InstallationID: "01HZXNODE10INSTALLATION", TargetNodeID: uuid.New(), TargetState: IdentityTrustTargetActive,
		PreviousRevision: 6, Revision: 7, IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute),
		Epochs: []IdentityTrustCAEpochFact{{ID: uuid.New(), Epoch: 1, Status: EpochActive, ChainPEM: [][]byte{root.pem}, NotBefore: root.certificate.NotBefore, NotAfter: root.certificate.NotAfter}},
	}
	tests := []struct {
		name   string
		mutate func(*IdentityTrustCheckpointRequest)
		want   error
	}{
		{"replayed revision", func(value *IdentityTrustCheckpointRequest) { value.Revision = value.PreviousRevision }, ErrIdentityTrustIssuerRevision},
		{"out of order revision", func(value *IdentityTrustCheckpointRequest) { value.Revision += 2 }, ErrIdentityTrustIssuerRevision},
		{"future issue", func(value *IdentityTrustCheckpointRequest) { value.IssuedAt = now.Add(3 * time.Minute) }, ErrIdentityTrustIssuerTime},
		{"expired checkpoint", func(value *IdentityTrustCheckpointRequest) { value.ExpiresAt = now.Add(-time.Second) }, ErrIdentityTrustIssuerTime},
		{"ttl exceeded", func(value *IdentityTrustCheckpointRequest) { value.ExpiresAt = now.Add(2 * time.Hour) }, ErrIdentityTrustIssuerTime},
		{"CA expires first", func(value *IdentityTrustCheckpointRequest) {
			value.ExpiresAt = root.certificate.NotAfter.Add(time.Second)
		}, ErrIdentityTrustIssuerTime},
		{"no active epoch", func(value *IdentityTrustCheckpointRequest) { value.Epochs[0].Status = EpochRetired }, ErrIdentityTrustIssuerInput},
		{"reversed chain", func(value *IdentityTrustCheckpointRequest) { value.Epochs[0].ChainPEM = [][]byte{root.pem, root.pem} }, ErrIdentityTrustIssuerInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Epochs = append([]IdentityTrustCAEpochFact(nil), valid.Epochs...)
			test.mutate(&candidate)
			if _, err := issuer.Issue(context.Background(), candidate); !errors.Is(err, test.want) {
				t.Fatalf("Issue() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestIdentityTrustIssuerAllowsDrainingAndRejectsRevokedTargetAndInvalidRevocation(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	signer := newIdentityTrustTestSigner(t, "hsm:identity-trust:5")
	issuer, err := NewIdentityTrustIssuer(signer, signer.KeyID(), IdentityTrustIssuerConfig{Clock: func() time.Time { return now }, MaximumClockSkew: time.Minute, MaximumTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	root := identityTrustTestCA(t, nil, nil, 1, "root", now.Add(-time.Hour), now.Add(2*time.Hour))
	request := IdentityTrustCheckpointRequest{
		InstallationID: "01HZXNODE10INSTALLATION", TargetNodeID: uuid.New(), TargetState: IdentityTrustTargetDraining,
		PreviousRevision: 8, Revision: 9, IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute),
		Epochs: []IdentityTrustCAEpochFact{{ID: uuid.New(), Epoch: 2, Status: EpochActive, ChainPEM: [][]byte{root.pem}, NotBefore: root.certificate.NotBefore, NotAfter: root.certificate.NotAfter}},
	}
	if _, err := issuer.Issue(context.Background(), request); err != nil {
		t.Fatalf("draining target error = %v", err)
	}
	request.TargetState = IdentityTrustTargetRevoked
	if _, err := issuer.Issue(context.Background(), request); !errors.Is(err, ErrIdentityTrustIssuerRecipient) {
		t.Fatalf("revoked target error = %v", err)
	}
	request.TargetState = IdentityTrustTargetActive
	request.Epochs = append(request.Epochs, IdentityTrustCAEpochFact{ID: uuid.New(), Epoch: 1, Status: EpochRevoked, RevocationRevision: 8})
	if _, err := issuer.Issue(context.Background(), request); !errors.Is(err, ErrIdentityTrustIssuerInput) {
		t.Fatalf("unproven revocation error = %v", err)
	}
}

func TestIdentityTrustIssuerContainsSignerFailuresAndKeyMismatch(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	signer := newIdentityTrustTestSigner(t, "hsm:identity-trust:5")
	if _, err := NewIdentityTrustIssuer(signer, "hsm:identity-trust:6", IdentityTrustIssuerConfig{Clock: func() time.Time { return now }, MaximumClockSkew: time.Minute, MaximumTTL: time.Hour}); !errors.Is(err, ErrIdentityTrustIssuerInput) {
		t.Fatalf("key mismatch error = %v", err)
	}
	failing := *signer
	failing.signError = errors.New("HSM unavailable")
	issuer, err := NewIdentityTrustIssuer(&failing, failing.KeyID(), IdentityTrustIssuerConfig{Clock: func() time.Time { return now }, MaximumClockSkew: time.Minute, MaximumTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	root := identityTrustTestCA(t, nil, nil, 1, "root", now.Add(-time.Hour), now.Add(2*time.Hour))
	request := IdentityTrustCheckpointRequest{InstallationID: "01HZXNODE10INSTALLATION", TargetNodeID: uuid.New(), TargetState: IdentityTrustTargetActive,
		PreviousRevision: 1, Revision: 2, IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute),
		Epochs: []IdentityTrustCAEpochFact{{ID: uuid.New(), Epoch: 1, Status: EpochActive, ChainPEM: [][]byte{root.pem}, NotBefore: root.certificate.NotBefore, NotAfter: root.certificate.NotAfter}}}
	if _, err := issuer.Issue(context.Background(), request); !errors.Is(err, ErrIdentityTrustIssuerSigning) || bytes.Contains([]byte(err.Error()), []byte("HSM unavailable")) {
		t.Fatalf("signer failure error = %v", err)
	}
}

type identityTrustTestSigner struct {
	id         string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	signError  error
}

func newIdentityTrustTestSigner(t *testing.T, id string) *identityTrustTestSigner {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &identityTrustTestSigner{id: id, publicKey: publicKey, privateKey: privateKey}
}

func (signer *identityTrustTestSigner) KeyID() string            { return signer.id }
func (signer *identityTrustTestSigner) Public() crypto.PublicKey { return signer.publicKey }
func (signer *identityTrustTestSigner) Sign(_ io.Reader, message []byte, options crypto.SignerOpts) ([]byte, error) {
	if signer.signError != nil {
		return nil, signer.signError
	}
	return signer.privateKey.Sign(rand.Reader, message, options)
}

type identityTrustTestCAFact struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

func identityTrustTestCA(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, serial int64, name string, notBefore, notAfter time.Time) identityTrustTestCAFact {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return identityTrustTestCAFact{certificate: certificate, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

type identityTrustTestDocument struct {
	Body      json.RawMessage `json:"body"`
	Signature string          `json:"signature"`
}
type identityTrustTestBody struct {
	Schema         string                       `json:"schema"`
	InstallationID string                       `json:"installation_id"`
	Revision       uint64                       `json:"revision"`
	CurrentEpoch   int64                        `json:"current_epoch"`
	IssuedAt       time.Time                    `json:"issued_at"`
	ExpiresAt      time.Time                    `json:"expires_at"`
	KeyID          string                       `json:"key_id"`
	Epochs         []identityTrustTestWireEpoch `json:"epochs"`
}
type identityTrustTestWireEpoch struct {
	Epoch        int64      `json:"epoch"`
	Status       string     `json:"status"`
	ChainPEM     []string   `json:"chain_pem"`
	OverlapUntil *time.Time `json:"overlap_until,omitempty"`
}

func decodeIdentityTrustCheckpoint(t *testing.T, wire []byte) (identityTrustTestDocument, identityTrustTestBody) {
	t.Helper()
	var document identityTrustTestDocument
	if err := json.Unmarshal(wire, &document); err != nil {
		t.Fatal(err)
	}
	var body identityTrustTestBody
	if err := json.Unmarshal(document.Body, &body); err != nil {
		t.Fatal(err)
	}
	return document, body
}
