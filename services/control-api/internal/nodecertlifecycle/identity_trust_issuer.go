package nodecertlifecycle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
)

const (
	identityTrustCheckpointSchema  = "cdnca.node.identity-trust/v1"
	identityTrustSignatureDomain   = "cdnca-node-identity-trust-signature/v1\x00"
	IdentityTrustTargetActive      = "active"
	IdentityTrustTargetDraining    = "draining"
	IdentityTrustTargetRevoked     = "revoked"
	maxIdentityTrustCheckpointSize = 1 << 20
)

var (
	ErrIdentityTrustIssuerInput     = errors.New("node identity trust issuer input is invalid")
	ErrIdentityTrustIssuerRevision  = errors.New("node identity trust issuer revision is invalid")
	ErrIdentityTrustIssuerTime      = errors.New("node identity trust issuer time is invalid")
	ErrIdentityTrustIssuerRecipient = errors.New("node identity trust issuer recipient is invalid")
	ErrIdentityTrustIssuerSigning   = errors.New("node identity trust issuer signing failed")
)

type IdentityTrustSigningKey interface {
	crypto.Signer
	KeyID() string
}

type IdentityTrustIssuerConfig struct {
	Clock            Clock
	MaximumClockSkew time.Duration
	MaximumTTL       time.Duration
}

type IdentityTrustCAEpochFact struct {
	ID                 uuid.UUID
	Epoch              int64
	Status             string
	ChainPEM           [][]byte
	NotBefore          time.Time
	NotAfter           time.Time
	RetiredAt          *time.Time
	OverlapUntil       *time.Time
	RevokedAt          *time.Time
	RevocationRevision uint64
}

type IdentityTrustCheckpointRequest struct {
	InstallationID   string
	TargetNodeID     uuid.UUID
	TargetState      string
	PreviousRevision uint64
	Revision         uint64
	IssuedAt         time.Time
	ExpiresAt        time.Time
	Epochs           []IdentityTrustCAEpochFact
}

type IdentityTrustCheckpoint struct {
	InstallationID string
	Revision       uint64
	CurrentEpoch   int64
	IssuedAt       time.Time
	ExpiresAt      time.Time
	KeyID          string
	Digest         [sha256.Size]byte
	WireBytes      []byte
}

type IdentityTrustIssuer struct {
	signer           IdentityTrustSigningKey
	publicKey        ed25519.PublicKey
	keyID            string
	clock            Clock
	maximumClockSkew time.Duration
	maximumTTL       time.Duration
}

type identityTrustCheckpointEpoch struct {
	Epoch        int64      `json:"epoch"`
	Status       string     `json:"status"`
	ChainPEM     []string   `json:"chain_pem"`
	OverlapUntil *time.Time `json:"overlap_until,omitempty"`
}

type identityTrustCheckpointBody struct {
	Schema         string                         `json:"schema"`
	InstallationID string                         `json:"installation_id"`
	Revision       uint64                         `json:"revision"`
	CurrentEpoch   int64                          `json:"current_epoch"`
	IssuedAt       time.Time                      `json:"issued_at"`
	ExpiresAt      time.Time                      `json:"expires_at"`
	KeyID          string                         `json:"key_id"`
	Epochs         []identityTrustCheckpointEpoch `json:"epochs"`
}

type signedIdentityTrustCheckpoint struct {
	Body      json.RawMessage `json:"body"`
	Signature string          `json:"signature"`
}

func NewIdentityTrustIssuer(signer IdentityTrustSigningKey, managedKeyID string, config IdentityTrustIssuerConfig) (*IdentityTrustIssuer, error) {
	if signer == nil || config.Clock == nil || config.MaximumClockSkew < 0 || config.MaximumClockSkew > 10*time.Minute || config.MaximumTTL <= 0 ||
		!validCheckpointIdentity(managedKeyID) || signer.KeyID() != managedKeyID {
		return nil, ErrIdentityTrustIssuerInput
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrIdentityTrustIssuerInput
	}
	return &IdentityTrustIssuer{
		signer: signer, publicKey: append(ed25519.PublicKey(nil), publicKey...), keyID: managedKeyID,
		clock: config.Clock, maximumClockSkew: config.MaximumClockSkew, maximumTTL: config.MaximumTTL,
	}, nil
}

func (issuer *IdentityTrustIssuer) Issue(ctx context.Context, request IdentityTrustCheckpointRequest) (IdentityTrustCheckpoint, error) {
	if issuer == nil || ctx == nil || !validCheckpointIdentity(request.InstallationID) || request.TargetNodeID == uuid.Nil {
		return IdentityTrustCheckpoint{}, ErrIdentityTrustIssuerInput
	}
	switch request.TargetState {
	case IdentityTrustTargetActive, IdentityTrustTargetDraining:
	case IdentityTrustTargetRevoked:
		return IdentityTrustCheckpoint{}, ErrIdentityTrustIssuerRecipient
	default:
		return IdentityTrustCheckpoint{}, ErrIdentityTrustIssuerRecipient
	}
	if request.Revision == 0 || request.PreviousRevision == math.MaxUint64 || request.Revision != request.PreviousRevision+1 {
		return IdentityTrustCheckpoint{}, ErrIdentityTrustIssuerRevision
	}
	issuedAt, expiresAt, now := request.IssuedAt.UTC(), request.ExpiresAt.UTC(), issuer.clock().UTC()
	if issuedAt.IsZero() || expiresAt.IsZero() || now.IsZero() || !issuedAt.Before(expiresAt) ||
		issuedAt.After(now.Add(issuer.maximumClockSkew)) || !expiresAt.After(now) || expiresAt.Sub(issuedAt) > issuer.maximumTTL {
		return IdentityTrustCheckpoint{}, ErrIdentityTrustIssuerTime
	}
	epochs, currentEpoch, err := normalizeIdentityTrustFacts(request.Epochs, issuedAt, expiresAt, request.Revision)
	if err != nil {
		return IdentityTrustCheckpoint{}, err
	}
	body := identityTrustCheckpointBody{
		Schema: identityTrustCheckpointSchema, InstallationID: request.InstallationID, Revision: request.Revision,
		CurrentEpoch: currentEpoch, IssuedAt: issuedAt, ExpiresAt: expiresAt, KeyID: issuer.keyID, Epochs: epochs,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil || len(bodyBytes) > maxIdentityTrustCheckpointSize {
		return IdentityTrustCheckpoint{}, ErrIdentityTrustIssuerInput
	}
	if ctx.Err() != nil {
		return IdentityTrustCheckpoint{}, ErrIdentityTrustIssuerSigning
	}
	message := identityTrustSigningMessage(bodyBytes)
	signature, err := issuer.signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(issuer.publicKey, message, signature) {
		return IdentityTrustCheckpoint{}, ErrIdentityTrustIssuerSigning
	}
	wire, err := json.Marshal(signedIdentityTrustCheckpoint{Body: bodyBytes, Signature: base64.RawStdEncoding.EncodeToString(signature)})
	if err != nil || len(wire) > maxIdentityTrustCheckpointSize {
		return IdentityTrustCheckpoint{}, ErrIdentityTrustIssuerSigning
	}
	return IdentityTrustCheckpoint{
		InstallationID: request.InstallationID, Revision: request.Revision, CurrentEpoch: currentEpoch,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, KeyID: issuer.keyID, Digest: sha256.Sum256(wire), WireBytes: wire,
	}, nil
}

func normalizeIdentityTrustFacts(facts []IdentityTrustCAEpochFact, issuedAt, expiresAt time.Time, revision uint64) ([]identityTrustCheckpointEpoch, int64, error) {
	ordered := append([]IdentityTrustCAEpochFact(nil), facts...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Epoch < ordered[right].Epoch })
	seenIDs := make(map[uuid.UUID]struct{}, len(ordered))
	result := make([]identityTrustCheckpointEpoch, 0, 2)
	activeCount, overlapCount := 0, 0
	var currentEpoch int64
	for index, fact := range ordered {
		if fact.ID == uuid.Nil || fact.Epoch < 1 || index > 0 && fact.Epoch == ordered[index-1].Epoch {
			return nil, 0, ErrIdentityTrustIssuerInput
		}
		if _, exists := seenIDs[fact.ID]; exists {
			return nil, 0, ErrIdentityTrustIssuerInput
		}
		seenIDs[fact.ID] = struct{}{}
		switch fact.Status {
		case EpochActive:
			if fact.RetiredAt != nil || fact.OverlapUntil != nil || fact.RevokedAt != nil || fact.RevocationRevision != 0 {
				return nil, 0, ErrIdentityTrustIssuerInput
			}
			chain, err := validateIdentityTrustChain(fact, issuedAt, expiresAt)
			if err != nil {
				return nil, 0, err
			}
			activeCount++
			currentEpoch = fact.Epoch
			result = append(result, identityTrustCheckpointEpoch{Epoch: fact.Epoch, Status: "active", ChainPEM: chain})
		case EpochRetired:
			if fact.RetiredAt == nil || fact.RetiredAt.After(issuedAt) || fact.RevokedAt != nil || fact.RevocationRevision != 0 {
				return nil, 0, ErrIdentityTrustIssuerInput
			}
			if fact.OverlapUntil == nil || !issuedAt.Before(*fact.OverlapUntil) {
				continue
			}
			chain, err := validateIdentityTrustChain(fact, issuedAt, expiresAt)
			if err != nil {
				return nil, 0, err
			}
			overlapCount++
			overlapUntil := fact.OverlapUntil.UTC()
			result = append(result, identityTrustCheckpointEpoch{Epoch: fact.Epoch, Status: "overlap", ChainPEM: chain, OverlapUntil: &overlapUntil})
		case EpochRevoked:
			if fact.RevokedAt == nil || fact.RevokedAt.After(issuedAt) || fact.RevocationRevision == 0 || fact.RevocationRevision > revision ||
				fact.RetiredAt != nil || fact.OverlapUntil != nil {
				return nil, 0, ErrIdentityTrustIssuerInput
			}
		default:
			return nil, 0, ErrIdentityTrustIssuerInput
		}
	}
	if activeCount != 1 || overlapCount > 1 || len(result) < 1 || len(result) > 2 {
		return nil, 0, ErrIdentityTrustIssuerInput
	}
	for _, epoch := range result {
		if epoch.Status == "overlap" && epoch.Epoch >= currentEpoch {
			return nil, 0, ErrIdentityTrustIssuerInput
		}
	}
	return result, currentEpoch, nil
}

func validateIdentityTrustChain(fact IdentityTrustCAEpochFact, issuedAt, expiresAt time.Time) ([]string, error) {
	if len(fact.ChainPEM) < 1 || len(fact.ChainPEM) > 8 || fact.NotBefore.IsZero() || fact.NotAfter.IsZero() || !fact.NotBefore.Before(fact.NotAfter) {
		return nil, ErrIdentityTrustIssuerInput
	}
	certificates := make([]*x509.Certificate, len(fact.ChainPEM))
	encoded := make([]string, len(fact.ChainPEM))
	seen := make(map[[sha256.Size]byte]struct{}, len(fact.ChainPEM))
	for index, value := range fact.ChainPEM {
		block, rest := pem.Decode(value)
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
			return nil, ErrIdentityTrustIssuerInput
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			issuedAt.Before(certificate.NotBefore) || expiresAt.After(certificate.NotAfter) {
			return nil, ErrIdentityTrustIssuerTime
		}
		digest := sha256.Sum256(certificate.Raw)
		if _, exists := seen[digest]; exists {
			return nil, ErrIdentityTrustIssuerInput
		}
		seen[digest] = struct{}{}
		certificates[index] = certificate
		encoded[index] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	}
	if !fact.NotBefore.UTC().Equal(certificates[0].NotBefore.UTC()) || !fact.NotAfter.UTC().Equal(certificates[0].NotAfter.UTC()) {
		return nil, ErrIdentityTrustIssuerInput
	}
	for index := 0; index < len(certificates)-1; index++ {
		if certificates[index].CheckSignatureFrom(certificates[index+1]) != nil {
			return nil, ErrIdentityTrustIssuerInput
		}
	}
	root := certificates[len(certificates)-1]
	if root.CheckSignatureFrom(root) != nil || !bytes.Equal(root.RawIssuer, root.RawSubject) {
		return nil, ErrIdentityTrustIssuerInput
	}
	if !validateCAChainLineage(certificates) {
		return nil, ErrIdentityTrustIssuerInput
	}
	return encoded, nil
}

func identityTrustSigningMessage(body []byte) []byte {
	return append(append(make([]byte, 0, len(identityTrustSignatureDomain)+len(body)), identityTrustSignatureDomain...), body...)
}
