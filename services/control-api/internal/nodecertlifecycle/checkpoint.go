package nodecertlifecycle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	RevocationCheckpointSchema          = "cdnca.node.revocation-checkpoint/v1"
	revocationCheckpointSignatureDomain = "cdnca-node-revocation-checkpoint-signature/v1\x00"
	maxRevocationCheckpointBytes        = 4 << 20
)

var (
	ErrCheckpointInvalid  = errors.New("node revocation checkpoint is invalid")
	ErrCheckpointReplay   = errors.New("node revocation checkpoint revision was replayed")
	ErrCheckpointConflict = errors.New("node revocation checkpoint LKG changed concurrently")
)

type RevokedCertificate struct {
	NodeID                uuid.UUID `json:"node_id"`
	SerialNumber          string    `json:"serial_number"`
	AuthorizationRevision uint64    `json:"authorization_revision"`
}

type RevokedCAEpoch struct {
	EpochID uuid.UUID `json:"epoch_id"`
	Epoch   int64     `json:"epoch"`
}

type RevocationCheckpointRequest struct {
	InstallationID string
	Revision       uint64
	IssuedAt       time.Time
	ExpiresAt      time.Time
	KeyID          string
	Certificates   []RevokedCertificate
	CAEpochs       []RevokedCAEpoch
}

type revocationCheckpointBody struct {
	Schema         string               `json:"schema"`
	InstallationID string               `json:"installation_id"`
	Revision       uint64               `json:"revision"`
	IssuedAt       time.Time            `json:"issued_at"`
	ExpiresAt      time.Time            `json:"expires_at"`
	KeyID          string               `json:"key_id"`
	Certificates   []RevokedCertificate `json:"certificates"`
	CAEpochs       []RevokedCAEpoch     `json:"ca_epochs"`
}

type signedRevocationCheckpoint struct {
	Body      json.RawMessage `json:"body"`
	Signature string          `json:"signature"`
}

type VerifiedRevocationCheckpoint struct {
	InstallationID string
	Revision       uint64
	IssuedAt       time.Time
	ExpiresAt      time.Time
	KeyID          string
	Certificates   []RevokedCertificate
	CAEpochs       []RevokedCAEpoch
	Digest         [32]byte
	WireBytes      []byte
}

func IssueRevocationCheckpoint(random io.Reader, signer crypto.Signer, request RevocationCheckpointRequest) ([]byte, error) {
	if random == nil || signer == nil {
		return nil, ErrCheckpointInvalid
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrCheckpointInvalid
	}
	body := revocationCheckpointBody{Schema: RevocationCheckpointSchema, InstallationID: request.InstallationID,
		Revision: request.Revision, IssuedAt: request.IssuedAt.UTC(), ExpiresAt: request.ExpiresAt.UTC(), KeyID: request.KeyID,
		Certificates: slices.Clone(request.Certificates), CAEpochs: slices.Clone(request.CAEpochs)}
	normalizeCheckpointBody(&body)
	if !validCheckpointBody(body) {
		return nil, ErrCheckpointInvalid
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil || len(bodyBytes) > maxRevocationCheckpointBytes {
		return nil, ErrCheckpointInvalid
	}
	signature, err := signer.Sign(random, checkpointSigningMessage(bodyBytes), crypto.Hash(0))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, checkpointSigningMessage(bodyBytes), signature) {
		return nil, ErrCheckpointInvalid
	}
	wire, err := json.Marshal(signedRevocationCheckpoint{Body: bodyBytes, Signature: base64.RawStdEncoding.EncodeToString(signature)})
	if err != nil || len(wire) > maxRevocationCheckpointBytes {
		return nil, ErrCheckpointInvalid
	}
	return wire, nil
}

type CheckpointLKGStore interface {
	Load(context.Context, string) (VerifiedRevocationCheckpoint, bool, error)
	StoreNext(context.Context, VerifiedRevocationCheckpoint, uint64) error
}

type CheckpointApplier struct {
	store            CheckpointLKGStore
	installationID   string
	keys             map[string]ed25519.PublicKey
	clock            Clock
	maximumClockSkew time.Duration
}

func NewCheckpointApplier(store CheckpointLKGStore, installationID string, keys map[string]ed25519.PublicKey, clock Clock, maximumClockSkew time.Duration) (*CheckpointApplier, error) {
	if store == nil || !validCheckpointIdentity(installationID) || clock == nil || maximumClockSkew < 0 || maximumClockSkew > 10*time.Minute || len(keys) == 0 {
		return nil, ErrCheckpointInvalid
	}
	copyKeys := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, key := range keys {
		if !validCheckpointIdentity(keyID) || len(key) != ed25519.PublicKeySize {
			return nil, ErrCheckpointInvalid
		}
		copyKeys[keyID] = slices.Clone(key)
	}
	return &CheckpointApplier{store: store, installationID: installationID, keys: copyKeys, clock: clock, maximumClockSkew: maximumClockSkew}, nil
}

func (applier *CheckpointApplier) Apply(ctx context.Context, wire []byte) (VerifiedRevocationCheckpoint, error) {
	if applier == nil || ctx == nil {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointInvalid
	}
	checkpoint, err := verifyRevocationCheckpoint(wire, applier.keys, applier.installationID, applier.clock().UTC(), applier.maximumClockSkew)
	if err != nil {
		return VerifiedRevocationCheckpoint{}, err
	}
	current, found, err := applier.store.Load(ctx, applier.installationID)
	if err != nil {
		return VerifiedRevocationCheckpoint{}, err
	}
	previous := uint64(0)
	if found {
		previous = current.Revision
		if checkpoint.Revision <= previous {
			return VerifiedRevocationCheckpoint{}, ErrCheckpointReplay
		}
	}
	if err := applier.store.StoreNext(ctx, checkpoint, previous); err != nil {
		return VerifiedRevocationCheckpoint{}, err
	}
	return checkpoint, nil
}

func verifyRevocationCheckpoint(wire []byte, keys map[string]ed25519.PublicKey, installationID string, now time.Time, skew time.Duration) (VerifiedRevocationCheckpoint, error) {
	if len(wire) == 0 || len(wire) > maxRevocationCheckpointBytes {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var document signedRevocationCheckpoint
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointInvalid
	}
	var body revocationCheckpointBody
	bodyDecoder := json.NewDecoder(bytes.NewReader(document.Body))
	bodyDecoder.DisallowUnknownFields()
	if bodyDecoder.Decode(&body) != nil || bodyDecoder.Decode(&struct{}{}) != io.EOF || !validCheckpointBody(body) || body.InstallationID != installationID {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointInvalid
	}
	canonical, _ := json.Marshal(body)
	if !bytes.Equal(canonical, document.Body) || body.IssuedAt.After(now.Add(skew)) || !body.ExpiresAt.After(now.Add(-skew)) {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointInvalid
	}
	key, found := keys[body.KeyID]
	signature, err := base64.RawStdEncoding.DecodeString(document.Signature)
	if !found || err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, checkpointSigningMessage(document.Body), signature) {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointInvalid
	}
	return VerifiedRevocationCheckpoint{InstallationID: body.InstallationID, Revision: body.Revision, IssuedAt: body.IssuedAt,
		ExpiresAt: body.ExpiresAt, KeyID: body.KeyID, Certificates: slices.Clone(body.Certificates), CAEpochs: slices.Clone(body.CAEpochs),
		Digest: sha256.Sum256(wire), WireBytes: slices.Clone(wire)}, nil
}

func normalizeCheckpointBody(body *revocationCheckpointBody) {
	sort.Slice(body.Certificates, func(i, j int) bool {
		if body.Certificates[i].NodeID != body.Certificates[j].NodeID {
			return bytes.Compare(body.Certificates[i].NodeID[:], body.Certificates[j].NodeID[:]) < 0
		}
		return body.Certificates[i].SerialNumber < body.Certificates[j].SerialNumber
	})
	sort.Slice(body.CAEpochs, func(i, j int) bool { return body.CAEpochs[i].Epoch < body.CAEpochs[j].Epoch })
}

func validCheckpointBody(body revocationCheckpointBody) bool {
	if body.Schema != RevocationCheckpointSchema || !validCheckpointIdentity(body.InstallationID) || body.Revision == 0 ||
		body.IssuedAt.IsZero() || body.ExpiresAt.IsZero() || !body.IssuedAt.Before(body.ExpiresAt) || !validCheckpointIdentity(body.KeyID) {
		return false
	}
	for index, item := range body.Certificates {
		if item.NodeID == uuid.Nil || !validSerial(item.SerialNumber) || item.AuthorizationRevision == 0 ||
			index > 0 && (item.NodeID == body.Certificates[index-1].NodeID && item.SerialNumber <= body.Certificates[index-1].SerialNumber ||
				bytes.Compare(item.NodeID[:], body.Certificates[index-1].NodeID[:]) < 0) {
			return false
		}
	}
	for index, item := range body.CAEpochs {
		if item.EpochID == uuid.Nil || item.Epoch < 1 || index > 0 && item.Epoch <= body.CAEpochs[index-1].Epoch {
			return false
		}
	}
	return true
}

func validCheckpointIdentity(value string) bool {
	return value != "" && len(value) <= 255 && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

func checkpointSigningMessage(body []byte) []byte {
	return append(append(make([]byte, 0, len(revocationCheckpointSignatureDomain)+len(body)), revocationCheckpointSignatureDomain...), body...)
}
