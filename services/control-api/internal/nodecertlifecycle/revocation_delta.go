package nodecertlifecycle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
)

const (
	RevocationCheckpointDeltaSchema          = "cdnca.node.revocation-checkpoint-delta/v1"
	revocationCheckpointDeltaSignatureDomain = "cdnca-node-revocation-checkpoint-delta-signature/v1\x00"
)

var (
	ErrCheckpointDeltaInvalid  = errors.New("node revocation checkpoint delta is invalid")
	ErrCheckpointDeltaReplay   = errors.New("node revocation checkpoint delta was replayed")
	ErrCheckpointDeltaConflict = errors.New("node revocation checkpoint delta base conflicts with LKG")
)

type RevocationCheckpointDeltaRequest struct {
	InstallationID string
	BaseRevision   uint64
	BaseDigest     [sha256.Size]byte
	Revision       uint64
	IssuedAt       time.Time
	ExpiresAt      time.Time
	KeyID          string
	Certificates   []RevokedCertificate
	CAEpochs       []RevokedCAEpoch
}

type revocationCheckpointDeltaBody struct {
	Schema         string               `json:"schema"`
	InstallationID string               `json:"installation_id"`
	BaseRevision   uint64               `json:"base_revision"`
	BaseDigest     string               `json:"base_digest"`
	Revision       uint64               `json:"revision"`
	IssuedAt       time.Time            `json:"issued_at"`
	ExpiresAt      time.Time            `json:"expires_at"`
	KeyID          string               `json:"key_id"`
	Certificates   []RevokedCertificate `json:"certificates"`
	CAEpochs       []RevokedCAEpoch     `json:"ca_epochs"`
}

type signedRevocationCheckpointDelta struct {
	Body      json.RawMessage `json:"body"`
	Signature string          `json:"signature"`
}

type VerifiedRevocationCheckpointDelta struct {
	InstallationID string
	BaseRevision   uint64
	BaseDigest     [sha256.Size]byte
	Revision       uint64
	IssuedAt       time.Time
	ExpiresAt      time.Time
	KeyID          string
	Certificates   []RevokedCertificate
	CAEpochs       []RevokedCAEpoch
	Digest         [sha256.Size]byte
	WireBytes      []byte
}

func IssueRevocationCheckpointDelta(random io.Reader, signer crypto.Signer, request RevocationCheckpointDeltaRequest) ([]byte, error) {
	if random == nil || signer == nil {
		return nil, ErrCheckpointDeltaInvalid
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrCheckpointDeltaInvalid
	}
	body := revocationCheckpointDeltaBody{
		Schema: RevocationCheckpointDeltaSchema, InstallationID: request.InstallationID,
		BaseRevision: request.BaseRevision, BaseDigest: hex.EncodeToString(request.BaseDigest[:]), Revision: request.Revision,
		IssuedAt: request.IssuedAt.UTC(), ExpiresAt: request.ExpiresAt.UTC(), KeyID: request.KeyID,
		Certificates: slices.Clone(request.Certificates), CAEpochs: slices.Clone(request.CAEpochs),
	}
	normalizeRevocationCheckpointDeltaBody(&body)
	if !validRevocationCheckpointDeltaBody(body) {
		return nil, ErrCheckpointDeltaInvalid
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil || len(bodyBytes) > maxRevocationCheckpointBytes {
		return nil, ErrCheckpointDeltaInvalid
	}
	signature, err := signer.Sign(random, revocationCheckpointDeltaSigningMessage(bodyBytes), crypto.Hash(0))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, revocationCheckpointDeltaSigningMessage(bodyBytes), signature) {
		return nil, ErrCheckpointDeltaInvalid
	}
	wire, err := json.Marshal(signedRevocationCheckpointDelta{Body: bodyBytes, Signature: base64.RawStdEncoding.EncodeToString(signature)})
	if err != nil || len(wire) > maxRevocationCheckpointBytes {
		return nil, ErrCheckpointDeltaInvalid
	}
	return wire, nil
}

func VerifyRevocationCheckpointDelta(wire []byte, keys map[string]ed25519.PublicKey, installationID string, now time.Time, skew time.Duration) (VerifiedRevocationCheckpointDelta, error) {
	if len(wire) == 0 || len(wire) > maxRevocationCheckpointBytes || !validCheckpointIdentity(installationID) || skew < 0 || skew > 10*time.Minute || len(keys) == 0 {
		return VerifiedRevocationCheckpointDelta{}, ErrCheckpointDeltaInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var document signedRevocationCheckpointDelta
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return VerifiedRevocationCheckpointDelta{}, ErrCheckpointDeltaInvalid
	}
	bodyDecoder := json.NewDecoder(bytes.NewReader(document.Body))
	bodyDecoder.DisallowUnknownFields()
	var body revocationCheckpointDeltaBody
	if bodyDecoder.Decode(&body) != nil || bodyDecoder.Decode(&struct{}{}) != io.EOF || !validRevocationCheckpointDeltaBody(body) || body.InstallationID != installationID {
		return VerifiedRevocationCheckpointDelta{}, ErrCheckpointDeltaInvalid
	}
	canonical, err := json.Marshal(body)
	if err != nil || !bytes.Equal(canonical, document.Body) || body.IssuedAt.After(now.UTC().Add(skew)) || !body.ExpiresAt.After(now.UTC().Add(-skew)) {
		return VerifiedRevocationCheckpointDelta{}, ErrCheckpointDeltaInvalid
	}
	key, found := keys[body.KeyID]
	signature, err := base64.RawStdEncoding.DecodeString(document.Signature)
	if !found || len(key) != ed25519.PublicKeySize || err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, revocationCheckpointDeltaSigningMessage(document.Body), signature) {
		return VerifiedRevocationCheckpointDelta{}, ErrCheckpointDeltaInvalid
	}
	baseDigest, err := hex.DecodeString(body.BaseDigest)
	if err != nil || len(baseDigest) != sha256.Size {
		return VerifiedRevocationCheckpointDelta{}, ErrCheckpointDeltaInvalid
	}
	var digest [sha256.Size]byte
	copy(digest[:], baseDigest)
	return VerifiedRevocationCheckpointDelta{InstallationID: body.InstallationID, BaseRevision: body.BaseRevision, BaseDigest: digest,
		Revision: body.Revision, IssuedAt: body.IssuedAt, ExpiresAt: body.ExpiresAt, KeyID: body.KeyID,
		Certificates: slices.Clone(body.Certificates), CAEpochs: slices.Clone(body.CAEpochs), Digest: sha256.Sum256(wire), WireBytes: slices.Clone(wire)}, nil
}

func ReplayRevocationCheckpointDelta(current VerifiedRevocationCheckpoint, delta VerifiedRevocationCheckpointDelta) (RevocationCheckpointRequest, error) {
	if !validCheckpointIdentity(current.InstallationID) || current.InstallationID != delta.InstallationID || current.Revision != delta.BaseRevision || current.Digest != delta.BaseDigest || delta.Revision != delta.BaseRevision+1 ||
		!validRevocationCheckpointDeltaBody(revocationCheckpointDeltaBody{Schema: RevocationCheckpointDeltaSchema, InstallationID: delta.InstallationID,
			BaseRevision: delta.BaseRevision, BaseDigest: hex.EncodeToString(delta.BaseDigest[:]), Revision: delta.Revision, IssuedAt: delta.IssuedAt,
			ExpiresAt: delta.ExpiresAt, KeyID: delta.KeyID, Certificates: slices.Clone(delta.Certificates), CAEpochs: slices.Clone(delta.CAEpochs)}) {
		return RevocationCheckpointRequest{}, ErrCheckpointDeltaConflict
	}
	certificates, err := mergeRevokedCertificates(current.Certificates, delta.Certificates)
	if err != nil {
		return RevocationCheckpointRequest{}, err
	}
	epochs, err := mergeRevokedCAEpochs(current.CAEpochs, delta.CAEpochs)
	if err != nil {
		return RevocationCheckpointRequest{}, err
	}
	return RevocationCheckpointRequest{InstallationID: delta.InstallationID, Revision: delta.Revision, IssuedAt: delta.IssuedAt,
		ExpiresAt: delta.ExpiresAt, KeyID: delta.KeyID, Certificates: certificates, CAEpochs: epochs}, nil
}

type RevocationCheckpointDeltaApplier struct {
	store            CheckpointLKGStore
	installationID   string
	keys             map[string]ed25519.PublicKey
	signer           crypto.Signer
	keyID            string
	clock            Clock
	maximumClockSkew time.Duration
}

func NewRevocationCheckpointDeltaApplier(store CheckpointLKGStore, installationID string, keys map[string]ed25519.PublicKey, signer crypto.Signer, keyID string, clock Clock, maximumClockSkew time.Duration) (*RevocationCheckpointDeltaApplier, error) {
	if store == nil || !validCheckpointIdentity(installationID) || len(keys) == 0 || signer == nil || !validCheckpointIdentity(keyID) || clock == nil || maximumClockSkew < 0 || maximumClockSkew > 10*time.Minute {
		return nil, ErrCheckpointDeltaInvalid
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	trustedKey, trusted := keys[keyID]
	if !ok || len(publicKey) != ed25519.PublicKeySize || !trusted || len(trustedKey) != ed25519.PublicKeySize || !bytes.Equal(publicKey, trustedKey) {
		return nil, ErrCheckpointDeltaInvalid
	}
	copyKeys := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		if !validCheckpointIdentity(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrCheckpointDeltaInvalid
		}
		copyKeys[id] = slices.Clone(key)
	}
	return &RevocationCheckpointDeltaApplier{store: store, installationID: installationID, keys: copyKeys, signer: signer, keyID: keyID,
		clock: clock, maximumClockSkew: maximumClockSkew}, nil
}

func (applier *RevocationCheckpointDeltaApplier) Apply(ctx context.Context, wire []byte) (VerifiedRevocationCheckpoint, error) {
	if applier == nil || ctx == nil {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointDeltaInvalid
	}
	delta, err := VerifyRevocationCheckpointDelta(wire, applier.keys, applier.installationID, applier.clock().UTC(), applier.maximumClockSkew)
	if err != nil {
		return VerifiedRevocationCheckpoint{}, err
	}
	current, found, err := applier.store.Load(ctx, applier.installationID)
	if err != nil {
		return VerifiedRevocationCheckpoint{}, err
	}
	if !found {
		current = VerifiedRevocationCheckpoint{InstallationID: applier.installationID, Digest: [sha256.Size]byte{}}
	} else if len(current.WireBytes) != 0 {
		stored, decodeErr := decodeStoredRevocationCheckpoint(current.WireBytes, applier.keys, applier.installationID)
		if decodeErr != nil || stored.Revision != current.Revision || stored.Digest != current.Digest {
			return VerifiedRevocationCheckpoint{}, ErrCheckpointDeltaConflict
		}
		current = stored
	}
	request, err := ReplayRevocationCheckpointDelta(current, delta)
	if err != nil {
		if errors.Is(err, ErrCheckpointDeltaConflict) && found && delta.Revision <= current.Revision {
			return VerifiedRevocationCheckpoint{}, ErrCheckpointDeltaReplay
		}
		return VerifiedRevocationCheckpoint{}, err
	}
	request.KeyID = applier.keyID
	fullWire, err := IssueRevocationCheckpoint(crand.Reader, applier.signer, request)
	if err != nil {
		return VerifiedRevocationCheckpoint{}, err
	}
	checkpoint, err := verifyRevocationCheckpoint(fullWire, applier.keys, applier.installationID, applier.clock().UTC(), applier.maximumClockSkew)
	if err != nil {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointDeltaInvalid
	}
	if err := applier.store.StoreNext(ctx, checkpoint, current.Revision); err != nil {
		return VerifiedRevocationCheckpoint{}, err
	}
	return checkpoint, nil
}

func normalizeRevocationCheckpointDeltaBody(body *revocationCheckpointDeltaBody) {
	sort.Slice(body.Certificates, func(i, j int) bool {
		if body.Certificates[i].NodeID != body.Certificates[j].NodeID {
			return bytes.Compare(body.Certificates[i].NodeID[:], body.Certificates[j].NodeID[:]) < 0
		}
		return body.Certificates[i].SerialNumber < body.Certificates[j].SerialNumber
	})
	sort.Slice(body.CAEpochs, func(i, j int) bool {
		if body.CAEpochs[i].Epoch != body.CAEpochs[j].Epoch {
			return body.CAEpochs[i].Epoch < body.CAEpochs[j].Epoch
		}
		return bytes.Compare(body.CAEpochs[i].EpochID[:], body.CAEpochs[j].EpochID[:]) < 0
	})
}

func validRevocationCheckpointDeltaBody(body revocationCheckpointDeltaBody) bool {
	if body.Schema != RevocationCheckpointDeltaSchema || !validCheckpointIdentity(body.InstallationID) || body.Revision == 0 || body.Revision != body.BaseRevision+1 ||
		body.IssuedAt.IsZero() || body.ExpiresAt.IsZero() || !body.IssuedAt.Before(body.ExpiresAt) || !validCheckpointIdentity(body.KeyID) || len(body.BaseDigest) != sha256.Size*2 {
		return false
	}
	decodedDigest, err := hex.DecodeString(body.BaseDigest)
	if err != nil || (body.BaseRevision == 0 && !bytes.Equal(decodedDigest, make([]byte, sha256.Size))) ||
		(body.BaseRevision > 0 && bytes.Equal(decodedDigest, make([]byte, sha256.Size))) {
		return false
	}
	for index, item := range body.Certificates {
		if item.NodeID == uuid.Nil || !validSerial(item.SerialNumber) || item.AuthorizationRevision == 0 || index > 0 && item.NodeID == body.Certificates[index-1].NodeID && item.SerialNumber <= body.Certificates[index-1].SerialNumber {
			return false
		}
	}
	seenEpochIDs := make(map[uuid.UUID]struct{}, len(body.CAEpochs))
	for index, item := range body.CAEpochs {
		if item.EpochID == uuid.Nil || item.Epoch < 1 || index > 0 && item.Epoch <= body.CAEpochs[index-1].Epoch {
			return false
		}
		if _, exists := seenEpochIDs[item.EpochID]; exists {
			return false
		}
		seenEpochIDs[item.EpochID] = struct{}{}
	}
	return true
}

func mergeRevokedCertificates(current, delta []RevokedCertificate) ([]RevokedCertificate, error) {
	merged := append([]RevokedCertificate(nil), current...)
	seen := make(map[string]RevokedCertificate, len(merged)+len(delta))
	for _, item := range merged {
		key := item.NodeID.String() + "\x00" + item.SerialNumber
		if previous, exists := seen[key]; exists && previous.AuthorizationRevision != item.AuthorizationRevision {
			return nil, ErrCheckpointDeltaConflict
		}
		if _, exists := seen[key]; exists {
			return nil, ErrCheckpointDeltaInvalid
		}
		seen[key] = item
	}
	for _, item := range delta {
		key := item.NodeID.String() + "\x00" + item.SerialNumber
		if previous, exists := seen[key]; exists {
			if previous.AuthorizationRevision != item.AuthorizationRevision {
				return nil, ErrCheckpointDeltaConflict
			}
			return nil, ErrCheckpointDeltaInvalid
		}
		seen[key] = item
		merged = append(merged, item)
	}
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].NodeID != merged[j].NodeID {
			return bytes.Compare(merged[i].NodeID[:], merged[j].NodeID[:]) < 0
		}
		return merged[i].SerialNumber < merged[j].SerialNumber
	})
	return merged, nil
}

func mergeRevokedCAEpochs(current, delta []RevokedCAEpoch) ([]RevokedCAEpoch, error) {
	merged := append([]RevokedCAEpoch(nil), current...)
	seenID := make(map[uuid.UUID]RevokedCAEpoch, len(merged)+len(delta))
	seenEpoch := make(map[int64]uuid.UUID, len(merged)+len(delta))
	for _, item := range merged {
		if previous, exists := seenID[item.EpochID]; exists && previous.Epoch != item.Epoch || seenEpoch[item.Epoch] != uuid.Nil && seenEpoch[item.Epoch] != item.EpochID {
			return nil, ErrCheckpointDeltaConflict
		}
		seenID[item.EpochID], seenEpoch[item.Epoch] = item, item.EpochID
	}
	for _, item := range delta {
		if previous, exists := seenID[item.EpochID]; exists {
			if previous.Epoch != item.Epoch {
				return nil, ErrCheckpointDeltaConflict
			}
			return nil, ErrCheckpointDeltaInvalid
		}
		if existingID := seenEpoch[item.Epoch]; existingID != uuid.Nil {
			return nil, ErrCheckpointDeltaConflict
		}
		seenID[item.EpochID], seenEpoch[item.Epoch] = item, item.EpochID
		merged = append(merged, item)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Epoch < merged[j].Epoch })
	return merged, nil
}

func decodeStoredRevocationCheckpoint(wire []byte, keys map[string]ed25519.PublicKey, installationID string) (VerifiedRevocationCheckpoint, error) {
	if len(wire) == 0 || len(wire) > maxRevocationCheckpointBytes {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointDeltaConflict
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var document signedRevocationCheckpoint
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointDeltaConflict
	}
	bodyDecoder := json.NewDecoder(bytes.NewReader(document.Body))
	bodyDecoder.DisallowUnknownFields()
	var body revocationCheckpointBody
	if bodyDecoder.Decode(&body) != nil || bodyDecoder.Decode(&struct{}{}) != io.EOF || !validCheckpointBody(body) || body.InstallationID != installationID {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointDeltaConflict
	}
	canonical, err := json.Marshal(body)
	signature, err2 := base64.RawStdEncoding.DecodeString(document.Signature)
	key, found := keys[body.KeyID]
	if err != nil || err2 != nil || !bytes.Equal(canonical, document.Body) || !found || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, checkpointSigningMessage(document.Body), signature) {
		return VerifiedRevocationCheckpoint{}, ErrCheckpointDeltaConflict
	}
	return VerifiedRevocationCheckpoint{InstallationID: body.InstallationID, Revision: body.Revision, IssuedAt: body.IssuedAt, ExpiresAt: body.ExpiresAt, KeyID: body.KeyID,
		Certificates: slices.Clone(body.Certificates), CAEpochs: slices.Clone(body.CAEpochs), Digest: sha256.Sum256(wire), WireBytes: slices.Clone(wire)}, nil
}

func revocationCheckpointDeltaSigningMessage(body []byte) []byte {
	return append(append(make([]byte, 0, len(revocationCheckpointDeltaSignatureDomain)+len(body)), revocationCheckpointDeltaSignatureDomain...), body...)
}
