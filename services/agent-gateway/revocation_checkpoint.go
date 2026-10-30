package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	revocationCheckpointSchema          = "cdnca.node.revocation-checkpoint/v1"
	revocationCheckpointSignatureDomain = "cdnca-node-revocation-checkpoint-signature/v1\x00"
	maxRevocationCheckpointBytes        = 4 << 20
)

var (
	ErrRevocationCheckpointInvalid = errors.New("node revocation checkpoint is invalid")
	ErrRevocationCheckpointReplay  = errors.New("node revocation checkpoint revision was replayed")
)

type gatewayRevokedCertificate struct {
	NodeID                string `json:"node_id"`
	SerialNumber          string `json:"serial_number"`
	AuthorizationRevision uint64 `json:"authorization_revision"`
}

type gatewayRevokedCAEpoch struct {
	EpochID string `json:"epoch_id"`
	Epoch   int64  `json:"epoch"`
}

type gatewayCheckpointBody struct {
	Schema         string                      `json:"schema"`
	InstallationID string                      `json:"installation_id"`
	Revision       uint64                      `json:"revision"`
	IssuedAt       time.Time                   `json:"issued_at"`
	ExpiresAt      time.Time                   `json:"expires_at"`
	KeyID          string                      `json:"key_id"`
	Certificates   []gatewayRevokedCertificate `json:"certificates"`
	CAEpochs       []gatewayRevokedCAEpoch     `json:"ca_epochs"`
}

type gatewaySignedCheckpointDocument struct {
	Body      json.RawMessage `json:"body"`
	Signature string          `json:"signature"`
}

type RevocationCheckpointSnapshot struct {
	Revision     uint64
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Digest       [32]byte
	Certificates []gatewayRevokedCertificate
	CAEpochs     []gatewayRevokedCAEpoch
}

type RevocationCheckpointCache struct {
	mu               sync.RWMutex
	installationID   string
	keys             map[string]ed25519.PublicKey
	clock            func() time.Time
	maximumClockSkew time.Duration
	current          RevocationCheckpointSnapshot
	found            bool
}

func NewRevocationCheckpointCache(installationID string, keys map[string]ed25519.PublicKey, clock func() time.Time, maximumClockSkew time.Duration) (*RevocationCheckpointCache, error) {
	if !validRevocationIdentity(installationID) || clock == nil || maximumClockSkew < 0 || maximumClockSkew > 10*time.Minute || len(keys) == 0 {
		return nil, ErrRevocationCheckpointInvalid
	}
	copyKeys := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, key := range keys {
		if !validRevocationIdentity(keyID) || len(key) != ed25519.PublicKeySize {
			return nil, ErrRevocationCheckpointInvalid
		}
		copyKeys[keyID] = slices.Clone(key)
	}
	return &RevocationCheckpointCache{installationID: installationID, keys: copyKeys, clock: clock, maximumClockSkew: maximumClockSkew}, nil
}

func (cache *RevocationCheckpointCache) ApplyRevocationCheckpoint(wire []byte) (RevocationCheckpointSnapshot, error) {
	if cache == nil || len(wire) == 0 || len(wire) > maxRevocationCheckpointBytes {
		return RevocationCheckpointSnapshot{}, ErrRevocationCheckpointInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var document gatewaySignedCheckpointDocument
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return RevocationCheckpointSnapshot{}, ErrRevocationCheckpointInvalid
	}
	bodyDecoder := json.NewDecoder(bytes.NewReader(document.Body))
	bodyDecoder.DisallowUnknownFields()
	var body gatewayCheckpointBody
	if bodyDecoder.Decode(&body) != nil || bodyDecoder.Decode(&struct{}{}) != io.EOF || !validGatewayCheckpointBody(body) || body.InstallationID != cache.installationID {
		return RevocationCheckpointSnapshot{}, ErrRevocationCheckpointInvalid
	}
	canonical, _ := json.Marshal(body)
	now := cache.clock().UTC()
	if !bytes.Equal(canonical, document.Body) || body.IssuedAt.After(now.Add(cache.maximumClockSkew)) || !body.ExpiresAt.After(now.Add(-cache.maximumClockSkew)) {
		return RevocationCheckpointSnapshot{}, ErrRevocationCheckpointInvalid
	}
	key, found := cache.keys[body.KeyID]
	signature, err := base64.RawStdEncoding.DecodeString(document.Signature)
	message := append(append(make([]byte, 0, len(revocationCheckpointSignatureDomain)+len(document.Body)), revocationCheckpointSignatureDomain...), document.Body...)
	if !found || err != nil || !ed25519.Verify(key, message, signature) {
		return RevocationCheckpointSnapshot{}, ErrRevocationCheckpointInvalid
	}
	next := RevocationCheckpointSnapshot{Revision: body.Revision, IssuedAt: body.IssuedAt, ExpiresAt: body.ExpiresAt,
		Digest: sha256.Sum256(wire), Certificates: slices.Clone(body.Certificates), CAEpochs: slices.Clone(body.CAEpochs)}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.found && next.Revision <= cache.current.Revision {
		return RevocationCheckpointSnapshot{}, ErrRevocationCheckpointReplay
	}
	cache.current, cache.found = next, true
	return next, nil
}

func (cache *RevocationCheckpointCache) Snapshot() (RevocationCheckpointSnapshot, bool) {
	if cache == nil {
		return RevocationCheckpointSnapshot{}, false
	}
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	if !cache.found {
		return RevocationCheckpointSnapshot{}, false
	}
	result := cache.current
	result.Certificates = slices.Clone(result.Certificates)
	result.CAEpochs = slices.Clone(result.CAEpochs)
	return result, true
}

func (cache *RevocationCheckpointCache) CertificateRevoked(nodeID, serialNumber string, minimumAuthorizationRevision uint64) bool {
	snapshot, found := cache.Snapshot()
	if !found || !cache.clock().UTC().Before(snapshot.ExpiresAt.Add(cache.maximumClockSkew)) {
		return true
	}
	for _, item := range snapshot.Certificates {
		if item.NodeID == nodeID && item.SerialNumber == serialNumber {
			return item.AuthorizationRevision >= minimumAuthorizationRevision
		}
	}
	return false
}

func (cache *RevocationCheckpointCache) CAEpochRevoked(epoch int64) bool {
	snapshot, found := cache.Snapshot()
	if !found || !cache.clock().UTC().Before(snapshot.ExpiresAt.Add(cache.maximumClockSkew)) {
		return true
	}
	for _, item := range snapshot.CAEpochs {
		if item.Epoch == epoch {
			return true
		}
	}
	return false
}

func validGatewayCheckpointBody(body gatewayCheckpointBody) bool {
	if body.Schema != revocationCheckpointSchema || !validRevocationIdentity(body.InstallationID) || body.Revision == 0 ||
		body.IssuedAt.IsZero() || body.ExpiresAt.IsZero() || !body.IssuedAt.Before(body.ExpiresAt) || !validRevocationIdentity(body.KeyID) {
		return false
	}
	for index, item := range body.Certificates {
		parsed, err := uuid.Parse(item.NodeID)
		if err != nil || parsed.String() != item.NodeID || !validGatewaySerial(item.SerialNumber) || item.AuthorizationRevision == 0 ||
			index > 0 && (item.NodeID < body.Certificates[index-1].NodeID || item.NodeID == body.Certificates[index-1].NodeID && item.SerialNumber <= body.Certificates[index-1].SerialNumber) {
			return false
		}
	}
	for index, item := range body.CAEpochs {
		parsed, err := uuid.Parse(item.EpochID)
		if err != nil || parsed.String() != item.EpochID || item.Epoch < 1 || index > 0 && item.Epoch <= body.CAEpochs[index-1].Epoch {
			return false
		}
	}
	return true
}

func validRevocationIdentity(value string) bool {
	return value != "" && len(value) <= 255 && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

func validGatewaySerial(value string) bool {
	if value == "" || len(value) > 128 || strings.ToLower(value) != value || value == "0" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
