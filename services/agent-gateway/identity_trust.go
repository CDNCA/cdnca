package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"slices"
	"sync"
	"time"
)

const (
	identityTrustSchema          = "cdnca.node.identity-trust/v1"
	identityTrustSignatureDomain = "cdnca-node-identity-trust-signature/v1\x00"
)

var (
	ErrIdentityTrustInvalid = errors.New("node identity trust update is invalid")
	ErrIdentityTrustReplay  = errors.New("node identity trust revision was replayed")
)

type IdentityTrustEpoch struct {
	Epoch        int64      `json:"epoch"`
	Status       string     `json:"status"`
	ChainPEM     []string   `json:"chain_pem"`
	OverlapUntil *time.Time `json:"overlap_until,omitempty"`
}

type IdentityTrustUpdate struct {
	Schema         string               `json:"schema"`
	InstallationID string               `json:"installation_id"`
	Revision       uint64               `json:"revision"`
	CurrentEpoch   int64                `json:"current_epoch"`
	IssuedAt       time.Time            `json:"issued_at"`
	ExpiresAt      time.Time            `json:"expires_at"`
	KeyID          string               `json:"key_id"`
	Epochs         []IdentityTrustEpoch `json:"epochs"`
}

type signedIdentityTrustUpdate struct {
	Body      json.RawMessage `json:"body"`
	Signature string          `json:"signature"`
}
type identityTrustChain struct {
	epoch                int64
	status               string
	overlapUntil         *time.Time
	roots, intermediates *x509.CertPool
}

type IdentityTrustSnapshot struct {
	Revision     uint64
	CurrentEpoch int64
	ExpiresAt    time.Time
	Digest       [32]byte
}

type IdentityTrustValidator struct {
	mu               sync.RWMutex
	installationID   string
	keys             map[string]ed25519.PublicKey
	clock            func() time.Time
	maximumClockSkew time.Duration
	snapshot         IdentityTrustSnapshot
	chains           []identityTrustChain
	found            bool
}

func NewIdentityTrustValidator(installationID string, keys map[string]ed25519.PublicKey, clock func() time.Time, maximumClockSkew time.Duration) (*IdentityTrustValidator, error) {
	if !validRevocationIdentity(installationID) || clock == nil || maximumClockSkew < 0 || maximumClockSkew > 10*time.Minute || len(keys) == 0 {
		return nil, ErrIdentityTrustInvalid
	}
	copyKeys := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		if !validRevocationIdentity(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrIdentityTrustInvalid
		}
		copyKeys[id] = slices.Clone(key)
	}
	return &IdentityTrustValidator{installationID: installationID, keys: copyKeys, clock: clock, maximumClockSkew: maximumClockSkew}, nil
}

func (validator *IdentityTrustValidator) ApplyIdentityTrustUpdate(wire []byte) (IdentityTrustSnapshot, error) {
	if validator == nil || len(wire) == 0 || len(wire) > maxRevocationCheckpointBytes {
		return IdentityTrustSnapshot{}, ErrIdentityTrustInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var document signedIdentityTrustUpdate
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return IdentityTrustSnapshot{}, ErrIdentityTrustInvalid
	}
	bodyDecoder := json.NewDecoder(bytes.NewReader(document.Body))
	bodyDecoder.DisallowUnknownFields()
	var body IdentityTrustUpdate
	if bodyDecoder.Decode(&body) != nil || bodyDecoder.Decode(&struct{}{}) != io.EOF || !validIdentityTrustUpdate(body, validator.installationID) {
		return IdentityTrustSnapshot{}, ErrIdentityTrustInvalid
	}
	canonical, _ := json.Marshal(body)
	now := validator.clock().UTC()
	if !bytes.Equal(canonical, document.Body) || body.IssuedAt.After(now.Add(validator.maximumClockSkew)) || !body.ExpiresAt.After(now.Add(-validator.maximumClockSkew)) {
		return IdentityTrustSnapshot{}, ErrIdentityTrustInvalid
	}
	key, found := validator.keys[body.KeyID]
	signature, err := base64.RawStdEncoding.DecodeString(document.Signature)
	message := append(append([]byte{}, identityTrustSignatureDomain...), document.Body...)
	if !found || err != nil || !ed25519.Verify(key, message, signature) {
		return IdentityTrustSnapshot{}, ErrIdentityTrustInvalid
	}
	chains := make([]identityTrustChain, len(body.Epochs))
	for index, epoch := range body.Epochs {
		parsed, err := parseIdentityTrustChain(epoch)
		if err != nil {
			return IdentityTrustSnapshot{}, err
		}
		chains[index] = parsed
	}
	next := IdentityTrustSnapshot{Revision: body.Revision, CurrentEpoch: body.CurrentEpoch, ExpiresAt: body.ExpiresAt, Digest: sha256.Sum256(wire)}
	validator.mu.Lock()
	defer validator.mu.Unlock()
	if validator.found && next.Revision <= validator.snapshot.Revision {
		return IdentityTrustSnapshot{}, ErrIdentityTrustReplay
	}
	validator.snapshot, validator.chains, validator.found = next, chains, true
	return next, nil
}

func (validator *IdentityTrustValidator) ValidateNodeCertificate(leaf *x509.Certificate) error {
	if validator == nil || leaf == nil {
		return ErrIdentityTrustInvalid
	}
	validator.mu.RLock()
	defer validator.mu.RUnlock()
	if !validator.found {
		return ErrIdentityTrustInvalid
	}
	now := validator.clock().UTC()
	if !now.Before(validator.snapshot.ExpiresAt.Add(validator.maximumClockSkew)) {
		return ErrIdentityTrustInvalid
	}
	for _, chain := range validator.chains {
		if chain.status == "overlap" && (chain.overlapUntil == nil || !now.Before(*chain.overlapUntil)) {
			continue
		}
		verifyAt := now
		if verifyAt.Before(leaf.NotBefore) && !verifyAt.Add(validator.maximumClockSkew).Before(leaf.NotBefore) {
			verifyAt = leaf.NotBefore
		}
		if !verifyAt.Before(leaf.NotAfter) && verifyAt.Add(-validator.maximumClockSkew).Before(leaf.NotAfter) {
			verifyAt = leaf.NotAfter.Add(-time.Nanosecond)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: chain.roots, Intermediates: chain.intermediates, CurrentTime: verifyAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
			return nil
		}
	}
	return ErrIdentityTrustInvalid
}

func validIdentityTrustUpdate(body IdentityTrustUpdate, installationID string) bool {
	if body.Schema != identityTrustSchema || body.InstallationID != installationID || body.Revision == 0 || body.CurrentEpoch < 1 || !body.IssuedAt.Before(body.ExpiresAt) || !validRevocationIdentity(body.KeyID) || len(body.Epochs) < 1 || len(body.Epochs) > 2 {
		return false
	}
	active := 0
	for index, epoch := range body.Epochs {
		if epoch.Epoch < 1 || index > 0 && epoch.Epoch <= body.Epochs[index-1].Epoch || len(epoch.ChainPEM) == 0 || len(epoch.ChainPEM) > 8 {
			return false
		}
		switch epoch.Status {
		case "active":
			active++
			if epoch.Epoch != body.CurrentEpoch || epoch.OverlapUntil != nil {
				return false
			}
		case "overlap":
			if epoch.OverlapUntil == nil || !body.IssuedAt.Before(*epoch.OverlapUntil) {
				return false
			}
		default:
			return false
		}
	}
	return active == 1
}

func parseIdentityTrustChain(epoch IdentityTrustEpoch) (identityTrustChain, error) {
	certificates := make([]*x509.Certificate, len(epoch.ChainPEM))
	for index, encoded := range epoch.ChainPEM {
		block, rest := pem.Decode([]byte(encoded))
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
			return identityTrustChain{}, ErrIdentityTrustInvalid
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return identityTrustChain{}, ErrIdentityTrustInvalid
		}
		certificates[index] = cert
	}
	for index := 0; index < len(certificates)-1; index++ {
		if certificates[index].CheckSignatureFrom(certificates[index+1]) != nil {
			return identityTrustChain{}, ErrIdentityTrustInvalid
		}
	}
	root := certificates[len(certificates)-1]
	if root.CheckSignatureFrom(root) != nil {
		return identityTrustChain{}, ErrIdentityTrustInvalid
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, certificate := range certificates[:len(certificates)-1] {
		intermediates.AddCert(certificate)
	}
	return identityTrustChain{epoch: epoch.Epoch, status: epoch.Status, overlapUntil: epoch.OverlapUntil, roots: roots, intermediates: intermediates}, nil
}
