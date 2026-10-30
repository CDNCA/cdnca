package gatewayclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	agentIdentityTrustSchema          = "cdnca.node.identity-trust/v1"
	agentIdentityTrustSignatureDomain = "cdnca-node-identity-trust-signature/v1\x00"
	maxAgentIdentityTrustBytes        = 1 << 20
)

var (
	ErrIdentityTrustUpdate = errors.New("gateway identity trust update is invalid")
	ErrIdentityTrustReplay = errors.New("gateway identity trust revision was replayed")
)

type AgentIdentityTrustEpoch struct {
	Epoch        int64      `json:"epoch"`
	Status       string     `json:"status"`
	ChainPEM     []string   `json:"chain_pem"`
	OverlapUntil *time.Time `json:"overlap_until,omitempty"`
}

type AgentIdentityTrustUpdate struct {
	Schema         string                    `json:"schema"`
	InstallationID string                    `json:"installation_id"`
	Revision       uint64                    `json:"revision"`
	CurrentEpoch   int64                     `json:"current_epoch"`
	IssuedAt       time.Time                 `json:"issued_at"`
	ExpiresAt      time.Time                 `json:"expires_at"`
	KeyID          string                    `json:"key_id"`
	Epochs         []AgentIdentityTrustEpoch `json:"epochs"`
}

type signedAgentIdentityTrustUpdate struct {
	Body      json.RawMessage `json:"body"`
	Signature string          `json:"signature"`
}

type IdentityTrustLKG struct {
	mu               sync.RWMutex
	path             string
	installationID   string
	keys             map[string]ed25519.PublicKey
	clock            func() time.Time
	maximumClockSkew time.Duration
	revision         uint64
	expiresAt        time.Time
	digest           [32]byte
	rootPEM          []byte
}

func NewIdentityTrustLKG(path, installationID string, keys map[string]ed25519.PublicKey, clock func() time.Time, maximumClockSkew time.Duration) (*IdentityTrustLKG, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || !validAgentTrustIdentity(installationID) || clock == nil || maximumClockSkew < 0 || maximumClockSkew > 10*time.Minute || len(keys) == 0 {
		return nil, ErrIdentityTrustUpdate
	}
	copyKeys := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		if !validAgentTrustIdentity(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrIdentityTrustUpdate
		}
		copyKeys[id] = slices.Clone(key)
	}
	store := &IdentityTrustLKG{path: path, installationID: installationID, keys: copyKeys, clock: clock, maximumClockSkew: maximumClockSkew}
	if wire, err := os.ReadFile(path); err == nil {
		if _, err := store.apply(wire, false); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read identity trust LKG: %w", err)
	}
	return store, nil
}

func (store *IdentityTrustLKG) ApplyIdentityTrustUpdate(wire []byte) (uint64, error) {
	return store.apply(wire, true)
}

func (store *IdentityTrustLKG) apply(wire []byte, persist bool) (uint64, error) {
	if store == nil || len(wire) == 0 || len(wire) > maxAgentIdentityTrustBytes {
		return 0, ErrIdentityTrustUpdate
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var document signedAgentIdentityTrustUpdate
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return 0, ErrIdentityTrustUpdate
	}
	bodyDecoder := json.NewDecoder(bytes.NewReader(document.Body))
	bodyDecoder.DisallowUnknownFields()
	var body AgentIdentityTrustUpdate
	if bodyDecoder.Decode(&body) != nil || bodyDecoder.Decode(&struct{}{}) != io.EOF || !validAgentIdentityTrustUpdate(body, store.installationID) {
		return 0, ErrIdentityTrustUpdate
	}
	canonical, _ := json.Marshal(body)
	now := store.clock().UTC()
	if !bytes.Equal(canonical, document.Body) || body.IssuedAt.After(now.Add(store.maximumClockSkew)) || !body.ExpiresAt.After(now.Add(-store.maximumClockSkew)) {
		return 0, ErrIdentityTrustUpdate
	}
	key, found := store.keys[body.KeyID]
	signature, err := base64.RawStdEncoding.DecodeString(document.Signature)
	message := append(append([]byte{}, agentIdentityTrustSignatureDomain...), document.Body...)
	if !found || err != nil || !ed25519.Verify(key, message, signature) {
		return 0, ErrIdentityTrustUpdate
	}
	rootPEM, err := activeAgentIdentityRoots(body, now)
	if err != nil {
		return 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.revision > 0 && body.Revision <= store.revision {
		return 0, ErrIdentityTrustReplay
	}
	if persist {
		if err := persistIdentityTrustWire(store.path, wire); err != nil {
			return 0, err
		}
	}
	store.revision, store.expiresAt, store.digest, store.rootPEM = body.Revision, body.ExpiresAt, sha256.Sum256(wire), rootPEM
	return body.Revision, nil
}

func (store *IdentityTrustLKG) RootPEM() ([]byte, uint64, bool) {
	if store == nil {
		return nil, 0, false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	valid := store.revision > 0 && store.clock().UTC().Before(store.expiresAt.Add(store.maximumClockSkew))
	return slices.Clone(store.rootPEM), store.revision, valid
}

func validAgentIdentityTrustUpdate(body AgentIdentityTrustUpdate, installationID string) bool {
	if body.Schema != agentIdentityTrustSchema || body.InstallationID != installationID || body.Revision == 0 || body.CurrentEpoch < 1 || !body.IssuedAt.Before(body.ExpiresAt) || !validAgentTrustIdentity(body.KeyID) || len(body.Epochs) < 1 || len(body.Epochs) > 2 {
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

func activeAgentIdentityRoots(body AgentIdentityTrustUpdate, now time.Time) ([]byte, error) {
	var result []byte
	for _, epoch := range body.Epochs {
		if epoch.Status == "overlap" && (epoch.OverlapUntil == nil || !now.Before(*epoch.OverlapUntil)) {
			continue
		}
		certificates := make([]*x509.Certificate, len(epoch.ChainPEM))
		for index, encoded := range epoch.ChainPEM {
			block, rest := pem.Decode([]byte(encoded))
			if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
				return nil, ErrIdentityTrustUpdate
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil || !certificate.IsCA {
				return nil, ErrIdentityTrustUpdate
			}
			certificates[index] = certificate
		}
		for index := 0; index < len(certificates)-1; index++ {
			if certificates[index].CheckSignatureFrom(certificates[index+1]) != nil {
				return nil, ErrIdentityTrustUpdate
			}
		}
		root := certificates[len(certificates)-1]
		if root.CheckSignatureFrom(root) != nil {
			return nil, ErrIdentityTrustUpdate
		}
		if !validateAgentIdentityTrustLineage(certificates) {
			return nil, ErrIdentityTrustUpdate
		}
		result = append(result, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
	}
	if len(result) == 0 {
		return nil, ErrIdentityTrustUpdate
	}
	return result, nil
}

func persistIdentityTrustWire(path string, wire []byte) error {
	if err := validateIdentityTrustDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".identity-trust-*")
	if err != nil {
		return fmt.Errorf("create identity trust LKG: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(wire)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporaryPath, path)
	}
	if err != nil {
		return fmt.Errorf("persist identity trust LKG: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open identity trust directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync identity trust directory: %w", err)
	}
	return nil
}

func validateIdentityTrustDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return ErrIdentityTrustUpdate
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create identity trust directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return ErrIdentityTrustUpdate
	}
	for current := path; current != filepath.Dir(current); current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrIdentityTrustUpdate
		}
	}
	return nil
}

func validAgentTrustIdentity(value string) bool {
	return value != "" && len(value) <= 255 && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}
