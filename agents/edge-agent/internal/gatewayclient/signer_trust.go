package gatewayclient

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
)

// signerTrustOverlay is the verified node signer trust document applied over
// the installed artifacts.json (docs/architecture/signer-revocation-offline-and-edge.md §3).
type signerTrustOverlay struct {
	revision     uint64
	trusted      map[string]crypto.PublicKey
	revokedIDs   map[string]bool
	revokedPrint map[string]bool
	// installationBan are the keys of usage installation-ban (ADR 0014):
	// never artifact keys, only for the license service's ban documents.
	installationBan map[string]ed25519.PublicKey
}

func newSignerTrustOverlay(document edgesignertrust.Document) (*signerTrustOverlay, error) {
	overlay := &signerTrustOverlay{revision: document.Revision, trusted: map[string]crypto.PublicKey{},
		revokedIDs: map[string]bool{}, revokedPrint: map[string]bool{},
		installationBan: document.InstallationBanKeys()}
	for _, revoked := range document.RevokedKeys {
		overlay.revokedIDs[revoked.KeyID] = true
		if revoked.PublicKeySHA256 != "" {
			overlay.revokedPrint[revoked.PublicKeySHA256] = true
		}
	}
	for _, trusted := range document.TrustedKeys {
		if !trusted.ArtifactKey() {
			continue
		}
		key, err := edgesignertrust.ParsePublicKeyPEM(trusted.PublicKeyPEM)
		if err != nil {
			return nil, err
		}
		overlay.trusted[trusted.KeyID] = key
	}
	return overlay, nil
}

func (overlay *signerTrustOverlay) revokes(keyID string, publicKey crypto.PublicKey) bool {
	if overlay == nil {
		return false
	}
	if overlay.revokedIDs[keyID] {
		return true
	}
	if publicKey == nil || len(overlay.revokedPrint) == 0 {
		return false
	}
	fingerprint, err := edgesignertrust.PublicKeySHA256(publicKey)
	return err == nil && overlay.revokedPrint[fingerprint]
}

func (s *TrustStore) setOverlay(overlay *signerTrustOverlay) {
	s.mu.Lock()
	s.overlay = overlay
	s.mu.Unlock()
}

// InstallationBanKeys are the applied document's installation-ban keys
// (none before a document was applied).
func (s *TrustStore) InstallationBanKeys() map[string]ed25519.PublicKey {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.overlay == nil {
		return nil
	}
	keys := make(map[string]ed25519.PublicKey, len(s.overlay.installationBan))
	for id, key := range s.overlay.installationBan {
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	return keys
}

// SignerTrustRevision is the applied node signer trust revision (0 = none).
func (s *TrustStore) SignerTrustRevision() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.overlay == nil {
		return 0
	}
	return s.overlay.revision
}

const (
	signerTrustStateSchema = "cdnca.edge.signer-trust-state/v1"
	signerTrustStateFile   = "state.json"
)

type signerTrustState struct {
	Schema    string `json:"schema"`
	Revision  uint64 `json:"revision"`
	Document  []byte `json:"document"`
	AppliedAt string `json:"applied_at"`
}

// SignerTrustRuntime persists and applies node signer trust bundles. State is
// <dir>/state.json (0600): the exact offline document bytes of the highest
// applied revision; it is restored before anything verifies a signature.
type SignerTrustRuntime struct {
	dir    string
	nodeID string
	trust  *TrustStore
	now    func() time.Time
	mu     sync.Mutex
	state  signerTrustState
}

func NewSignerTrustRuntime(dir, nodeID string, trust *TrustStore, now func() time.Time) (*SignerTrustRuntime, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || nodeID == "" || trust == nil {
		return nil, fmt.Errorf("%w: signer trust runtime configuration is invalid", ErrInvalidConfiguration)
	}
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &SignerTrustRuntime{dir: dir, nodeID: nodeID, trust: trust, now: now}, nil
}

// Restore applies the persisted document. A missing file is a node that never
// received one. An unreadable file is moved aside and reported: the node keeps
// its installed trust until the control plane delivers the document again.
func (runtime *SignerTrustRuntime) Restore() error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	path := filepath.Join(runtime.dir, signerTrustStateFile)
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	state, document, decodeErr := decodeSignerTrustState(content)
	if err == nil && decodeErr == nil {
		overlay, overlayErr := newSignerTrustOverlay(document.Document)
		if overlayErr == nil {
			runtime.state = state
			runtime.trust.setOverlay(overlay)
			return nil
		}
		decodeErr = overlayErr
	}
	quarantine := path + ".invalid-" + runtime.now().UTC().Format("20060102T150405Z")
	_ = os.Rename(path, quarantine)
	return fmt.Errorf("node signer trust state is unreadable (moved to %s): %w", quarantine, errors.Join(err, decodeErr))
}

func decodeSignerTrustState(content []byte) (signerTrustState, edgesignertrust.Signed, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var state signerTrustState
	if err := decoder.Decode(&state); err != nil || state.Schema != signerTrustStateSchema {
		return signerTrustState{}, edgesignertrust.Signed{}, errors.New("invalid signer trust state")
	}
	document, err := edgesignertrust.Decode(state.Document)
	if err != nil || document.Document.Revision != state.Revision {
		return signerTrustState{}, edgesignertrust.Signed{}, errors.New("invalid signer trust state document")
	}
	return state, document, nil
}

// Apply verifies one bundle with the current effective trust (a revoked
// control key cannot deliver), enforces revision order, persists, applies and
// returns the receipt to send.
func (runtime *SignerTrustRuntime) Apply(encoded []byte) edgesignertrust.Receipt {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	receipt := edgesignertrust.Receipt{Schema: edgesignertrust.ReceiptSchema, NodeID: runtime.nodeID,
		BundleSHA256: edgesignertrust.Digest(encoded), Revision: runtime.state.Revision,
		ReportedAt: edgesignertrust.CanonicalTime(runtime.now())}
	reject := func(reason string) edgesignertrust.Receipt {
		receipt.Result, receipt.Reason = edgesignertrust.ResultRejected, reason
		return receipt
	}
	_, signed, document, err := edgesignertrust.OpenBundle(encoded, runtime.nodeID, runtime.trust.Ed25519Key)
	switch {
	case errors.Is(err, edgesignertrust.ErrUntrusted):
		return reject(edgesignertrust.ReasonUntrusted)
	case err != nil:
		return reject(edgesignertrust.ReasonInvalid)
	}
	revision := signed.Document.Revision
	switch {
	case revision < runtime.state.Revision:
		return reject(edgesignertrust.ReasonStale)
	case revision == runtime.state.Revision && !bytes.Equal(document, runtime.state.Document):
		return reject(edgesignertrust.ReasonConflict)
	case revision == runtime.state.Revision:
		receipt.Result = edgesignertrust.ResultApplied
		return receipt
	}
	if runtime.state.Revision > 0 {
		previous, err := edgesignertrust.Decode(runtime.state.Document)
		if err != nil {
			return reject(edgesignertrust.ReasonPersistence)
		}
		for _, revoked := range previous.Document.RevokedKeys {
			if !signed.Document.Revokes(revoked.KeyID, nil) {
				return reject(edgesignertrust.ReasonConflict)
			}
		}
	}
	overlay, err := newSignerTrustOverlay(signed.Document)
	if err != nil {
		return reject(edgesignertrust.ReasonInvalid)
	}
	state := signerTrustState{Schema: signerTrustStateSchema, Revision: revision, Document: document,
		AppliedAt: edgesignertrust.CanonicalTime(runtime.now())}
	if err := runtime.persist(state); err != nil {
		return reject(edgesignertrust.ReasonPersistence)
	}
	runtime.state = state
	runtime.trust.setOverlay(overlay)
	receipt.Revision, receipt.Result = revision, edgesignertrust.ResultApplied
	return receipt
}

func (runtime *SignerTrustRuntime) persist(state signerTrustState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(runtime.dir, ".state-*.json")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(runtime.dir, signerTrustStateFile)); err != nil {
		return err
	}
	directory, err := os.Open(runtime.dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
