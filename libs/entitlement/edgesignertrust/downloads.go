package edgesignertrust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

)

// Installers download edge-agent/artifacts.json: nodes from their control
// plane (install-node.sh --artifact-trust-url), control planes from the
// authorization server (install-control.sh --edge-artifact-trust-url).
// PublishDownloads keeps it in step with an accepted document so anything
// installed after a revocation never trusts the revoked key, and publishes the
// document itself as edge-agent/signer-trust.json for the installer's check.
// Both control-api (edgesignertrustsync) and license-service call it.
const (
	artifactTrustName = "artifacts.json"
	signerTrustName   = "signer-trust.json"
	maxArtifactTrust  = 1 << 20
)

var errEveryKeyRevoked = errors.New("the document revokes every artifact trust key")

type artifactTrustDocument struct {
	Version int                  `json:"version"`
	Keys    []artifactTrustEntry `json:"keys"`
}

type artifactTrustEntry struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// RenderArtifactTrust returns artifacts.json minus every key the document
// revokes (by ID or public key) plus its trusted keys. An existing entry with
// a trusted key's ID but another key is kept as is (IDs are never reused for
// a different key; the conflict is returned for logging).
func RenderArtifactTrust(current []byte, document Document) ([]byte, []string, error) {
	decoder := json.NewDecoder(bytes.NewReader(current))
	decoder.DisallowUnknownFields()
	var trust artifactTrustDocument
	if err := decoder.Decode(&trust); err != nil || trust.Version != 1 || len(trust.Keys) == 0 {
		return nil, nil, errors.New("artifact trust document is invalid")
	}
	result := artifactTrustDocument{Version: 1, Keys: []artifactTrustEntry{}}
	seen := map[string]string{}
	for _, entry := range trust.Keys {
		key, err := ParsePublicKeyPEM(entry.PublicKeyPEM)
		if err != nil {
			// Keep entries this package cannot judge (the agent validates them).
			key = nil
		}
		if document.Revokes(entry.KeyID, key) {
			continue
		}
		seen[entry.KeyID] = entry.PublicKeyPEM
		result.Keys = append(result.Keys, entry)
	}
	var conflicts []string
	for _, trusted := range document.TrustedKeys {
		if !trusted.ArtifactKey() {
			continue
		}
		if existing, found := seen[trusted.KeyID]; found {
			if existing != trusted.PublicKeyPEM {
				conflicts = append(conflicts, trusted.KeyID)
			}
			continue
		}
		result.Keys = append(result.Keys, artifactTrustEntry{KeyID: trusted.KeyID, PublicKeyPEM: trusted.PublicKeyPEM})
	}
	if len(result.Keys) == 0 {
		return nil, conflicts, errEveryKeyRevoked
	}
	sort.SliceStable(result.Keys, func(i, j int) bool { return result.Keys[i].KeyID < result.Keys[j].KeyID })
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, conflicts, err
	}
	return append(encoded, '\n'), conflicts, nil
}

// PublishDownloads rewrites <dir>/artifacts.json and <dir>/signer-trust.json
// for a verified document. Both are replaced atomically; unchanged content is
// not rewritten.
func PublishDownloads(dir string, encoded []byte) ([]string, error) {
	_, conflicts, err := PublishDownloadCopies(dir, encoded)
	return conflicts, err
}

// Download copy outcomes reported to the operator (AUTH-TRUST-02).
const (
	DownloadCopyRefreshed = "refreshed"
	DownloadCopyUnchanged = "unchanged"
	DownloadCopyFailed    = "failed"
	// DownloadCopySkipped: not attempted because an earlier copy failed.
	DownloadCopySkipped = "skipped"
)

// DownloadCopy is the outcome for one file. Reason is a stable code (never a
// path or OS error text) and is set unless the copy is refreshed/unchanged.
type DownloadCopy struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// DownloadCopyNames lists the copies in the order PublishDownloadCopies
// reports them.
var DownloadCopyNames = []string{signerTrustName, artifactTrustName}

// FailedDownloadCopies returns every copy with the same reason (used when the
// refresh cannot start, e.g. no readable latest document).
func FailedDownloadCopies(reason string) []DownloadCopy {
	copies := make([]DownloadCopy, 0, len(DownloadCopyNames))
	for _, name := range DownloadCopyNames {
		copies = append(copies, DownloadCopy{Name: name, Status: DownloadCopyFailed, Reason: reason})
	}
	return copies
}

// PublishDownloadCopies is PublishDownloads with one result per copy.
// signer-trust.json is written only once artifacts.json renders, and
// artifacts.json only after signer-trust.json is in place (unchanged order).
func PublishDownloadCopies(dir string, encoded []byte) ([]DownloadCopy, []string, error) {
	signer := DownloadCopy{Name: signerTrustName, Status: DownloadCopySkipped, Reason: "artifact_trust_failed"}
	artifacts := DownloadCopy{Name: artifactTrustName, Status: DownloadCopyFailed}
	result := func() []DownloadCopy { return []DownloadCopy{signer, artifacts} }
	signed, err := Decode(encoded)
	if err != nil {
		return FailedDownloadCopies("document_invalid"), nil, err
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return FailedDownloadCopies("directory_invalid"), nil, errors.New("edge download directory must be an absolute clean path")
	}
	current, err := readBounded(filepath.Join(dir, artifactTrustName))
	if err != nil {
		artifacts.Reason = "artifact_trust_unreadable"
		return result(), nil, fmt.Errorf("read edge artifact trust: %w", err)
	}
	rendered, conflicts, err := RenderArtifactTrust(current, signed.Document)
	if err != nil {
		artifacts.Reason = "artifact_trust_invalid"
		if errors.Is(err, errEveryKeyRevoked) {
			artifacts.Reason = "every_key_revoked"
		}
		return result(), conflicts, err
	}
	changed, err := replaceIfChanged(filepath.Join(dir, signerTrustName), encoded)
	if err != nil {
		signer = DownloadCopy{Name: signerTrustName, Status: DownloadCopyFailed, Reason: "write_failed"}
		artifacts = DownloadCopy{Name: artifactTrustName, Status: DownloadCopySkipped, Reason: "signer_trust_failed"}
		return result(), conflicts, err
	}
	signer = DownloadCopy{Name: signerTrustName, Status: copyStatus(changed)}
	changed, err = replaceIfChanged(filepath.Join(dir, artifactTrustName), rendered)
	if err != nil {
		artifacts.Reason = "write_failed"
		return result(), conflicts, err
	}
	artifacts = DownloadCopy{Name: artifactTrustName, Status: copyStatus(changed)}
	return result(), conflicts, nil
}

func copyStatus(changed bool) string {
	if changed {
		return DownloadCopyRefreshed
	}
	return DownloadCopyUnchanged
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxArtifactTrust+1))
	if err != nil || len(content) > maxArtifactTrust {
		return nil, errors.Join(errors.New("artifact trust document is too large"), err)
	}
	return content, nil
}

func replaceIfChanged(path string, content []byte) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, content) {
		return false, nil
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return false, err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(name, path); err != nil {
		return false, err
	}
	return true, nil
}
