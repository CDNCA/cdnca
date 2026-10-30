// Package wafengine installs the optional OWASP CRS engine extension
// (libmodsecurity + ModSecurity-nginx) and gates it into releases.
//
// Node packages do not contain the engine. It arrives as an item of the node
// artifact set (libs/edgeconfig/artifactset MediaTypeEngineModule, ADR 0007
// section 4.2 B3): the license service lists the signed build in its
// artifact catalog, the control plane syncs it and puts the build for this
// node's OpenResty version and architecture in the node's set. The set
// executor has checked the item's digest chain against the control plane
// signature; the installer (Installer) additionally verifies the platform
// release signature over the manifest (signatures.json, Trust) and every
// file digest before it installs the build below Root. Neither the license
// service nor the control plane can vouch for native code.
//
// When the active release carries security/modsecurity/engine.json (a site
// runs OWASP CRS rule sets), Manager.Prepare re-verifies the installed build
// against the node's current trust (a revoked signer degrades it) and only
// then writes the gate files the release's nginx.conf includes
// (edgeconfig.RenderWAFEngineGate). Any failure leaves the gate absent:
// nginx starts without the module and the CRS sites run their
// self-developed detection only; the reason is reported.
package wafengine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
)

// The build format is libs/entitlement/enginemodule.
type (
	Manifest          = enginemodule.Manifest
	FileEntry         = enginemodule.FileEntry
	PayloadRef        = enginemodule.PayloadRef
	SignatureDocument = enginemodule.SignatureDocument
	SignatureEntry    = enginemodule.SignatureEntry
)

const (
	ModulePath     = enginemodule.ModulePath
	UnicodeMapPath = enginemodule.UnicodeMapPath
)

var (
	ErrSumsMismatch = enginemodule.ErrSumsMismatch
	ErrSignature    = enginemodule.ErrSignature
	ErrManifest     = enginemodule.ErrManifest
	ErrPayload      = enginemodule.ErrPayload
)

// Trust is what a node accepts an extension signature from.
//   - Release: the platform release keys, the same anchors that verify the
//     signed node package (artifact_trust_file). Checked in signatures.json;
//     any listed key that is trusted and verifies is enough, so several keys
//     can sign during a rotation and unknown key IDs are skipped.
//   - ReleaseKey, when set, replaces Release with a live lookup (the agent's
//     artifact trust including the node signer trust overlay).
//   - Revoked, when set, rejects a key the node signer trust revoked; it also
//     applies to an already installed extension (Manager.Prepare re-verifies).
type Trust struct {
	Release    map[string]ed25519.PublicKey
	ReleaseKey func(keyID string) (ed25519.PublicKey, bool)
	Revoked    func(keyID string, key ed25519.PublicKey) bool
}

func (trust Trust) release(keyID string) (ed25519.PublicKey, bool) {
	if trust.ReleaseKey != nil {
		key, ok := trust.ReleaseKey(keyID)
		return key, ok && !trust.revoked(keyID, key)
	}
	key, ok := trust.Release[keyID]
	return key, ok && !trust.revoked(keyID, key)
}

func (trust Trust) revoked(keyID string, key ed25519.PublicKey) bool {
	return trust.Revoked != nil && trust.Revoked(keyID, key)
}

func (trust Trust) empty() bool {
	return trust.ReleaseKey == nil && len(trust.Release) == 0
}

// Signer is the key a verified manifest was accepted under.
type Signer struct {
	KeyID string `json:"key_id"`
}

// VerifySignature returns the first trusted platform release key whose
// signature in signatures.json verifies over the manifest (domain
// enginemodule.SigningDomain). The bundle has been checked: its files agree.
func VerifySignature(manifestBytes []byte, signatures enginemodule.SignatureDocument, trust Trust) (Signer, error) {
	message := enginemodule.SigningBytes(manifestBytes)
	for _, entry := range signatures.Signatures {
		key, ok := trust.release(entry.KeyID)
		raw, _ := base64.StdEncoding.DecodeString(entry.Signature)
		if ok && len(key) == ed25519.PublicKeySize && ed25519.Verify(key, message, raw) {
			return Signer{KeyID: entry.KeyID}, nil
		}
	}
	return Signer{}, ErrSignature
}

// Extract verifies the payload against the manifest and writes exactly its
// files below destination (which must not exist). Only regular files and
// directories are accepted; every manifest file must appear once with the
// declared size and digest, and nothing else may.
func Extract(payload []byte, manifest Manifest, destination string) error {
	if int64(len(payload)) != manifest.Payload.Size || enginemodule.Digest(payload) != manifest.Payload.SHA256 {
		return ErrPayload
	}
	want := map[string]FileEntry{}
	for _, file := range manifest.Files {
		want[file.Path] = file
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return ErrPayload
	}
	reader := tar.NewReader(gz)
	written := map[string]bool{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ErrPayload
		}
		name := strings.TrimPrefix(strings.TrimSuffix(header.Name, "/"), "./")
		switch header.Typeflag {
		case tar.TypeDir:
			if name == "" || name == "." {
				continue
			}
			if !enginemodule.ValidRelativePath(name) {
				return ErrPayload
			}
			if err := os.MkdirAll(filepath.Join(destination, filepath.FromSlash(name)), 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			entry, ok := want[name]
			if !ok || written[name] || header.Size != entry.Size {
				return ErrPayload
			}
			content, err := io.ReadAll(io.LimitReader(reader, entry.Size+1))
			if err != nil || int64(len(content)) != entry.Size || enginemodule.Digest(content) != entry.SHA256 {
				return ErrPayload
			}
			target := filepath.Join(destination, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(target, content, os.FileMode(entry.Mode)); err != nil {
				return err
			}
			if err := os.Chmod(target, os.FileMode(entry.Mode)); err != nil {
				return err
			}
			written[name] = true
		default:
			return ErrPayload // links, devices, fifos
		}
	}
	if len(written) != len(want) {
		return ErrPayload
	}
	return nil
}

// VerifyInstalled re-checks an installed tree against its manifest.
func VerifyInstalled(root string, manifest Manifest) error {
	for _, file := range manifest.Files {
		target := filepath.Join(root, filepath.FromSlash(file.Path))
		info, err := os.Lstat(target)
		if err != nil || !info.Mode().IsRegular() || info.Size() != file.Size || uint32(info.Mode().Perm()) != file.Mode {
			return ErrPayload
		}
		content, err := os.ReadFile(target)
		if err != nil || enginemodule.Digest(content) != file.SHA256 {
			return ErrPayload
		}
	}
	return nil
}
