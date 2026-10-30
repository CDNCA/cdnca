// Package enginemoduletest builds signed engine module bundles from a fake
// extension tree for tests (test keys only).
package enginemoduletest

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
)

// Signer is a platform release key that signs signatures.json.
type Signer struct {
	KeyID   string
	Private ed25519.PrivateKey
}

// Options shape one build. Zero values: version 3.0.17-1.0.4-1, OpenResty
// 1.31.1.1, amd64, manifest key_id = the first signer's.
type Options struct {
	Version          string
	OpenRestyVersion string
	Architecture     string
	// Module is the content of the module file (distinct builds differ in it).
	Module string
	// Mutate edits the manifest before it is encoded and signed.
	Mutate func(*enginemodule.Manifest)
}

const (
	DefaultVersion   = "3.0.17-1.0.4-1"
	DefaultOpenResty = "1.31.1.1"
)

// Build returns the four files of a build signed by signers (none: no
// signatures.json, SHA256SUMS does not list it).
func Build(t testing.TB, signers []Signer, options Options) enginemodule.Bundle {
	t.Helper()
	if options.Version == "" {
		options.Version = DefaultVersion
	}
	if options.OpenRestyVersion == "" {
		options.OpenRestyVersion = DefaultOpenResty
	}
	if options.Architecture == "" {
		options.Architecture = "amd64"
	}
	if options.Module == "" {
		options.Module = "module"
	}
	keyID := "release-1"
	if len(signers) > 0 {
		keyID = signers[0].KeyID
	}
	tree := t.TempDir()
	for name, content := range map[string]string{enginemodule.ModulePath: options.Module, enginemodule.UnicodeMapPath: "mapping",
		"lib/libmodsecurity.so.3": "lib", "LICENSE.libmodsecurity": "Apache-2.0"} {
		target := filepath.Join(tree, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := enginemodule.BuildManifest(tree, enginemodule.Manifest{Version: options.Version,
		OpenRestyVersion: options.OpenRestyVersion, Platform: "linux", Architecture: options.Architecture, KeyID: keyID})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := enginemodule.BuildPayload(tree, manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Payload = enginemodule.PayloadRef{Name: fmt.Sprintf("cdnca-waf-crs-module-%s-openresty-%s-linux-%s.tar.gz",
		options.Version, options.OpenRestyVersion, options.Architecture), SHA256: enginemodule.Digest(payload), Size: int64(len(payload))}
	if options.Mutate != nil {
		options.Mutate(&manifest)
	}
	manifestBytes, err := enginemodule.EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	bundle := enginemodule.Bundle{Manifest: manifestBytes, Payload: payload}
	sums := fmt.Sprintf("%s  %s\n", enginemodule.Digest(manifestBytes), enginemodule.ManifestName)
	if len(signers) > 0 {
		document := enginemodule.SignatureDocument{}
		for _, signer := range signers {
			document.Signatures = append(document.Signatures, enginemodule.SignatureEntry{KeyID: signer.KeyID, Algorithm: "ed25519",
				Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(signer.Private, enginemodule.SigningBytes(manifestBytes)))})
		}
		if bundle.Signatures, err = enginemodule.EncodeSignatures(document); err != nil {
			t.Fatal(err)
		}
		sums += fmt.Sprintf("%s  %s\n", enginemodule.Digest(bundle.Signatures), enginemodule.SignaturesName)
	}
	bundle.Sums = []byte(sums + fmt.Sprintf("%s  %s\n", enginemodule.Digest(payload), manifest.Payload.Name))
	return bundle
}

// Encoded is Build, encoded as catalog bytes (the bundle must Check).
func Encoded(t testing.TB, signers []Signer, options Options) []byte {
	t.Helper()
	encoded, err := Build(t, signers, options).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// WriteDirectory writes bundle as a published build directory.
func WriteDirectory(t testing.TB, directory string, bundle enginemodule.Bundle) {
	t.Helper()
	manifest, err := enginemodule.DecodeManifest(bundle.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{enginemodule.SumsName: bundle.Sums, enginemodule.ManifestName: bundle.Manifest,
		enginemodule.SignaturesName: bundle.Signatures, manifest.Payload.Name: bundle.Payload} {
		if content == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
