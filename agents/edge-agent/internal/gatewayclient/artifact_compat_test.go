package gatewayclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestSharedConfigurationBundleCodecCompatibility(t *testing.T) {
	content := []byte("events {}\n")
	fileDigest := sha256.Sum256(content)
	manifest := edgeconfig.Manifest{Files: []edgeconfig.FileManifest{{
		Path: "nginx.conf", Size: int64(len(content)), SHA256: hex.EncodeToString(fileDigest[:]),
	}}}
	manifestDigest, err := edgeconfig.ManifestDigest(manifest)
	if err != nil {
		t.Fatalf("ManifestDigest() error = %v", err)
	}
	wire, err := edgeconfig.MarshalBundle(edgeconfig.Bundle{
		Manifest: manifest, ManifestSHA256: manifestDigest,
		Files: map[string][]byte{"nginx.conf": content},
	})
	if err != nil {
		t.Fatalf("MarshalBundle() error = %v", err)
	}
	decoded, err := decodeConfigurationBundle(wire)
	if err != nil {
		t.Fatalf("decodeConfigurationBundle() error = %v", err)
	}
	if decoded.ManifestSHA256 != manifestDigest || !bytes.Equal(decoded.Files["nginx.conf"], content) {
		t.Fatalf("Edge compatibility shim changed the bundle: %#v", decoded)
	}
	if ConfigurationBundleMediaType != edgeconfig.ConfigurationBundleMediaType {
		t.Fatalf("media type drift: %q != %q", ConfigurationBundleMediaType, edgeconfig.ConfigurationBundleMediaType)
	}
}
