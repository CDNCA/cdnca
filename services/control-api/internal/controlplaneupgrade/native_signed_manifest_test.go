package controlplaneupgrade

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeSignedArchiveRequiresIndependentSignature(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"release-test": private.Public().(ed25519.PublicKey)}
	for _, change := range []string{"valid", "newline", "missing", "unknown key", "wrong key", "wrong domain", "raw change", "duplicate key", "extra field", "double newline", "unlisted file", "signature in inventory", "signature mode", "v1 key", "v1 empty key"} {
		t.Run(change, func(t *testing.T) {
			manifest, files := nativeManifestFixture()
			manifest.Schema, manifest.KeyID = NativeManifestSignedSchema, "release-test"
			if change == "unknown key" {
				manifest.KeyID = "unknown"
			}
			if change == "signature in inventory" {
				manifest.Files = append(manifest.Files, NativeFile{Path: NativeSignatureFilename, SHA256: strings.Repeat("a", 64), Bytes: 88, Mode: 0o644})
			}
			if change == "v1 key" || change == "v1 empty key" {
				manifest.Schema = NativeManifestSchema
			}
			raw, _ := json.Marshal(manifest)
			if change == "v1 empty key" {
				raw = bytes.Replace(raw, []byte(`"key_id":"release-test"`), []byte(`"key_id":""`), 1)
			}
			if change == "duplicate key" {
				raw = bytes.Replace(raw, []byte(`"key_id":"release-test"`), []byte(`"key_id":"release-test","key_id":"release-test"`), 1)
			}
			if change == "extra field" {
				raw = bytes.Replace(raw, []byte(`"key_id":"release-test"`), []byte(`"key_id":"release-test","unexpected":true`), 1)
			}
			domain := NativeManifestSignedSchema + "\n"
			if change == "wrong domain" {
				domain = "cdnca.native-management.install/v2\n"
			}
			signer := private
			if change == "wrong key" {
				signer = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x38}, ed25519.SeedSize))
			}
			signature := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(signer, append([]byte(domain), raw...))))
			if change == "newline" {
				signature = append(signature, '\n')
			}
			if change == "double newline" {
				signature = append(signature, '\n', '\n')
			}
			if change == "raw change" {
				raw = append(raw, '\n')
			}
			if change == "missing" || change == "v1 key" || change == "v1 empty key" {
				signature = nil
			}
			if change == "unlisted file" {
				files["source.bundle"] = []byte("unexpected")
			}
			mode := int64(0o644)
			if change == "signature mode" {
				mode = 0o755
			}
			filename, artifact := nativeSignedReleaseArchiveFixture(t, raw, signature, mode, files)
			_, err := ValidateSignedNativeReleaseArchive(filename, artifact, manifest.Platform, keys)
			valid := change == "valid" || change == "newline"
			if (err == nil) != valid {
				t.Fatalf("signed archive accepted=%v, want %v: %v", err == nil, valid, err)
			}
			if _, err := ValidateNativeReleaseArchive(filename, artifact, manifest.Platform); err == nil {
				t.Fatal("legacy entry accepted signed or malformed schema")
			}
			if valid {
				if _, err := ValidateSignedNativeReleaseArchive(filename, artifact, manifest.Platform, nil); err == nil {
					t.Fatal("signature accepted without independent trust")
				}
			}
		})
	}
	manifest, files := nativeManifestFixture()
	file, artifact := nativeArchiveFixture(t, manifest, files, nil)
	if _, err := ValidateSignedNativeReleaseArchive(file, artifact, manifest.Platform, keys); err == nil {
		t.Fatal("signed-only entry accepted v1")
	}
}

func TestNativeArtifactTrustStrict(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
	der, _ := x509.MarshalPKIXPublicKey(private.Public())
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	key := map[string]any{"key_id": "release-test", "public_key_pem": public}
	good, _ := json.Marshal(map[string]any{"version": 1, "keys": []any{key}})
	keys, err := DecodeNativeArtifactTrust(good)
	if err != nil || !bytes.Equal(keys["release-test"], private.Public().(ed25519.PublicKey)) {
		t.Fatalf("valid trust: %v", err)
	}
	for _, change := range []string{"version", "empty", "duplicate id", "unknown field", "unknown key field", "duplicate member", "private pem", "trailing pem", "rsa", "too many", "invalid id", "null", "oversize"} {
		t.Run(change, func(t *testing.T) {
			var candidate map[string]any
			_ = json.Unmarshal(good, &candidate)
			entry := candidate["keys"].([]any)[0].(map[string]any)
			switch change {
			case "version":
				candidate["version"] = 2
			case "empty":
				candidate["keys"] = []any{}
			case "duplicate id":
				candidate["keys"] = []any{key, key}
			case "unknown field":
				candidate["extra"] = true
			case "unknown key field":
				entry["extra"] = true
			case "private pem":
				entry["public_key_pem"] = "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n"
			case "trailing pem":
				entry["public_key_pem"] = public + public
			case "rsa":
				entry["public_key_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}))
			case "too many":
				candidate["keys"] = make([]any, 33)
			case "invalid id":
				entry["key_id"] = "invalid key"
			case "null":
				candidate["keys"] = nil
			}
			raw, _ := json.Marshal(candidate)
			if change == "duplicate member" {
				raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
			}
			if change == "oversize" {
				raw = append(raw, bytes.Repeat([]byte{' '}, 65537)...)
			}
			if _, err := DecodeNativeArtifactTrust(raw); err == nil {
				t.Fatal("unsafe trust accepted")
			}
		})
	}
}

func nativeSignedReleaseArchiveFixture(t *testing.T, raw, signature []byte, signatureMode int64, files map[string][]byte) (string, Artifact) {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	write := func(name string, body []byte, mode int64) {
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	write(NativeManifestFilename, raw, 0o644)
	if signature != nil {
		write(NativeSignatureFilename, signature, signatureMode)
	}
	for name, body := range files {
		mode := int64(0o644)
		if strings.HasPrefix(name, "bin/") {
			mode = 0o755
		}
		write(name, body, mode)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "signed.tar")
	if err := os.WriteFile(filename, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var manifest NativeManifest
	_ = json.Unmarshal(raw, &manifest)
	return filename, Artifact{Version: manifest.Version, Digest: digestBytes(output.Bytes()), Size: int64(output.Len()), URL: "https://release.invalid/full.tar"}
}
