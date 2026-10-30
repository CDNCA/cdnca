package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

func TestNativeArtifactTrustFileOwnership(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
	der, _ := x509.MarshalPKIXPublicKey(private.Public())
	encoded, _ := json.Marshal(map[string]any{"version": 1, "keys": []any{map[string]string{
		"key_id": "publisher", "public_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}}})
	if keys, err := readNativeArtifactTrust("", uint32(os.Getuid())); err != nil || keys != nil {
		t.Fatalf("legacy optional trust: %v", err)
	}
	for _, change := range []string{"valid", "relative", "link", "hardlink", "wrong owner", "writable parent", "writable file", "directory", "malformed", "oversize"} {
		t.Run(change, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			filename, owner := filepath.Join(root, "artifacts.json"), uint32(os.Getuid())
			if err := os.WriteFile(filename, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "relative":
				filename = "relative-artifact-trust.json"
			case "link":
				link := filepath.Join(root, "link.json")
				if err := os.Symlink(filename, link); err != nil {
					t.Fatal(err)
				}
				filename = link
			case "hardlink":
				if err := os.Link(filename, filepath.Join(root, "hardlink.json")); err != nil {
					t.Fatal(err)
				}
			case "wrong owner":
				owner++
			case "writable parent":
				if err := os.Chmod(root, 0o777); err != nil {
					t.Fatal(err)
				}
			case "writable file":
				if err := os.Chmod(filename, 0o666); err != nil {
					t.Fatal(err)
				}
			case "directory":
				filename = root
			case "malformed":
				if err := os.WriteFile(filename, []byte(`{"keys":[]}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(filename, bytes.Repeat([]byte{' '}, 65537), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			keys, err := readNativeArtifactTrust(filename, owner)
			if change == "valid" {
				if err != nil || !bytes.Equal(keys["publisher"], private.Public().(ed25519.PublicKey)) {
					t.Fatalf("trusted key file: %v", err)
				}
			} else if err == nil {
				t.Fatal("unsafe trust path accepted")
			}
		})
	}
}

func TestNativeVerifierAcceptsSignedStatus(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	installationID := uuid.NewString()
	signer := nativeVerifierSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: signer.KeyID(), PublicKey: signer.private.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := controlplaneupgrade.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	status := controlplaneupgrade.NativeStandaloneStatus{Ready: true, Reason: "ready", Phase: "idle", InstallationID: installationID,
		ProtocolVersion: 2, ArtifactFormat: controlplaneupgrade.NativeManifestSignedSchema, CurrentVersion: "1.4.0"}
	runner := nativeVerifierRunner{probe: func(context.Context) (controlplaneupgrade.NativeStandaloneStatus, error) { return status, nil }}
	verify := newNativePlanVerifier(t.Context(), trust, installationID, 2, store, runner, func() time.Time { return now })
	plan := nativeSignedPlan(t, signer, installationID, "1.4.0", "1.5.0", 42, now)
	if err := verify(plan); err != nil {
		t.Fatalf("v2 ready status rejected: %v", err)
	}
	status.ArtifactFormat = "cdnca.native-management.release/v3"
	if err := verify(plan); err == nil {
		t.Fatal("unknown provenance accepted")
	}
}
