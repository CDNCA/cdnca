package artifactcatalog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/enginemodule/enginemoduletest"
)

func TestEngineModuleEntryChecksBundleAndPlatform(t *testing.T) {
	seed := sha256.Sum256([]byte("release"))
	signers := []enginemoduletest.Signer{{KeyID: "release-1", Private: ed25519.NewKeyFromSeed(seed[:])}}
	encoded := enginemoduletest.Encoded(t, signers, enginemoduletest.Options{})
	entry, err := EngineModuleEntry(encoded, 3, "pack.crs")
	if err != nil {
		t.Fatal(err)
	}
	if entry.ArtifactID != "engine_module/waf-crs-module.openresty-1.31.1.1.linux-amd64" || entry.Kind != KindEngineModule ||
		entry.Version != enginemoduletest.DefaultVersion || entry.Revision != 3 || !entry.Resident ||
		entry.RequiresFeature != "pack.crs" || entry.RequiresCapability == nil ||
		entry.RequiresCapability.Name != EngineModuleCapability || entry.LicenseSPDX != "Apache-2.0" || !Supported(entry) {
		t.Fatalf("entry = %+v", entry)
	}
	if _, _, err := CanonicalCatalog(Catalog{Schema: CatalogSchema, Entries: []Entry{entry}}); err != nil {
		t.Fatalf("catalog with an engine module: %v", err)
	}
	if checked, err := VerifyEngineModule(entry, encoded); err != nil || checked.Manifest.Architecture != "amd64" {
		t.Fatalf("VerifyEngineModule = %v", err)
	}
	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)/2] ^= 1
	if _, err := VerifyEngineModule(entry, tampered); !errors.Is(err, ErrContentMismatch) {
		t.Fatalf("tampered bundle error = %v", err)
	}
	// Bytes of another platform under this entry's id are rejected even with
	// the digest recomputed.
	other := enginemoduletest.Encoded(t, signers, enginemoduletest.Options{Architecture: "arm64"})
	forged := entry
	digest := sha256.Sum256(other)
	forged.SHA256, forged.Size = hex.EncodeToString(digest[:]), int64(len(other))
	if _, err := VerifyEngineModule(forged, other); !errors.Is(err, ErrContentMismatch) {
		t.Fatalf("platform mismatch error = %v", err)
	}
	if _, err := EngineModuleEntry([]byte("not a bundle"), 1, ""); !errors.Is(err, ErrInvalidCatalog) {
		t.Fatalf("malformed bundle entry error = %v", err)
	}
	wrongMedia := entry
	wrongMedia.MediaType = MediaTypeRuleset
	if ValidateEntry(wrongMedia) == nil {
		t.Fatal("engine module entry with another media type accepted")
	}
}
