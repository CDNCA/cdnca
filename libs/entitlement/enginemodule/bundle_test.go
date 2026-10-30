package enginemodule_test

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule/enginemoduletest"
)

func signer(name string) enginemoduletest.Signer {
	seed := sha256.Sum256([]byte(name))
	return enginemoduletest.Signer{KeyID: name, Private: ed25519.NewKeyFromSeed(seed[:])}
}

func TestBundleRoundTripIsCanonical(t *testing.T) {
	bundle := enginemoduletest.Build(t, []enginemoduletest.Signer{signer("release-1")}, enginemoduletest.Options{})
	encoded, err := bundle.Encode()
	if err != nil {
		t.Fatal(err)
	}
	again, err := bundle.Encode()
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatalf("encoding is not deterministic: %v", err)
	}
	checked, err := enginemodule.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(checked.Bundle.Payload, bundle.Payload) || checked.Manifest.Version != enginemoduletest.DefaultVersion {
		t.Fatalf("decoded %+v", checked.Manifest)
	}
	id := checked.ArtifactID()
	if id != "engine_module/waf-crs-module.openresty-1.31.1.1.linux-amd64" {
		t.Fatalf("artifact id %q", id)
	}
	component, platform, ok := enginemodule.ParseArtifactID(id)
	if !ok || component != enginemodule.Component || platform != checked.Platform() {
		t.Fatalf("parse %q: %q %+v %v", id, component, platform, ok)
	}
	for _, bad := range []string{"engine_module/waf-crs-module.openresty-1.31.1.linux-amd64",
		"engine_module/waf-crs-module.openresty-1.31.1.1.linux-386", "ruleset/waf-crs-module.openresty-1.31.1.1.linux-amd64"} {
		if _, _, ok := enginemodule.ParseArtifactID(bad); ok {
			t.Fatalf("%q parsed", bad)
		}
	}
}

func TestBundleDirectoryRoundTrip(t *testing.T) {
	bundle := enginemoduletest.Build(t, []enginemoduletest.Signer{signer("release-1")}, enginemoduletest.Options{Architecture: "arm64"})
	directory := filepath.Join(t.TempDir(), "linux-arm64")
	enginemoduletest.WriteDirectory(t, directory, bundle)
	read, err := enginemodule.ReadDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := read.Check()
	if err != nil || checked.Platform().Architecture != "arm64" {
		t.Fatalf("checked %+v: %v", checked.Platform(), err)
	}
}

// rewrite re-tars files (name/content pairs) without the Encode checks.
func rewrite(t *testing.T, files ...[2]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, file := range files {
		if err := writer.WriteHeader(&tar.Header{Name: file[0], Mode: 0o444, Size: int64(len(file[1])), Typeflag: tar.TypeReg,
			Uname: "root", Gname: "root", Format: tar.FormatPAX}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(file[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestBundleRejectsInconsistentFiles(t *testing.T) {
	good := enginemoduletest.Build(t, []enginemoduletest.Signer{signer("release-1")}, enginemoduletest.Options{})
	manifest, err := enginemodule.DecodeManifest(good.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	payloadName := manifest.Payload.Name
	cases := map[string]struct {
		mutate func(*enginemodule.Bundle)
		want   error
	}{
		"payload byte flipped": {func(bundle *enginemodule.Bundle) {
			bundle.Payload = append([]byte(nil), bundle.Payload...)
			bundle.Payload[len(bundle.Payload)/2] ^= 0xff
		}, enginemodule.ErrSumsMismatch},
		"manifest edited": {func(bundle *enginemodule.Bundle) {
			bundle.Manifest = append(append([]byte(nil), bundle.Manifest...), ' ')
		}, enginemodule.ErrSumsMismatch},
		"signatures edited": {func(bundle *enginemodule.Bundle) {
			bundle.Signatures = bytes.Replace(bundle.Signatures, []byte(`"algorithm": "ed25519"`), []byte(`"algorithm":  "ed25519"`), 1)
		}, enginemodule.ErrSumsMismatch},
		"no signatures": {func(bundle *enginemodule.Bundle) {
			*bundle = enginemoduletest.Build(t, nil, enginemoduletest.Options{})
		}, enginemodule.ErrSignature},
		"extra sums line": {func(bundle *enginemodule.Bundle) {
			bundle.Sums = append(append([]byte(nil), bundle.Sums...), []byte(strings.Repeat("0", 64)+"  manifest.sig\n")...)
		}, enginemodule.ErrManifest},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := good
			test.mutate(&bundle)
			if _, err := bundle.Check(); !errors.Is(err, test.want) {
				t.Fatalf("Check = %v, want %v", err, test.want)
			}
			if _, err := bundle.Encode(); err == nil {
				t.Fatal("inconsistent bundle encoded")
			}
		})
	}
	// Tar-level shape: exactly the four files, canonical order and encoding.
	for name, encoded := range map[string][]byte{
		"reordered": rewrite(t, [2]string{enginemodule.ManifestName, string(good.Manifest)},
			[2]string{enginemodule.SumsName, string(good.Sums)}, [2]string{enginemodule.SignaturesName, string(good.Signatures)},
			[2]string{payloadName, string(good.Payload)}),
		"extra member": rewrite(t, [2]string{enginemodule.SumsName, string(good.Sums)},
			[2]string{enginemodule.ManifestName, string(good.Manifest)}, [2]string{enginemodule.SignaturesName, string(good.Signatures)},
			[2]string{payloadName, string(good.Payload)}, [2]string{"manifest.sig", "x"}),
		"payload renamed": rewrite(t, [2]string{enginemodule.SumsName, string(good.Sums)},
			[2]string{enginemodule.ManifestName, string(good.Manifest)}, [2]string{enginemodule.SignaturesName, string(good.Signatures)},
			[2]string{"cdnca-waf-crs-module-other.tar.gz", string(good.Payload)}),
		"empty": nil,
	} {
		if _, err := enginemodule.Decode(encoded); err == nil {
			t.Fatalf("%s: decoded", name)
		}
	}
	encoded, err := good.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enginemodule.Decode(append(encoded, make([]byte, 512)...)); err == nil {
		t.Fatal("trailing blocks decoded")
	}
}

func TestUnsignedBundleIsASignatureError(t *testing.T) {
	unsigned := enginemoduletest.Build(t, nil, enginemoduletest.Options{})
	manifest, err := enginemodule.DecodeManifest(unsigned.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	encoded := rewrite(t, [2]string{enginemodule.SumsName, string(unsigned.Sums)},
		[2]string{enginemodule.ManifestName, string(unsigned.Manifest)}, [2]string{enginemodule.SignaturesName, ""},
		[2]string{manifest.Payload.Name, string(unsigned.Payload)})
	if _, err := enginemodule.Decode(encoded); !errors.Is(err, enginemodule.ErrSignature) {
		t.Fatalf("unsigned bundle error = %v", err)
	}
}
