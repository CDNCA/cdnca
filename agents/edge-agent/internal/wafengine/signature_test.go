package wafengine

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule/enginemoduletest"
)

func jsonMarshal(value any) ([]byte, error) { return json.Marshal(value) }

// rawBundle tars the four files without enginemodule's checks (a build the
// encoder refuses, judged by the node path).
func rawBundle(t *testing.T, bundle enginemodule.Bundle) []byte {
	t.Helper()
	manifest, err := enginemodule.DecodeManifest(bundle.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, file := range []struct {
		name    string
		content []byte
	}{{enginemodule.SumsName, bundle.Sums}, {enginemodule.ManifestName, bundle.Manifest},
		{enginemodule.SignaturesName, bundle.Signatures}, {manifest.Payload.Name, bundle.Payload}} {
		if err := writer.WriteHeader(&tar.Header{Name: file.name, Mode: 0o444, Size: int64(len(file.content)),
			Typeflag: tar.TypeReg, Uname: "root", Gname: "root", Format: tar.FormatPAX}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(file.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// resign replaces signatures.json (and its SHA256SUMS line) with one
// signature by keyID over sign(manifest).
func resign(t *testing.T, built enginemodule.Bundle, keyID string, sign func(manifest []byte) []byte) enginemodule.Bundle {
	t.Helper()
	encoded, err := enginemodule.EncodeSignatures(enginemodule.SignatureDocument{Signatures: []enginemodule.SignatureEntry{{
		KeyID: keyID, Algorithm: "ed25519", Signature: base64.StdEncoding.EncodeToString(sign(built.Manifest))}}})
	if err != nil {
		t.Fatal(err)
	}
	built.Sums = []byte(strings.Replace(string(built.Sums), enginemodule.Digest(built.Signatures), enginemodule.Digest(encoded), 1))
	built.Signatures = encoded
	return built
}

// Every published/trusted combination of platform release keys. Only
// signatures.json counts.
func TestEngineSignatureCombinations(t *testing.T) {
	platform, next, edge := testSigner("cdnca-native-node-20261008"), testSigner("cdnca-native-node-20270101"),
		testSigner("edge-execution-v1")
	platformOnly := []enginemoduletest.Signer{platform}
	rotation := []enginemoduletest.Signer{platform, next}
	for name, test := range map[string]struct {
		trust   Trust
		signers []enginemoduletest.Signer
		signer  string // "": rejected signature_invalid
	}{
		"platform-signed":                      {keys(platform).trust(), platformOnly, platform.KeyID},
		"edge execution key signs":             {keys(platform).trust(), []enginemoduletest.Signer{edge}, ""},
		"edge execution key as a release key":  {keys(edge).trust(), platformOnly, ""},
		"rotation/node knows only the old key": {keys(platform).trust(), rotation, platform.KeyID},
		"rotation/node knows only the new key": {keys(next).trust(), rotation, next.KeyID},
		"retired key no longer in trust":       {keys(next).trust(), platformOnly, ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, true)
			f.useManager(test.trust)
			err := f.install(bundle(t, test.signers, enginemoduletest.Options{}), testVersion)
			if test.signer == "" {
				if artifactset.RejectReason(err) != artifactset.ReasonSignatureInvalid {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			current, _ := f.manager.readInstalled()
			if current == nil || current.Signer.KeyID != test.signer {
				t.Fatalf("installed signer = %+v, want %s", current, test.signer)
			}
			if err := f.deploy(); err != nil || f.manager.Status().State != StateActive || len(f.gate()) != 3 {
				t.Fatalf("deploy %v status=%+v", err, f.manager.Status())
			}
		})
	}
}

// A release-key signature only counts under the WAF manifest domain, a key
// only in its own role, and every signature file must match SHA256SUMS.
func TestEngineSignatureIsDomainAndRoleSeparated(t *testing.T) {
	platform, edge := testSigner("platform-1"), testSigner("edge-execution-v1")
	base := enginemoduletest.Build(t, []enginemoduletest.Signer{platform}, enginemoduletest.Options{})
	for name, test := range map[string]struct {
		bundle enginemodule.Bundle
		reason string
	}{
		"control": {base, ""},
		"platform key over the raw manifest": {resign(t, base, platform.KeyID, func(m []byte) []byte {
			return ed25519.Sign(platform.Private, m)
		}), artifactset.ReasonSignatureInvalid},
		"platform key under the node package domain": {resign(t, base, platform.KeyID, func(m []byte) []byte {
			return ed25519.Sign(platform.Private, append([]byte("cdnca.native-node.release/v1\n"), m...))
		}), artifactset.ReasonSignatureInvalid},
		"edge execution key in signatures.json": {resign(t, base, edge.KeyID, func(m []byte) []byte {
			return ed25519.Sign(edge.Private, enginemodule.SigningBytes(m))
		}), artifactset.ReasonSignatureInvalid},
		"signatures.json not in SHA256SUMS": {func() enginemodule.Bundle {
			altered := base
			altered.Signatures = append(append([]byte(nil), base.Signatures...), ' ')
			return altered
		}(), artifactset.ReasonInstallRejected},
		"no signature published": {enginemoduletest.Build(t, nil, enginemoduletest.Options{}), artifactset.ReasonSignatureInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, true)
			f.useManager(keys(platform).trust())
			err := f.install(rawBundle(t, test.bundle), testVersion)
			if test.reason == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if reason := artifactset.RejectReason(err); err == nil || reason != test.reason {
				t.Fatalf("err = %v reason %q, want %q", err, reason, test.reason)
			}
		})
	}
}

func TestManagerNeedsTrustForAPlatform(t *testing.T) {
	f := newFixture(t, true)
	if _, err := NewManager(Config{Root: f.root, StateRoot: f.state, OpenRestyVersion: testNginx, Architecture: "amd64"}); err == nil {
		t.Fatal("manager for a platform without trust accepted")
	}
	if _, err := NewManager(Config{Root: f.root, StateRoot: f.state, OpenRestyVersion: testNginx, Architecture: "386",
		Trust: keys(f.signer).trust()}); err == nil {
		t.Fatal("manager for an unknown architecture accepted")
	}
}
