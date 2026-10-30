// waf-engine-smoke drives the agent's engine gate outside the daemon for the
// signing regression (tests/waf-engine-signing/run.sh).
//
//	install: the full agent path of a node artifact set engine module item
//	  (bundle of the published directory, SHA256SUMS, platform signature,
//	  digests, install, gate) from a local build directory.
//	  --pkg DIR --public-key PEM --key-id ID --root DIR --state DIR
//	  --release DIR --version-id ID --version V --openresty V --arch A
//	  --public-key/--key-id: a platform release key (artifact_trust_file).
//	  A rejected build prints state degraded with the receipt reason
//	  (signature_invalid, platform_mismatch, install_rejected).
//	render: write the gate for an engine already present at --module /
//	  --unicode (no download).
//	  --state DIR --release DIR --version-id ID --module PATH --unicode PATH
//	remove: delete the gate (a node without the extension).
//	  --state DIR --version-id ID
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/wafengine"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
)

// readBuild reads a published build directory; a missing signatures.json
// is left empty (the bundle then has no platform signature).
func readBuild(dir string) enginemodule.Bundle {
	read := func(name string) []byte { content, _ := os.ReadFile(filepath.Join(dir, name)); return content }
	bundle := enginemodule.Bundle{Sums: read(enginemodule.SumsName), Manifest: read(enginemodule.ManifestName),
		Signatures: read(enginemodule.SignaturesName)}
	if manifest, err := enginemodule.DecodeManifest(bundle.Manifest); err == nil {
		bundle.Payload = read(manifest.Payload.Name)
	}
	return bundle
}

// encodeBuild is the catalog bytes of a build; a build that does not Check
// is encoded raw (four tar members) so the node path judges it.
func encodeBuild(bundle enginemodule.Bundle) []byte {
	if encoded, err := bundle.Encode(); err == nil {
		return encoded
	}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	manifest, _ := enginemodule.DecodeManifest(bundle.Manifest)
	for _, file := range []struct {
		name    string
		content []byte
	}{{enginemodule.SumsName, bundle.Sums}, {enginemodule.ManifestName, bundle.Manifest},
		{enginemodule.SignaturesName, bundle.Signatures}, {manifest.Payload.Name, bundle.Payload}} {
		_ = writer.WriteHeader(&tar.Header{Name: file.name, Mode: 0o444, Size: int64(len(file.content)), Typeflag: tar.TypeReg})
		_, _ = writer.Write(file.content)
	}
	_ = writer.Close()
	return buffer.Bytes()
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: waf-engine-smoke install|render|remove ..."))
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	pkg := flags.String("pkg", "", "")
	publicKey := flags.String("public-key", "", "")
	keyID := flags.String("key-id", "", "")
	root := flags.String("root", "", "")
	state := flags.String("state", "", "")
	release := flags.String("release", "", "")
	versionID := flags.String("version-id", "", "")
	version := flags.String("version", "", "")
	openresty := flags.String("openresty", "", "")
	arch := flags.String("arch", "", "")
	module := flags.String("module", "", "")
	unicode := flags.String("unicode", "", "")
	_ = flags.Parse(os.Args[2:])
	gateDir := filepath.FromSlash(edgeconfig.WAFEngineGateDir(*state, *versionID))
	switch os.Args[1] {
	case "install":
		trust := wafengine.Trust{Release: map[string]ed25519.PublicKey{}}
		if *publicKey != "" {
			key, err := loadPublicKey(*publicKey)
			if err != nil {
				fail(err)
			}
			trust.Release[*keyID] = key
		}
		manager, err := wafengine.NewManager(wafengine.Config{Root: *root, StateRoot: *state,
			OpenRestyVersion: *openresty, Architecture: *arch, Trust: trust})
		if err != nil {
			fail(err)
		}
		bundle := readBuild(*pkg)
		content := encodeBuild(bundle)
		artifactID := enginemodule.ArtifactID(enginemodule.Component, enginemodule.Platform{OpenRestyVersion: *openresty, Architecture: *arch})
		staged, err := manager.PrepareModule(content, wafengine.Expected{ArtifactID: artifactID, Version: *version, Revision: 1}, time.Now())
		if err != nil {
			encoded, _ := json.Marshal(map[string]any{"status": wafengine.Status{State: wafengine.StateDegraded,
				Reason: artifactset.RejectReason(err)}, "module": ""})
			fmt.Println(string(encoded))
			return
		}
		if _, err := staged.Commit(); err != nil {
			fail(err)
		}
		gate, err := manager.Prepare(context.Background(), *versionID, *release)
		if err != nil {
			fail(err)
		}
		encoded, _ := json.Marshal(map[string]any{"status": manager.Status(), "module": gate.ModulePath})
		fmt.Println(string(encoded))
	case "render":
		content, err := os.ReadFile(filepath.Join(*release, filepath.FromSlash(edgeconfig.WAFEngineManifestPath)))
		if err != nil {
			fail(err)
		}
		manifest, err := edgeconfig.ParseWAFEngineManifest(content)
		if err != nil {
			fail(err)
		}
		files, err := edgeconfig.RenderWAFEngineGate(manifest, edgeconfig.WAFEngineGate{
			ReleasePath: *state, ModulePath: *module, UnicodeMapPath: *unicode})
		if err != nil {
			fail(err)
		}
		local := filepath.Join(*release, "waf-engine", *versionID)
		if err := os.MkdirAll(local, 0o755); err != nil {
			fail(err)
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(local, name), body, 0o644); err != nil {
				fail(err)
			}
		}
		fmt.Println(local)
	case "remove":
		if err := os.RemoveAll(gateDir); err != nil {
			fail(err)
		}
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return key, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "waf-engine-smoke:", err)
	os.Exit(1)
}
