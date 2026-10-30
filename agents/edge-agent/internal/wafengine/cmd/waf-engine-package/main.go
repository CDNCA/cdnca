// waf-engine-package turns an extension build (edge/openresty/modsecurity/
// Dockerfile output) into the signed download-server layout the agent
// fetches. It never reads a private key: prepare writes the manifest and the
// exact bytes the platform release key signs (release.signing-data =
// enginemodule.SigningDomain + manifest.json, the same raw Ed25519 flow as the
// node package's release.signing-data); the release signing host signs them;
// finalize verifies every signature and writes signatures.json and SHA256SUMS.
//
//	waf-engine-package prepare --tree DIR --version V --openresty V --arch amd64|arm64 \
//	    --key-id PLATFORM_KEY_ID --out DIR --signing-data FILE
//	waf-engine-package finalize --dir DIR --trust ARTIFACTS_JSON --signature KEY_ID=FILE [--signature ...]
//
// --trust is the published platform trust document (downloads/edge-agent/
// artifacts.json, what nodes install as artifact_trust_file); a signature by a
// key that document does not list is refused. manifest.key_id is the platform
// key ID the build was prepared for.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/wafengine"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
)

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: waf-engine-package prepare|finalize ..."))
	}
	var err error
	switch os.Args[1] {
	case "prepare":
		err = prepare(os.Args[2:])
	case "finalize":
		err = finalize(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "waf-engine-package:", err)
	os.Exit(1)
}

// Only the runtime files ship; build evidence stays with the build.
var runtimeFiles = map[string]bool{"unicode.mapping": true, "LICENSE.libmodsecurity": true, "LICENSE.libxml2": true,
	"LICENSE.yajl": true}

func prepare(args []string) error {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	tree := flags.String("tree", "", "extension build output")
	version := flags.String("version", "", "extension version")
	openresty := flags.String("openresty", "", "target OpenResty version")
	arch := flags.String("arch", "", "amd64 or arm64")
	keyID := flags.String("key-id", "", "platform release key ID")
	out := flags.String("out", "", "output directory (must not exist)")
	signingData := flags.String("signing-data", "", "where to write the bytes the platform release key signs (must not exist)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyID == "" || *signingData == "" {
		return errors.New("--key-id and --signing-data are required")
	}
	staging, err := os.MkdirTemp("", "waf-engine-tree-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := filepath.WalkDir(*tree, func(current string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, _ := filepath.Rel(*tree, current)
		relative = filepath.ToSlash(relative)
		if !runtimeFiles[relative] && !strings.HasPrefix(relative, "lib/") && !strings.HasPrefix(relative, "modules/") {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", relative)
		}
		content, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		target := filepath.Join(staging, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o644)
	}); err != nil {
		return err
	}
	manifest, err := enginemodule.BuildManifest(staging, wafengine.Manifest{Version: *version, OpenRestyVersion: *openresty,
		Platform: "linux", Architecture: *arch, KeyID: *keyID})
	if err != nil {
		return err
	}
	payload, err := enginemodule.BuildPayload(staging, manifest)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	name := fmt.Sprintf("cdnca-waf-crs-module-%s-openresty-%s-linux-%s.tar.gz", *version, *openresty, *arch)
	manifest.Payload = enginemodule.PayloadRef{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(payload))}
	encoded, err := enginemodule.EncodeManifest(manifest)
	if err != nil {
		return err
	}
	if err := os.Mkdir(*out, 0o755); err != nil {
		return err
	}
	for file, content := range map[string][]byte{name: payload, enginemodule.ManifestName: encoded} {
		if err := os.WriteFile(filepath.Join(*out, file), content, 0o444); err != nil {
			return err
		}
	}
	data, err := os.OpenFile(*signingData, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	if _, err := data.Write(enginemodule.SigningBytes(encoded)); err != nil {
		data.Close()
		return err
	}
	if err := data.Close(); err != nil {
		return err
	}
	dataSum := sha256.Sum256(enginemodule.SigningBytes(encoded))
	facts, _ := json.MarshalIndent(map[string]any{"payload": manifest.Payload, "files": len(manifest.Files),
		"download_path":       fmt.Sprintf("%s/%s/openresty-%s/linux-%s/", enginemodule.Component, *version, *openresty, *arch),
		"platform_key_id":     *keyID,
		"signing_data_sha256": hex.EncodeToString(dataSum[:])}, "", "  ")
	fmt.Println(string(facts))
	return nil
}

type signatureFlags []string

func (values *signatureFlags) String() string         { return strings.Join(*values, ",") }
func (values *signatureFlags) Set(value string) error { *values = append(*values, value); return nil }

// readSignature accepts a raw 64-byte or a base64 Ed25519 signature.
func readSignature(path string) ([]byte, error) {
	signature, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
		if decodeErr != nil || len(decoded) != ed25519.SignatureSize {
			return nil, fmt.Errorf("%s is neither a raw nor a base64 Ed25519 signature", path)
		}
		signature = decoded
	}
	return signature, nil
}

func readPublicKey(content []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("public key is not one PEM PUBLIC KEY")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return key, nil
}

// platformKeys reads the Ed25519 keys of an artifact trust document
// ({"version":1,"keys":[{"key_id","public_key_pem"}]}).
func platformKeys(path string) (map[string]ed25519.PublicKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document struct {
		Version int `json:"version"`
		Keys    []struct {
			KeyID        string `json:"key_id"`
			PublicKeyPEM string `json:"public_key_pem"`
		} `json:"keys"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || document.Version != 1 || len(document.Keys) == 0 {
		return nil, errors.New("trust document is not a version 1 artifact trust document")
	}
	keys := map[string]ed25519.PublicKey{}
	for _, entry := range document.Keys {
		if key, err := readPublicKey([]byte(entry.PublicKeyPEM)); err == nil {
			keys[entry.KeyID] = key
		}
	}
	return keys, nil
}

func finalize(args []string) error {
	flags := flag.NewFlagSet("finalize", flag.ContinueOnError)
	dir := flags.String("dir", "", "prepared directory")
	trustPath := flags.String("trust", "", "platform artifact trust document (downloads/edge-agent/artifacts.json)")
	var signatureArgs signatureFlags
	flags.Var(&signatureArgs, "signature", "KEY_ID=FILE: platform release signature over the signing data (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(signatureArgs) == 0 || *trustPath == "" {
		return errors.New("--trust and at least one platform --signature are required")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(*dir, enginemodule.ManifestName))
	if err != nil {
		return err
	}
	manifest, err := enginemodule.DecodeManifest(manifestBytes)
	if err != nil {
		return err
	}
	trusted, err := platformKeys(*trustPath)
	if err != nil {
		return err
	}
	document := enginemodule.SignatureDocument{}
	release := map[string]ed25519.PublicKey{}
	for _, argument := range signatureArgs {
		keyID, path, ok := strings.Cut(argument, "=")
		key, listed := trusted[keyID]
		if !ok || !listed {
			return fmt.Errorf("signature %q: key ID is not an Ed25519 key of the platform trust document", argument)
		}
		signature, err := readSignature(path)
		if err != nil {
			return err
		}
		if !ed25519.Verify(key, enginemodule.SigningBytes(manifestBytes), signature) {
			return fmt.Errorf("signature of %s does not verify over the signing data of manifest.json", keyID)
		}
		release[keyID] = key
		document.Signatures = append(document.Signatures, enginemodule.SignatureEntry{KeyID: keyID, Algorithm: "ed25519",
			Signature: base64.StdEncoding.EncodeToString(signature)})
	}
	signatures, err := enginemodule.EncodeSignatures(document)
	if err != nil {
		return err
	}
	payload, err := os.ReadFile(filepath.Join(*dir, manifest.Payload.Name))
	if err != nil {
		return err
	}
	line := func(content []byte, name string) string {
		sum := sha256.Sum256(content)
		return hex.EncodeToString(sum[:]) + "  " + name + "\n"
	}
	sums := line(manifestBytes, enginemodule.ManifestName) + line(signatures, enginemodule.SignaturesName) +
		line(payload, manifest.Payload.Name)
	// The published build must verify exactly as a node does.
	checked, err := (enginemodule.Bundle{Sums: []byte(sums), Manifest: manifestBytes, Signatures: signatures, Payload: payload}).Check()
	if err != nil {
		return err
	}
	if _, err := wafengine.VerifySignature(manifestBytes, checked.Signatures, wafengine.Trust{Release: release}); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, enginemodule.SignaturesName), signatures, 0o444); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*dir, enginemodule.SumsName), []byte(sums), 0o444)
}
