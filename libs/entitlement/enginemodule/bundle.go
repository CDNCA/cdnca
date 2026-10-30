package enginemodule

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	// MediaType is the catalog / node artifact set media type of a Bundle.
	MediaType = "application/vnd.cdnca.engine-module+tar;version=1"
	// Kind is the artifact catalog kind of a Bundle.
	Kind = "engine_module"
	// MaxBundleBytes bounds an encoded bundle (four files and tar headers).
	MaxBundleBytes = MaxPayloadBytes + MaxManifestBytes + MaxSumsBytes + MaxSignaturesBytes + 16<<10
)

// ErrBundle: the bytes are not a well-formed bundle.
var ErrBundle = errors.New("engine module bundle is malformed")

// Bundle is one build: the four published files, byte for byte.
type Bundle struct {
	Sums       []byte
	Manifest   []byte
	Signatures []byte
	Payload    []byte
}

// Checked is a bundle whose files agree with each other: SHA256SUMS lists
// exactly manifest.json, signatures.json and the payload with their digests,
// the manifest is well formed and names the payload, signatures.json is well
// formed. Nothing here says the signatures are trusted.
type Checked struct {
	Bundle     Bundle
	Sums       map[string]string
	Manifest   Manifest
	Signatures SignatureDocument
}

// Platform is what a node must run for a build: its OpenResty version and
// architecture (always linux).
type Platform struct {
	OpenRestyVersion string
	Architecture     string
}

// Platform of a checked build.
func (checked Checked) Platform() Platform {
	return Platform{OpenRestyVersion: checked.Manifest.OpenRestyVersion, Architecture: checked.Manifest.Architecture}
}

// ArtifactID is the catalog / node artifact set ID of a build: one ID per
// component and platform; a newer build of the same platform is a newer
// revision of the same ID.
func (checked Checked) ArtifactID() string {
	return ArtifactID(checked.Manifest.Component, checked.Platform())
}

// ArtifactID names component builds for platform.
func ArtifactID(component string, platform Platform) string {
	return Kind + "/" + component + ".openresty-" + platform.OpenRestyVersion + ".linux-" + platform.Architecture
}

var artifactIDPattern = regexp.MustCompile(`^` + Kind + `/([a-z0-9]+(?:-[a-z0-9]+)*)\.openresty-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.linux-(amd64|arm64)$`)

// ParseArtifactID reverses ArtifactID.
func ParseArtifactID(artifactID string) (string, Platform, bool) {
	match := artifactIDPattern.FindStringSubmatch(artifactID)
	if match == nil {
		return "", Platform{}, false
	}
	return match[1], Platform{OpenRestyVersion: match[2], Architecture: match[3]}, true
}

// Check verifies that the four files agree (see Checked).
func (bundle Bundle) Check() (Checked, error) {
	sums, err := ParseSums(bundle.Sums)
	if err != nil {
		return Checked{}, err
	}
	if len(bundle.Manifest) == 0 || len(bundle.Manifest) > MaxManifestBytes || sums[ManifestName] != Digest(bundle.Manifest) {
		return Checked{}, ErrSumsMismatch
	}
	// Without signatures.json the build has no platform signature.
	if _, listed := sums[SignaturesName]; !listed || len(bundle.Signatures) == 0 {
		return Checked{}, fmt.Errorf("%w: signatures.json is missing or not listed", ErrSignature)
	}
	if sums[SignaturesName] != Digest(bundle.Signatures) {
		return Checked{}, ErrSumsMismatch
	}
	manifest, err := DecodeManifest(bundle.Manifest)
	if err != nil {
		return Checked{}, err
	}
	if len(sums) != 3 || sums[manifest.Payload.Name] != manifest.Payload.SHA256 {
		return Checked{}, ErrManifest
	}
	if int64(len(bundle.Payload)) != manifest.Payload.Size || Digest(bundle.Payload) != manifest.Payload.SHA256 {
		return Checked{}, ErrSumsMismatch
	}
	signatures, err := ParseSignatures(bundle.Signatures)
	if err != nil {
		return Checked{}, err
	}
	return Checked{Bundle: bundle, Sums: sums, Manifest: manifest, Signatures: signatures}, nil
}

// Encode is the canonical bundle bytes: a PAX tar of SHA256SUMS,
// manifest.json, signatures.json and the payload in that order, regular
// files 0444, owner root, time zero. The bundle must Check.
func (bundle Bundle) Encode() ([]byte, error) {
	checked, err := bundle.Check()
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, file := range []struct {
		name    string
		content []byte
	}{{SumsName, bundle.Sums}, {ManifestName, bundle.Manifest}, {SignaturesName, bundle.Signatures},
		{checked.Manifest.Payload.Name, bundle.Payload}} {
		if err := writer.WriteHeader(&tar.Header{Name: file.name, Mode: 0o444, Size: int64(len(file.content)),
			Typeflag: tar.TypeReg, Uname: "root", Gname: "root", Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if _, err := writer.Write(file.content); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if buffer.Len() > MaxBundleBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrBundle, buffer.Len())
	}
	return buffer.Bytes(), nil
}

// Decode reads canonical bundle bytes and checks them (Check). Anything but
// exactly the four files, in canonical encoding, is rejected. An empty
// signatures.json member decodes far enough to be refused as unsigned
// (ErrSignature), so a node reports signature_invalid for it.
func Decode(encoded []byte) (Checked, error) {
	if len(encoded) == 0 || len(encoded) > MaxBundleBytes {
		return Checked{}, ErrBundle
	}
	reader := tar.NewReader(bytes.NewReader(encoded))
	files := make([][]byte, 0, 4)
	names := make([]string, 0, 4)
	limits := []int64{MaxSumsBytes, MaxManifestBytes, MaxSignaturesBytes, MaxPayloadBytes}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Typeflag != tar.TypeReg || len(files) == len(limits) ||
			header.Size < 1 && len(files) != 2 || header.Size > limits[len(files)] || strings.Contains(header.Name, "/") {
			return Checked{}, ErrBundle
		}
		content, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(content)) != header.Size {
			return Checked{}, ErrBundle
		}
		files, names = append(files, content), append(names, header.Name)
	}
	if len(files) != 4 || names[0] != SumsName || names[1] != ManifestName || names[2] != SignaturesName {
		return Checked{}, ErrBundle
	}
	bundle := Bundle{Sums: files[0], Manifest: files[1], Signatures: files[2], Payload: files[3]}
	checked, err := bundle.Check()
	if err != nil {
		return Checked{}, err
	}
	if names[3] != checked.Manifest.Payload.Name {
		return Checked{}, ErrBundle
	}
	canonical, err := bundle.Encode()
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Checked{}, ErrBundle
	}
	return checked, nil
}
