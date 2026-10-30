// Package nativeruntime keeps a native node's OpenResty/Lua runtime
// (/opt/cdnca-node) at the version of the running Agent (node-runtime-upgrade).
//
// The Agent release directory holds the signed native node package of its
// version (native.tar.gz, the v2 upgrade bundle section, or the first
// installation's package). At start the Agent verifies it with its artifact
// trust (the signature install-node.sh checks), and when its runtime differs
// from the active one installs it as releases/<manifest sha256>, prechecks it
// against the live configuration, switches the current link, rewrites
// config.json and hot-upgrades the running HTTP OpenResty master. Any
// failure puts the previous runtime back; the outcome is a status file the
// upgrade health probe reports.
package nativeruntime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	signatureDomain = "cdnca.native-node.release/v1\n"
	manifestName    = "release.manifest.json"
	signatureName   = "release.manifest.sig"
	maxPackageBytes = 512 << 20
	maxTotalBytes   = 1 << 30
	maxMemberBytes  = 256 << 20
	maxManifest     = 4 << 20
	maxMembers      = 32768
)

// Paths inside a native release the switch relies on.
const (
	NginxPath    = "runtime/openresty/nginx/sbin/nginx"
	LoaderPath   = "runtime/lib/ld-musl-x86_64.so.1"
	SecurityRoot = "lua/share/cdnca/security"
	AgentPath    = "bin/edge-agent"
)

var (
	ErrSignature = errors.New("native package signature or inventory rejected")

	memberPattern  = regexp.MustCompile(`^[A-Za-z0-9_+./-]{1,240}$`)
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	runtimePattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)
	memberPrefixes = []string{"runtime/openresty/", "runtime/lib/", "runtime/usr/lib/", "lua/share/cdnca/", "lua/l4geo/",
		"evidence/", "packaging/", "upgrade/"}
	memberExact = map[string]bool{"bin/edge-agent": true, "bin/cdnca-edge-agent-helper": true, "runtime/bin/h3probe": true}
	required    = []string{NginxPath, "runtime/openresty/bin/openresty", LoaderPath, AgentPath,
		SecurityRoot + "/cdnca_waf.lua", SecurityRoot + "/cc.lua", SecurityRoot + "/cc_adaptive.lua"}
)

// Manifest is release.manifest.json (cdnca.native-node.release/v1).
type Manifest struct {
	Schema  string `json:"schema"`
	KeyID   string `json:"key_id"`
	Version string `json:"version"`
	Source  struct {
		Commit string `json:"commit"`
		Tree   string `json:"tree"`
	} `json:"source"`
	Platform struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	} `json:"platform"`
	Runtime struct {
		OpenRestyVersion    string `json:"openresty_version"`
		NginxVersion        string `json:"nginx_version"`
		SourceSHA256        string `json:"source_sha256"`
		PatchManifestSHA256 string `json:"patch_manifest_sha256"`
		ReleaseEligible     bool   `json:"release_eligible"`
	} `json:"runtime"`
	Files []File `json:"files"`
}

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
}

// Package is a verified native node package.
type Package struct {
	Manifest       Manifest
	ManifestSHA256 string
	path           string
}

// SignedSHA256 is the signed digest of a member path ("" when absent).
func (p Package) SignedSHA256(path string) string {
	for _, file := range p.Manifest.Files {
		if file.Path == path {
			return file.SHA256
		}
	}
	return ""
}

// RuntimeSHA256 identifies the runtime part (OpenResty, libraries, Lua): two
// packages with the same digest need no switch even when the Agent differs.
func (p Package) RuntimeSHA256() string { return runtimeDigest(p.Manifest.Files) }

func runtimeDigest(files []File) string {
	var lines []string
	for _, file := range files {
		if strings.HasPrefix(file.Path, "runtime/") || strings.HasPrefix(file.Path, "lua/") {
			lines = append(lines, fmt.Sprintf("%s %s %s %d\n", file.Path, file.Mode, file.SHA256, file.Size))
		}
	}
	sort.Strings(lines)
	digest := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(digest[:])
}

type member struct {
	size   int64
	mode   int64
	digest string
}

// Verify checks the package's signature (one of keys) and its complete
// signed inventory without writing anything.
func Verify(path string, keys map[string]ed25519.PublicKey) (Package, error) {
	members, metadata, err := scan(path)
	if err != nil {
		return Package{}, err
	}
	manifestBytes, signature := metadata[manifestName], metadata[signatureName]
	if manifestBytes == nil || signature == nil {
		return Package{}, fmt.Errorf("%w: missing manifest or signature", ErrSignature)
	}
	manifest, err := verifyManifest(manifestBytes, signature, keys)
	if err != nil {
		return Package{}, err
	}
	listed := make(map[string]bool, len(manifest.Files))
	for _, file := range manifest.Files {
		found, ok := members[file.Path]
		if !ok || listed[file.Path] || file.Path == manifestName || file.Path == signatureName || !safeMember(file.Path) ||
			(file.Mode != "0444" && file.Mode != "0555") || !digestPattern.MatchString(file.SHA256) ||
			found.size != file.Size || found.digest != file.SHA256 || fmt.Sprintf("%04o", found.mode) != file.Mode {
			return Package{}, fmt.Errorf("%w: inventory differs at %q", ErrSignature, file.Path)
		}
		listed[file.Path] = true
	}
	if len(listed) != len(members)-2 {
		return Package{}, fmt.Errorf("%w: unlisted members", ErrSignature)
	}
	for _, path := range required {
		if !listed[path] {
			return Package{}, fmt.Errorf("%w: %s is missing", ErrSignature, path)
		}
	}
	digest := sha256.Sum256(manifestBytes)
	return Package{Manifest: manifest, ManifestSHA256: hex.EncodeToString(digest[:]), path: path}, nil
}

func verifyManifest(raw, signature []byte, keys map[string]ed25519.PublicKey) (Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil || decoder.More() {
		return Manifest{}, fmt.Errorf("%w: manifest is not canonical", ErrSignature)
	}
	key, ok := keys[manifest.KeyID]
	if manifest.Schema != strings.TrimSpace(signatureDomain) || !ok || len(key) != ed25519.PublicKeySize {
		return Manifest{}, fmt.Errorf("%w: unknown schema or signing key", ErrSignature)
	}
	encoded := bytes.TrimSuffix(signature, []byte("\n"))
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Strict().Decode(decoded, encoded)
	if err != nil || n != ed25519.SignatureSize ||
		!ed25519.Verify(key, append([]byte(signatureDomain), raw...), decoded[:n]) {
		return Manifest{}, fmt.Errorf("%w: signature does not verify", ErrSignature)
	}
	if !versionPattern.MatchString(manifest.Version) || manifest.Platform.OS != "linux" || manifest.Platform.Arch != "amd64" ||
		!manifest.Runtime.ReleaseEligible || !runtimePattern.MatchString(manifest.Runtime.OpenRestyVersion) ||
		len(manifest.Files) == 0 || len(manifest.Files) > maxMembers-2 {
		return Manifest{}, fmt.Errorf("%w: manifest facts rejected", ErrSignature)
	}
	return manifest, nil
}

func safeMember(path string) bool {
	if !memberPattern.MatchString(path) {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	if memberExact[path] || path == manifestName || path == signatureName {
		return true
	}
	for _, prefix := range memberPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func openPackage(path string) (*os.File, *tar.Reader, func(), error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPackageBytes {
		file.Close()
		return nil, nil, nil, fmt.Errorf("%w: package file rejected", ErrSignature)
	}
	compressed, err := gzip.NewReader(file)
	if err != nil {
		file.Close()
		return nil, nil, nil, fmt.Errorf("%w: package is not gzip", ErrSignature)
	}
	compressed.Multistream(false)
	limited := &limitReader{reader: compressed, remaining: maxTotalBytes}
	return file, tar.NewReader(limited), func() { compressed.Close(); file.Close() }, nil
}

type limitReader struct {
	reader    io.Reader
	remaining int64
}

func (l *limitReader) Read(buffer []byte) (int, error) {
	if l.remaining <= 0 {
		return 0, fmt.Errorf("%w: expanded package too large", ErrSignature)
	}
	if int64(len(buffer)) > l.remaining {
		buffer = buffer[:l.remaining]
	}
	n, err := l.reader.Read(buffer)
	l.remaining -= int64(n)
	return n, err
}

// scan reads every member once: size, mode and digest; the manifest and the
// signature are kept.
func scan(path string) (map[string]member, map[string][]byte, error) {
	_, reader, closeAll, err := openPackage(path)
	if err != nil {
		return nil, nil, err
	}
	defer closeAll()
	members, metadata := map[string]member{}, map[string][]byte{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%w: tar framing: %v", ErrSignature, err)
		}
		if (header.Typeflag != tar.TypeReg && header.Typeflag != '\x00') || header.Linkname != "" || !safeMember(header.Name) ||
			(header.Mode != 0o444 && header.Mode != 0o555) || header.Size < 0 || header.Size > maxMemberBytes ||
			len(members) >= maxMembers {
			return nil, nil, fmt.Errorf("%w: member %q rejected", ErrSignature, header.Name)
		}
		if _, duplicate := members[header.Name]; duplicate {
			return nil, nil, fmt.Errorf("%w: duplicate member %q", ErrSignature, header.Name)
		}
		hash := sha256.New()
		var body bytes.Buffer
		writer := io.Writer(hash)
		if header.Name == manifestName || header.Name == signatureName {
			if header.Size > maxManifest || header.Mode != 0o444 {
				return nil, nil, fmt.Errorf("%w: manifest member rejected", ErrSignature)
			}
			writer = io.MultiWriter(hash, &body)
		}
		if n, err := io.Copy(writer, reader); err != nil || n != header.Size {
			return nil, nil, fmt.Errorf("%w: member %q truncated", ErrSignature, header.Name)
		}
		members[header.Name] = member{size: header.Size, mode: header.Mode, digest: hex.EncodeToString(hash.Sum(nil))}
		if body.Len() > 0 {
			metadata[header.Name] = body.Bytes()
		}
	}
	for name := range members {
		for parent := filepath.Dir(name); parent != "."; parent = filepath.Dir(parent) {
			if _, collision := members[parent]; collision {
				return nil, nil, fmt.Errorf("%w: file and directory collision", ErrSignature)
			}
		}
	}
	return members, metadata, nil
}

// Extract writes the verified package into the new directory destination
// (created 0755), re-checking every member against the signed inventory.
func (p Package) Extract(destination string) (err error) {
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(destination)
		}
	}()
	signed := make(map[string]File, len(p.Manifest.Files))
	for _, file := range p.Manifest.Files {
		signed[file.Path] = file
	}
	_, reader, closeAll, err := openPackage(p.path)
	if err != nil {
		return err
	}
	defer closeAll()
	written := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: tar framing: %v", ErrSignature, err)
		}
		file, listed := signed[header.Name]
		if !listed && header.Name != manifestName && header.Name != signatureName {
			return fmt.Errorf("%w: unlisted member %q", ErrSignature, header.Name)
		}
		if !safeMember(header.Name) {
			return fmt.Errorf("%w: member %q rejected", ErrSignature, header.Name)
		}
		target := filepath.Join(destination, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		hash := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(output, hash), reader)
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || n != header.Size {
			return fmt.Errorf("write %s: %w", header.Name, errors.Join(copyErr, syncErr, closeErr))
		}
		if listed && (hex.EncodeToString(hash.Sum(nil)) != file.SHA256 || n != file.Size) {
			return fmt.Errorf("%w: member %q changed", ErrSignature, header.Name)
		}
		if err := os.Chmod(target, os.FileMode(header.Mode)); err != nil {
			return err
		}
		if listed {
			written++
		}
	}
	if written != len(signed) {
		return fmt.Errorf("%w: members missing", ErrSignature)
	}
	return filepath.WalkDir(destination, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return err
		}
		return os.Chmod(path, 0o755)
	})
}

// installedRuntimeSHA256 is RuntimeSHA256 of an installed release, read
// from the manifest the installer extracted with it.
func installedRuntimeSHA256(release string) (string, Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(release, manifestName))
	if err != nil {
		return "", Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return "", Manifest{}, err
	}
	return runtimeDigest(manifest.Files), manifest, nil
}

// VerifyInstalledRelease checks an installed release (install-node.sh keeps
// release.manifest.json and its signature in it): the signature under keys
// and every signed file's digest.
func VerifyInstalledRelease(release string, keys map[string]ed25519.PublicKey) (Package, error) {
	raw, err := os.ReadFile(filepath.Join(release, manifestName))
	if err != nil {
		return Package{}, err
	}
	signature, err := os.ReadFile(filepath.Join(release, signatureName))
	if err != nil {
		return Package{}, err
	}
	manifest, err := verifyManifest(raw, signature, keys)
	if err != nil {
		return Package{}, err
	}
	if err := verifyInstalled(release, manifest); err != nil {
		return Package{}, err
	}
	digest := sha256.Sum256(raw)
	return Package{Manifest: manifest, ManifestSHA256: hex.EncodeToString(digest[:])}, nil
}

// verifyInstalled re-hashes every signed file of an installed release.
func verifyInstalled(release string, manifest Manifest) error {
	for _, file := range manifest.Files {
		content, err := os.Open(filepath.Join(release, filepath.FromSlash(file.Path)))
		if err != nil {
			return err
		}
		hash := sha256.New()
		n, err := io.Copy(hash, content)
		content.Close()
		if err != nil || n != file.Size || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
			return fmt.Errorf("%w: installed %s differs", ErrSignature, file.Path)
		}
	}
	return nil
}
