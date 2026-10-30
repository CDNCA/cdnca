package certstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	manifestSchemaVersion   = "cdnca.edge.certificate-manifest/v1"
	clientBodyTempDirectory = "client-body-temp"
	proxyTempDirectory      = "proxy-temp"
	fastCGITempDirectory    = "fastcgi-temp"
	uWSGITempDirectory      = "uwsgi-temp"
	scgiTempDirectory       = "scgi-temp"
)

func CompileJSON(raw []byte, config RuntimeConfig, now time.Time) (Artifact, error) {
	if len(raw) == 0 || len(raw) > MaxBundleBytes {
		return Artifact{}, invalid("bundle size must be between 1 and %d bytes", MaxBundleBytes)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return Artifact{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Artifact{}, invalid("decode bundle: %v", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Artifact{}, err
	}
	return Compile(bundle, config, now)
}

func Compile(bundle Bundle, config RuntimeConfig, now time.Time) (Artifact, error) {
	return compile(bundle, config, now, nil, true)
}

func CompileWithActivation(bundle Bundle, config RuntimeConfig, now time.Time, activation ActivationMetadata) (Artifact, error) {
	return compile(bundle, config, now, &activation, true)
}

func compile(bundle Bundle, config RuntimeConfig, now time.Time, activation *ActivationMetadata, checkValidity bool) (Artifact, error) {
	if err := validateRuntimeConfig(config); err != nil {
		return Artifact{}, err
	}
	// A command without bindings only removes sites, and says so explicitly.
	explicitRemoval := activation != nil && bundle.Bindings != nil && len(bundle.Bindings) == 0 &&
		activation.Certificates != nil && len(activation.Certificates) == 0 && len(activation.RemovedSites) != 0
	normalized, err := normalizeBundle(bundle, now.UTC(), explicitRemoval, checkValidity)
	if err != nil {
		return Artifact{}, err
	}
	normalizedActivation, err := normalizeActivation(activation, normalized)
	if err != nil {
		return Artifact{}, err
	}
	manifest := Manifest{
		SchemaVersion: manifestSchemaVersion,
		VersionID:     normalized.VersionID,
		Activation:    normalizedActivation,
		Bindings:      make([]ManifestBinding, 0, len(normalized.Bindings)),
	}
	files := make([]ArtifactFile, 0, 2+len(normalized.Bindings)*2)
	health := make([]HealthTarget, 0)
	for index, binding := range normalized.Bindings {
		certificatePath := fmt.Sprintf("certificates/certificate-%03d.pem", index)
		privateKeyPath := fmt.Sprintf("private/private-key-%03d.pem", index)
		leafDigest := sha256.Sum256(binding.Leaf.Raw)
		manifest.Bindings = append(manifest.Bindings, ManifestBinding{
			SiteID: binding.SiteID, Domains: append([]string(nil), binding.Domains...),
			CertificateFile: certificatePath, PrivateKeyFile: privateKeyPath, LeafSHA256: hex.EncodeToString(leafDigest[:]),
		})
		files = append(files,
			ArtifactFile{Path: certificatePath, Content: bytes.Clone(binding.CertificatePEM), Mode: 0o400},
			ArtifactFile{Path: privateKeyPath, Content: bytes.Clone(binding.PrivateKeyPEM), Mode: 0o400, Private: true},
		)
		for _, domain := range binding.Domains {
			health = append(health, HealthTarget{ServerName: healthServerName(domain), LeafSHA256: leafDigest})
		}
	}
	sort.Slice(health, func(i, j int) bool { return health[i].ServerName < health[j].ServerName })

	nginx, err := renderNginx(config, normalized, manifest)
	if err != nil {
		return Artifact{}, err
	}
	manifestWithoutDigest, err := json.Marshal(manifest)
	if err != nil {
		return Artifact{}, fmt.Errorf("marshal certificate manifest: %w", err)
	}
	digest := artifactDigest(manifestWithoutDigest, nginx, files)
	manifest.Digest = digest
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return Artifact{}, fmt.Errorf("marshal certificate manifest: %w", err)
	}
	manifestJSON = append(manifestJSON, '\n')
	files = append([]ArtifactFile{
		{Path: "manifest.json", Content: manifestJSON, Mode: 0o400},
		{Path: "nginx.conf", Content: nginx, Mode: 0o400},
	}, files...)
	return Artifact{VersionID: normalized.VersionID, Digest: digest, Manifest: manifest, Activation: normalizedActivation, Files: files, HealthTargets: health}, nil
}

func validateRuntimeConfig(config RuntimeConfig) error {
	if !filepath.IsAbs(config.StateRoot) || filepath.Clean(config.StateRoot) != config.StateRoot || hasControl(config.StateRoot) {
		return invalid("state root must be a clean absolute path")
	}
	address, err := netip.ParseAddr(config.ListenAddress)
	if err != nil || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
		return invalid("listen address must be an unzoned unicast IP literal")
	}
	if config.ListenPort == 0 {
		return invalid("listen port is required")
	}
	return nil
}

func renderNginx(config RuntimeConfig, bundle normalizedBundle, manifest Manifest) ([]byte, error) {
	listenAddress := config.ListenAddress
	if strings.Contains(listenAddress, ":") {
		listenAddress = "[" + listenAddress + "]"
	}
	listen := fmt.Sprintf("%s:%d", listenAddress, config.ListenPort)
	pid := filepath.Join(config.StateRoot, "shared", "nginx.pid")
	errorLog := filepath.Join(config.StateRoot, "shared", "error.log")
	quotedPID, err := nginxQuoted(pid)
	if err != nil {
		return nil, err
	}
	quotedErrorLog, err := nginxQuoted(errorLog)
	if err != nil {
		return nil, err
	}
	var output strings.Builder
	fmt.Fprintf(&output, "worker_processes 1;\npid %s;\nerror_log %s notice;\n", quotedPID, quotedErrorLog)
	output.WriteString("events { worker_connections 2048; }\nhttp {\n  access_log off;\n")
	for _, temporary := range []struct {
		directive string
		directory string
	}{
		{directive: "client_body_temp_path", directory: clientBodyTempDirectory},
		{directive: "proxy_temp_path", directory: proxyTempDirectory},
		{directive: "fastcgi_temp_path", directory: fastCGITempDirectory},
		{directive: "uwsgi_temp_path", directory: uWSGITempDirectory},
		{directive: "scgi_temp_path", directory: scgiTempDirectory},
	} {
		path, err := nginxQuoted(filepath.Join(config.StateRoot, "shared", temporary.directory))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&output, "  %s %s;\n", temporary.directive, path)
	}
	fmt.Fprintf(&output, "  server {\n    listen %s ssl default_server;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_reject_handshake on;\n  }\n", listen)
	for index, binding := range bundle.Bindings {
		manifestBinding := manifest.Bindings[index]
		output.WriteString("  server {\n")
		fmt.Fprintf(&output, "    listen %s ssl;\n    server_name", listen)
		for _, domain := range binding.Domains {
			if strings.HasPrefix(domain, "*.") {
				fmt.Fprintf(&output, " ~^[^.]+\\.%s$", strings.ReplaceAll(strings.TrimPrefix(domain, "*."), ".", "\\."))
			} else {
				fmt.Fprintf(&output, " %s", domain)
			}
		}
		output.WriteString(";\n")
		fmt.Fprintf(&output, "    ssl_certificate %s;\n    ssl_certificate_key %s;\n", manifestBinding.CertificateFile, manifestBinding.PrivateKeyFile)
		output.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_session_tickets off;\n    keepalive_timeout 30s;\n")
		fmt.Fprintf(&output, "    location / { default_type text/plain; return 200 %q; }\n", "certificate-version:"+bundle.VersionID+"\n")
		output.WriteString("  }\n")
	}
	output.WriteString("}\n")
	return []byte(output.String()), nil
}

func nginxQuoted(value string) (string, error) {
	if value == "" || hasControl(value) {
		return "", invalid("runtime path contains unsafe characters")
	}
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$")
	return "\"" + replacer.Replace(value) + "\"", nil
}

func healthServerName(domain string) string {
	if strings.HasPrefix(domain, "*.") {
		return "cdnca-health." + strings.TrimPrefix(domain, "*.")
	}
	return domain
}

func artifactDigest(manifest, nginx []byte, files []ArtifactFile) string {
	hash := sha256.New()
	writeHashPart(hash, manifest)
	writeHashPart(hash, nginx)
	for _, file := range files {
		writeHashPart(hash, []byte(file.Path))
		writeHashPart(hash, file.Content)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type hashWriter interface{ Write([]byte) (int, error) }

func writeHashPart(hash hashWriter, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(value)
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return invalid("decode tokens: %v", err)
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return invalid("decode object key")
				}
				key, ok := keyToken.(string)
				if !ok {
					return invalid("object key is not a string")
				}
				if _, exists := keys[key]; exists {
					return invalid("duplicate JSON key %q", key)
				}
				keys[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return invalid("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return invalid("multiple JSON values are not allowed")
		}
		return invalid("trailing JSON")
	}
	return nil
}
