package http3runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	dnsLabelPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

func normalize(policy Policy) (Policy, string, []byte, error) {
	if policy.SchemaVersion != SchemaVersionV1 || !identifierPattern.MatchString(policy.VersionID) {
		return Policy{}, "", nil, ErrInvalidPolicy
	}
	if !validProtocols(policy.Protocols) {
		return Policy{}, "", nil, ErrInvalidPolicy
	}
	if policy.Runtime.Family != RuntimeFamilyOpenResty || policy.Runtime.Version != RuntimeVersionOpenResty {
		return Policy{}, "", nil, ErrUnsupported
	}
	address, err := netip.ParseAddr(policy.Listener.Address)
	if err != nil || address.Zone() != "" || address.Is4In6() || address.IsMulticast() {
		return Policy{}, "", nil, ErrInvalidPolicy
	}
	serverName := strings.ToLower(strings.TrimSuffix(policy.Listener.ServerName, "."))
	if !validDNSName(serverName) || policy.Listener.Port < 1 || policy.Listener.Port > 65_535 ||
		policy.Listener.AltSvcMaxAgeSeconds < 0 || policy.Listener.AltSvcMaxAgeSeconds > maxAltSvcAgeSeconds {
		return Policy{}, "", nil, ErrInvalidPolicy
	}
	if policy.TLS.MinimumVersion != "TLSv1.3" || !safeDirectivePath(policy.TLS.CertificateFile) ||
		!validDigest(policy.TLS.CertificateSHA256) || !safeDirectivePath(policy.TLS.PrivateKeyFile) ||
		!validDigest(policy.TLS.PrivateKeySHA256) || policy.TLS.CertificateFile == policy.TLS.PrivateKeyFile {
		return Policy{}, "", nil, ErrInvalidPolicy
	}
	limits := policy.Limits
	if limits.IdleTimeoutMS < minIdleTimeoutMS || limits.IdleTimeoutMS > maxIdleTimeoutMS ||
		limits.WorkerConnections < minWorkerConnections || limits.WorkerConnections > maxWorkerConnections ||
		limits.ConnectionsPerClient < 1 || limits.ConnectionsPerClient > maxConnectionsPerClient ||
		limits.ConcurrentStreams < 1 || limits.ConcurrentStreams > maxConcurrentStreams ||
		limits.RequestHeaderBytes < minHeaderBytes || limits.RequestHeaderBytes > maxHeaderBytes || !powerOfTwo(limits.RequestHeaderBytes) ||
		limits.ActiveConnectionIDs < minActiveConnectionIDs || limits.ActiveConnectionIDs > maxActiveConnectionIDs {
		return Policy{}, "", nil, ErrInvalidPolicy
	}
	normalized := policy
	normalized.Listener.Address = address.String()
	normalized.Listener.ServerName = serverName
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return Policy{}, "", nil, ErrInvalidPolicy
	}
	canonical = append(canonical, '\n')
	digest := sha256.Sum256(canonical)
	return normalized, hex.EncodeToString(digest[:]), canonical, nil
}

func validProtocols(protocols []string) bool {
	if len(protocols) != 2 && len(protocols) != 3 {
		return false
	}
	if protocols[0] != "http1" || protocols[1] != "http2" {
		return false
	}
	return len(protocols) == 2 || protocols[2] == "http3"
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	return len(labels) >= 2
}

func safeAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) && !strings.ContainsAny(path, "\r\n\x00")
}

func safeDirectivePath(path string) bool {
	if !safeAbsolutePath(path) {
		return false
	}
	for _, character := range path {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("/_.-", character) {
			continue
		}
		return false
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func powerOfTwo(value int) bool {
	return value > 0 && value&(value-1) == 0
}
