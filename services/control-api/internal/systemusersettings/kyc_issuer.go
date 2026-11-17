package systemusersettings

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// The evidence issuer fields of the page are checked in the
// form identityverificationissuerhttp.NewListener / NewMTLSAuthenticator and
// the control-api issuer environment accept (that package depends on this
// one, so the rules are repeated here). The checks that depend on the clock
// (certificate validity) run on save only (kycIssuerSaveError), so a stored
// certificate that expires later keeps the page readable; the runtime checks
// them again when it builds the listener.

const kycIssuerPEMMaxBytes = 65536

// kycIssuerFieldError names the first issuer field that is set but not
// usable; nil when every set field is valid.
func kycIssuerFieldError(value Settings) error {
	field := func(name, reason string) error { return fielderr.New(ErrInvalidInput, "value."+name, reason) }
	if value.KYCIssuerListenAddress != "" && !validKYCIssuerListenAddress(value.KYCIssuerListenAddress) {
		return field("kyc_issuer_listen_address", fielderr.InvalidFormat)
	}
	if value.KYCIssuerServerCertificate != "" {
		chain, ok := kycIssuerCertificates(value.KYCIssuerServerCertificate)
		if !ok {
			return field("kyc_issuer_server_certificate", fielderr.InvalidFormat)
		}
		if !validKYCIssuerServerChain(chain) {
			return field("kyc_issuer_server_certificate", fielderr.Invalid)
		}
	}
	if value.KYCIssuerClientCA != "" {
		authorities, ok := kycIssuerCertificates(value.KYCIssuerClientCA)
		if !ok {
			return field("kyc_issuer_client_ca", fielderr.InvalidFormat)
		}
		for _, authority := range authorities {
			if !authority.BasicConstraintsValid || !authority.IsCA || authority.KeyUsage&x509.KeyUsageCertSign == 0 ||
				!kycIssuerAllowsUsage(authority, x509.ExtKeyUsageClientAuth) {
				return field("kyc_issuer_client_ca", fielderr.Invalid)
			}
		}
	}
	if value.KYCIssuerWorkloadIdentities != "" && !validKYCIssuerWorkloadIdentities(value.KYCIssuerWorkloadIdentities) {
		return field("kyc_issuer_workload_identities", fielderr.InvalidFormat)
	}
	if value.KYCIssuerKMSEndpoint != "" && !validKYCIssuerKMSEndpoint(value.KYCIssuerKMSEndpoint) {
		return field("kyc_issuer_kms_endpoint", fielderr.InvalidFormat)
	}
	return nil
}

// kycIssuerSaveError checks a save at now: the page certificates must be
// valid (the server one for at least another hour, as the listener requires)
// and a private key sent with a page server certificate must match it.
func kycIssuerSaveError(value Settings, secrets map[string]*string, now time.Time) error {
	field := func(name string) error { return fielderr.New(ErrInvalidInput, name, fielderr.Invalid) }
	now = now.UTC()
	if value.KYCIssuerServerCertificate != "" {
		chain, _ := kycIssuerCertificates(value.KYCIssuerServerCertificate)
		for index, certificate := range chain {
			minimum := now
			if index == 0 {
				minimum = now.Add(time.Hour)
			}
			if now.Before(certificate.NotBefore) || !minimum.Before(certificate.NotAfter) {
				return field("value.kyc_issuer_server_certificate")
			}
		}
		if key := secrets[SecretKYCIssuerServerPrivateKey]; key != nil && *key != "" {
			if _, err := tls.X509KeyPair([]byte(value.KYCIssuerServerCertificate), []byte(*key)); err != nil {
				return field(SecretKYCIssuerServerPrivateKey)
			}
		}
	}
	if value.KYCIssuerClientCA != "" {
		authorities, _ := kycIssuerCertificates(value.KYCIssuerClientCA)
		for _, authority := range authorities {
			if now.Before(authority.NotBefore) || !now.Before(authority.NotAfter) {
				return field("value.kyc_issuer_client_ca")
			}
		}
	}
	return nil
}

// kycIssuerCertificates parses PEM text made only of CERTIFICATE blocks.
func kycIssuerCertificates(text string) ([]*x509.Certificate, bool) {
	if len(text) > kycIssuerPEMMaxBytes || strings.ContainsAny(text, "\r\x00") {
		return nil, false
	}
	var result []*x509.Certificate
	for remaining := bytes.TrimSpace([]byte(text)); len(remaining) > 0; {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, false
		}
		result = append(result, certificate)
		remaining = bytes.TrimSpace(rest)
	}
	return result, len(result) > 0
}

// validKYCIssuerServerChain: a server-auth leaf that is not a CA, then
// signing CAs each of which signed the one before.
func validKYCIssuerServerChain(chain []*x509.Certificate) bool {
	leaf := chain[0]
	if leaf.IsCA || !kycIssuerAllowsUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return false
	}
	child := leaf
	for _, issuer := range chain[1:] {
		if !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 || child.CheckSignatureFrom(issuer) != nil {
			return false
		}
		child = issuer
	}
	return true
}

func kycIssuerAllowsUsage(certificate *x509.Certificate, required x509.ExtKeyUsage) bool {
	if len(certificate.ExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == required || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// validKYCIssuerPrivateKey: exactly one PEM private key block that parses.
func validKYCIssuerPrivateKey(text string) bool {
	block, rest := pem.Decode([]byte(text))
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	defer clear(block.Bytes)
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		_, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return false
	}
	return err == nil
}

// validKYCIssuerListenAddress: host:port with a host and a port 1-65535.
func validKYCIssuerListenAddress(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	port, portErr := strconv.Atoi(portText)
	return err == nil && portErr == nil && host != "" && port >= 1 && port <= 65535 && strings.TrimSpace(value) == value
}

// validKYCIssuerWorkloadIdentities: "spiffe-uri|workload-id" pairs separated
// by commas, at most 1024, no URI or workload ID twice.
func validKYCIssuerWorkloadIdentities(raw string) bool {
	parts := strings.Split(raw, ",")
	if len(parts) > 1024 {
		return false
	}
	uris, workloads := make(map[string]struct{}, len(parts)), make(map[string]struct{}, len(parts))
	for _, part := range parts {
		uri, workloadID, ok := strings.Cut(part, "|")
		if !ok || strings.Contains(workloadID, "|") || !canonicalKYCIssuerWorkloadURI(uri) || !validKYCIssuerWorkloadID(workloadID) {
			return false
		}
		if _, duplicate := uris[uri]; duplicate {
			return false
		}
		if _, duplicate := workloads[workloadID]; duplicate {
			return false
		}
		uris[uri], workloads[workloadID] = struct{}{}, struct{}{}
	}
	return true
}

func canonicalKYCIssuerWorkloadURI(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "spiffe" || parsed.User != nil || parsed.Host == "" ||
		parsed.Host != parsed.Hostname() || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.RawPath != "" || !strings.HasPrefix(parsed.Path, "/") {
		return false
	}
	for _, segment := range strings.Split(parsed.Path[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return parsed.String() == raw
}

func validKYCIssuerWorkloadID(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.ContainsFunc(value, unicode.IsSpace) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' ||
			strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

// validKYCIssuerKMSEndpoint: an https origin, or http on a loopback host.
func validKYCIssuerKMSEndpoint(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil {
		return false
	}
	host := parsed.Hostname()
	secure := parsed.Scheme == "https" || parsed.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1")
	return parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == "" && secure
}

// setKYCIssuerRuntime copies the issuer fields of the page and the opened
// server private key into the runtime view.
func setKYCIssuerRuntime(runtime *IdentityVerificationRuntime, value Settings, secrets map[string]string) {
	runtime.IssuerEnabled, runtime.IssuerListenAddress = value.KYCIssuerEnabled, value.KYCIssuerListenAddress
	runtime.IssuerServerCertificate, runtime.IssuerClientCA = value.KYCIssuerServerCertificate, value.KYCIssuerClientCA
	runtime.IssuerWorkloadIdentities, runtime.IssuerKMSEndpoint = value.KYCIssuerWorkloadIdentities, value.KYCIssuerKMSEndpoint
	if key := secrets[SecretKYCIssuerServerPrivateKey]; key != "" {
		runtime.IssuerServerPrivateKey = []byte(key)
	}
}
