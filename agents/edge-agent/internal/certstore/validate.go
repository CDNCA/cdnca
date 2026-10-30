package certstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

type normalizedBundle struct {
	VersionID string
	Bindings  []normalizedBinding
}

type normalizedBinding struct {
	SiteID         string
	Domains        []string
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Leaf           *x509.Certificate
}

// checkValidity is false only for a stored release: its content was
// validated when it was activated and its digest is checked; the probe
// runtime keeps serving it after a certificate in it expires.
func normalizeBundle(bundle Bundle, now time.Time, allowEmpty, checkValidity bool) (normalizedBundle, error) {
	if bundle.SchemaVersion != SchemaVersion {
		return normalizedBundle{}, invalid("schema_version must be %q", SchemaVersion)
	}
	if !validIdentifier(bundle.VersionID, MaxVersionIDBytes) {
		return normalizedBundle{}, invalid("version_id has an invalid format")
	}
	if !allowEmpty && len(bundle.Bindings) == 0 {
		return normalizedBundle{}, invalid("a bundle without bindings must be an explicit removal")
	}

	result := normalizedBundle{VersionID: bundle.VersionID, Bindings: make([]normalizedBinding, 0, len(bundle.Bindings))}
	sites := make(map[string]struct{}, len(bundle.Bindings))
	for index, input := range bundle.Bindings {
		binding, err := normalizeBinding(input, now, checkValidity)
		if err != nil {
			return normalizedBundle{}, invalid("binding %d: %v", index, err)
		}
		if _, exists := sites[binding.SiteID]; exists {
			return normalizedBundle{}, invalid("duplicate site_id %q", binding.SiteID)
		}
		sites[binding.SiteID] = struct{}{}
		result.Bindings = append(result.Bindings, binding)
	}
	sort.Slice(result.Bindings, func(i, j int) bool { return result.Bindings[i].SiteID < result.Bindings[j].SiteID })
	if err := rejectSNIConflicts(result.Bindings); err != nil {
		return normalizedBundle{}, err
	}
	return result, nil
}

func normalizeActivation(input *ActivationMetadata, bundle normalizedBundle) (*ActivationMetadata, error) {
	if input == nil {
		return nil, nil
	}
	if input.SchemaVersion != ActivationSchemaVersion || input.ConfigVersionID != bundle.VersionID ||
		!validMetadataIdentifier(input.RecipientKeyID, 128) || !validMetadataIdentifier(input.CommandEventID, 128) ||
		!validMetadataIdentifier(input.DeploymentID, 128) || input.Attempt == 0 ||
		!validMetadataIdentifier(input.ArtifactID, 128) || len(input.Certificates) != len(bundle.Bindings) {
		return nil, invalid("certificate activation metadata is invalid")
	}
	bindings := make(map[string]struct{}, len(bundle.Bindings))
	for _, binding := range bundle.Bindings {
		bindings[binding.SiteID] = struct{}{}
	}
	result := *input
	result.Certificates = make([]CertificateRevision, len(input.Certificates))
	copy(result.Certificates, input.Certificates)
	seenSites := make(map[string]struct{}, len(result.Certificates)+len(input.RemovedSites))
	seenCertificates := make(map[string]struct{}, len(result.Certificates))
	for _, revision := range result.Certificates {
		// Every revision names its version and its site's binding revision:
		// the node orders each site by binding revision (sites/ index).
		if !validIdentifier(revision.TenantID, MaxSiteIDBytes) || !validIdentifier(revision.SiteID, MaxSiteIDBytes) ||
			!validIdentifier(revision.CertificateID, MaxSiteIDBytes) || revision.Version == 0 || revision.BindingRevision == 0 {
			return nil, invalid("certificate activation revision is invalid")
		}
		if !canonicalUUID(revision.TenantScopeID) || !canonicalUUID(revision.CertificateVersionID) {
			return nil, invalid("certificate activation version identity is invalid")
		}
		if _, exists := bindings[revision.SiteID]; !exists {
			return nil, invalid("certificate activation site is not in the bundle")
		}
		identity := revision.TenantID + "\x00" + revision.TenantScopeID + "\x00" + revision.SiteID + "\x00" +
			revision.CertificateID + "\x00" + revision.CertificateVersionID
		if _, exists := seenSites[revision.SiteID]; exists {
			return nil, invalid("certificate activation site is duplicated")
		}
		if _, exists := seenCertificates[identity]; exists {
			return nil, invalid("certificate activation identity is duplicated")
		}
		seenSites[revision.SiteID] = struct{}{}
		seenCertificates[identity] = struct{}{}
	}
	if len(input.RemovedSites) == 0 {
		result.RemovedSites = nil
	} else {
		result.RemovedSites = append([]RemovedSite(nil), input.RemovedSites...)
	}
	for _, removed := range result.RemovedSites {
		if !validIdentifier(removed.TenantID, MaxSiteIDBytes) || !canonicalUUID(removed.TenantScopeID) ||
			!validIdentifier(removed.SiteID, MaxSiteIDBytes) || removed.BindingRevision == 0 {
			return nil, invalid("certificate activation removal is invalid")
		}
		if _, exists := seenSites[removed.SiteID]; exists {
			return nil, invalid("certificate activation site is duplicated")
		}
		seenSites[removed.SiteID] = struct{}{}
	}
	sort.Slice(result.RemovedSites, func(i, j int) bool { return result.RemovedSites[i].SiteID < result.RemovedSites[j].SiteID })
	sort.Slice(result.Certificates, func(i, j int) bool {
		left, right := result.Certificates[i], result.Certificates[j]
		if left.TenantID != right.TenantID {
			return left.TenantID < right.TenantID
		}
		if left.SiteID != right.SiteID {
			return left.SiteID < right.SiteID
		}
		return left.CertificateID < right.CertificateID
	})
	return &result, nil
}

// validateCommandReplay: a command identity names one set of revisions.
// Activations are per-site deltas ordered by binding revision (planIndex);
// only a replayed command with other content is refused here.
func validateCommandReplay(previous, candidate *ActivationMetadata, active bool) error {
	if !active {
		return nil
	}
	if previous == nil || candidate == nil {
		if previous == nil && candidate == nil {
			return nil
		}
		return ErrStaleActivation
	}
	if sameActivationCommand(previous, candidate) && !sameActivationMetadata(previous, candidate) {
		return ErrStaleActivation
	}
	return nil
}

func sameActivationCommand(left, right *ActivationMetadata) bool {
	return left.SchemaVersion == right.SchemaVersion && left.ConfigVersionID == right.ConfigVersionID &&
		left.RecipientKeyID == right.RecipientKeyID && left.CommandEventID == right.CommandEventID &&
		left.DeploymentID == right.DeploymentID && left.Attempt == right.Attempt && left.ArtifactID == right.ArtifactID
}

func sameCertificateRevisions(left, right []CertificateRevision) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func normalizeCertificateVersionReferences(input CertificateVersionReferences) (CertificateVersionReferences, error) {
	normalize := func(values []string) ([]string, error) {
		result := append(make([]string, 0, len(values)), values...)
		sort.Strings(result)
		for index, value := range result {
			if !canonicalUUID(value) || (index > 0 && value == result[index-1]) {
				return nil, ErrCertificateUnavailable
			}
		}
		return result, nil
	}
	current, err := normalize(input.Current)
	if err != nil {
		return CertificateVersionReferences{}, err
	}
	previous, err := normalize(input.Previous)
	if err != nil {
		return CertificateVersionReferences{}, err
	}
	return CertificateVersionReferences{Current: current, Previous: previous}, nil
}

func normalizeBinding(input Binding, now time.Time, checkValidity bool) (normalizedBinding, error) {
	if !validIdentifier(input.SiteID, MaxSiteIDBytes) {
		return normalizedBinding{}, fmt.Errorf("site_id has an invalid format")
	}
	if len(input.Domains) == 0 || len(input.Domains) > MaxDomainsPerSite {
		return normalizedBinding{}, fmt.Errorf("domain count must be between 1 and %d", MaxDomainsPerSite)
	}
	domains := make([]string, 0, len(input.Domains))
	seen := make(map[string]struct{}, len(input.Domains))
	for index, domain := range input.Domains {
		normalized, err := normalizeDomain(domain, true)
		if err != nil {
			return normalizedBinding{}, fmt.Errorf("domain %d is invalid", index)
		}
		if _, exists := seen[normalized]; exists {
			return normalizedBinding{}, fmt.Errorf("duplicate domain %q", normalized)
		}
		seen[normalized] = struct{}{}
		domains = append(domains, normalized)
	}
	sort.Strings(domains)

	certificates, certificatePEM, err := parseCertificateChain([]byte(input.CertificateChainPEM), now, checkValidity)
	if err != nil {
		return normalizedBinding{}, err
	}
	privateKey, privateKeyPEM, err := parsePrivateKey([]byte(input.PrivateKeyPEM))
	if err != nil {
		return normalizedBinding{}, err
	}
	leaf := certificates[0]
	if err := validateKeyPair(leaf, privateKey); err != nil {
		return normalizedBinding{}, err
	}
	for _, domain := range domains {
		if err := certificateCovers(leaf, domain); err != nil {
			return normalizedBinding{}, fmt.Errorf("leaf SAN does not cover bound domain %q", domain)
		}
	}
	return normalizedBinding{
		SiteID: input.SiteID, Domains: domains, CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM, Leaf: leaf,
	}, nil
}

func parseCertificateChain(value []byte, now time.Time, checkValidity bool) ([]*x509.Certificate, []byte, error) {
	if len(value) == 0 || len(value) > MaxCertificateBytes || bytes.IndexByte(value, 0) >= 0 {
		return nil, nil, fmt.Errorf("certificate chain is empty, oversized, or contains a NUL byte")
	}
	remaining := value
	certificates := make([]*x509.Certificate, 0, 4)
	canonical := make([]byte, 0, len(value))
	seen := make(map[string]struct{})
	for len(bytes.TrimSpace(remaining)) > 0 {
		trimmed := bytes.TrimSpace(remaining)
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, nil, fmt.Errorf("certificate chain contains non-PEM data")
		}
		block, rest := pem.Decode(trimmed)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, fmt.Errorf("certificate chain contains an unsupported PEM block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("certificate chain contains an unparsable certificate")
		}
		fingerprint := string(certificate.Raw)
		if _, exists := seen[fingerprint]; exists {
			return nil, nil, fmt.Errorf("certificate chain contains a duplicate certificate")
		}
		seen[fingerprint] = struct{}{}
		certificates = append(certificates, certificate)
		if len(certificates) > 8 {
			return nil, nil, fmt.Errorf("certificate chain exceeds 8 certificates")
		}
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
		remaining = rest
	}
	if len(certificates) == 0 {
		return nil, nil, fmt.Errorf("certificate chain contains no certificate")
	}
	for index, certificate := range certificates {
		if checkValidity && (now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter)) {
			return nil, nil, fmt.Errorf("certificate %d is not currently valid", index)
		}
		if weakSignature(certificate.SignatureAlgorithm) {
			return nil, nil, fmt.Errorf("certificate %d uses a weak or unsupported signature algorithm", index)
		}
		if err := validatePublicKey(certificate.PublicKey); err != nil {
			return nil, nil, fmt.Errorf("certificate %d: %v", index, err)
		}
	}
	leaf := certificates[0]
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !allowsServerAuth(leaf.ExtKeyUsage) {
		return nil, nil, fmt.Errorf("leaf certificate is not valid for TLS server authentication")
	}
	for index := 1; index < len(certificates); index++ {
		issuer := certificates[index]
		if !issuer.IsCA || !issuer.BasicConstraintsValid || issuer.KeyUsage&x509.KeyUsageCertSign == 0 ||
			certificates[index-1].CheckSignatureFrom(issuer) != nil {
			return nil, nil, fmt.Errorf("certificate chain linkage failed at certificate %d", index)
		}
	}
	return certificates, canonical, nil
}

func parsePrivateKey(value []byte) (crypto.PrivateKey, []byte, error) {
	if len(value) == 0 || len(value) > MaxPrivateKeyBytes || bytes.IndexByte(value, 0) >= 0 {
		return nil, nil, fmt.Errorf("private key is empty, oversized, or contains a NUL byte")
	}
	trimmed := bytes.TrimSpace(value)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, nil, fmt.Errorf("private key is not PEM encoded")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, nil, fmt.Errorf("private key must contain exactly one unencrypted PEM block")
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" || x509.IsEncryptedPEMBlock(block) {
		return nil, nil, fmt.Errorf("encrypted private keys are not supported")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, nil, fmt.Errorf("private key PEM type is unsupported")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("private key cannot be parsed")
	}
	privateKey, ok := key.(crypto.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key type is unsupported")
	}
	if err := validatePrivateKey(privateKey); err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("private key cannot be normalized")
	}
	return privateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func validatePrivateKey(key crypto.PrivateKey) error {
	switch value := key.(type) {
	case *rsa.PrivateKey:
		if value.N.BitLen() < 2048 || value.Validate() != nil {
			return fmt.Errorf("RSA private key must be valid and at least 2048 bits")
		}
	case *ecdsa.PrivateKey:
		if value.Curve != elliptic.P256() && value.Curve != elliptic.P384() && value.Curve != elliptic.P521() {
			return fmt.Errorf("EC private key curve is unsupported")
		}
	default:
		return fmt.Errorf("private key must be RSA or ECDSA")
	}
	return nil
}

func validatePublicKey(key any) error {
	switch value := key.(type) {
	case *rsa.PublicKey:
		if value.N.BitLen() < 2048 {
			return fmt.Errorf("RSA public key must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if value.Curve != elliptic.P256() && value.Curve != elliptic.P384() && value.Curve != elliptic.P521() {
			return fmt.Errorf("EC public key curve is unsupported")
		}
	default:
		return fmt.Errorf("certificate public key must be RSA or ECDSA")
	}
	return nil
}

func validateKeyPair(leaf *x509.Certificate, privateKey crypto.PrivateKey) error {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key is not a signing key")
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("certificate public key cannot be encoded")
	}
	privatePublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(certificatePublic, privatePublic) {
		return fmt.Errorf("leaf certificate and private key do not match")
	}
	return nil
}

func certificateCovers(leaf *x509.Certificate, domain string) error {
	if strings.HasPrefix(domain, "*.") {
		for _, name := range leaf.DNSNames {
			normalized, err := normalizeDomain(name, true)
			if err == nil && normalized == domain {
				return nil
			}
		}
		return fmt.Errorf("wildcard SAN missing")
	}
	return leaf.VerifyHostname(domain)
}

func weakSignature(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1, x509.UnknownSignatureAlgorithm:
		return true
	default:
		return false
	}
}

func allowsServerAuth(usages []x509.ExtKeyUsage) bool {
	if len(usages) == 0 {
		return true
	}
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageAny || usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

// rejectSNIConflicts refuses a command whose bindings overlap: the probe
// runtime selects a binding by SNI. Exact names and wildcard bases are
// indexed, so a name is checked against the names it can overlap with only
// (an exact name against its wildcard parent, a wildcard against exact names
// one label below its base).
func rejectSNIConflicts(bindings []normalizedBinding) error {
	exact := make(map[string]string)
	wildcards := make(map[string]string) // base -> site
	children := make(map[string]string)  // parent of an exact name -> site
	for _, binding := range bindings {
		for _, domain := range binding.Domains {
			if base, found := strings.CutPrefix(domain, "*."); found {
				if owner, exists := wildcards[base]; exists {
					return invalid("SNI %q for site %q conflicts with %q for site %q", domain, binding.SiteID, domain, owner)
				}
				if owner, exists := children[base]; exists {
					return invalid("SNI %q for site %q conflicts with a name of site %q", domain, binding.SiteID, owner)
				}
				wildcards[base] = binding.SiteID
				continue
			}
			if owner, exists := exact[domain]; exists {
				return invalid("SNI %q for site %q conflicts with %q for site %q", domain, binding.SiteID, domain, owner)
			}
			if _, parent, found := strings.Cut(domain, "."); found {
				if owner, exists := wildcards[parent]; exists {
					return invalid("SNI %q for site %q conflicts with %q for site %q", domain, binding.SiteID, "*."+parent, owner)
				}
				if _, exists := children[parent]; !exists {
					children[parent] = binding.SiteID
				}
			}
			exact[domain] = binding.SiteID
		}
	}
	return nil
}

func normalizeDomain(value string, allowWildcard bool) (string, error) {
	if len(value) == 0 || len(value) > MaxDomainBytes || !utf8.ValidString(value) || !isASCII(value) || hasControl(value) || strings.HasSuffix(value, ".") {
		return "", fmt.Errorf("invalid domain length or encoding")
	}
	value = strings.ToLower(value)
	if strings.HasPrefix(value, "*.") {
		if !allowWildcard || strings.Count(value, "*") != 1 {
			return "", fmt.Errorf("wildcard must be the complete left-most label")
		}
		base := strings.TrimPrefix(value, "*.")
		if labelCount(base) < 2 || !validDNSLabels(base) {
			return "", fmt.Errorf("wildcard base is invalid")
		}
		return "*." + base, nil
	}
	if strings.Contains(value, "*") || !validDNSLabels(value) {
		return "", fmt.Errorf("domain is invalid")
	}
	return value, nil
}

func validDNSLabels(value string) bool {
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range label {
			character := label[index]
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !isASCII(value) || hasControl(value) {
		return false
	}
	for index := range value {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validMetadataIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !isASCII(value) || hasControl(value) {
		return false
	}
	for index := range value {
		if value[index] == '/' || value[index] == '\\' || value[index] == ' ' {
			return false
		}
	}
	return true
}

func labelCount(value string) int { return strings.Count(value, ".") + 1 }

func hasControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func isASCII(value string) bool {
	for index := range value {
		if value[index] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func invalid(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidBundle, fmt.Sprintf(format, values...))
}
