package edgeconfig

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Site TLS profile: per-site TLS versions, a cipher preset,
// OCSP stapling and client certificate verification. A listener that names
// none of them keeps the platform baseline (TLSv1.2 TLSv1.3, nginx's
// default ciphers, no stapling, no client certificates), which is also the
// lazy certificate default server's profile.
//
// nginx applies protocols, ciphers and client verification from the server
// that SNI selects (SSL_set_SSL_CTX copies the options and the verify mode,
// measured on OpenResty 1.31.1.1 with a TLSv1.3-only and a TLSv1.0 site on
// one port), so sites with different profiles share a port. OCSP stapling
// and client CAs need the site's own SSL_CTX: such a listener never takes
// the lazy (variable certificate) path.

// The fields are part of the 1.0.35 site runtime v2 document (the
// compatibility baseline): no capability version gates them.

// TLS protocol names, oldest first. SSLv2/SSLv3 are never accepted.
var siteTLSProtocolOrder = []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}

// BaselineTLSProtocols is the platform baseline protocol set.
func BaselineTLSProtocols() []string { return []string{"TLSv1.2", "TLSv1.3"} }

// Cipher presets. The TLS 1.3 suites are OpenSSL's defaults in every preset
// (ssl_ciphers only sets TLS 1.2 and older). A document writes "" for
// modern, the default.
const (
	// TLSCipherModern: forward-secret AEAD suites only (the platform
	// "recommended" setting).
	TLSCipherModern = "modern"
	// TLSCipherCompatible adds CBC and static RSA suites for old TLS 1.2
	// clients ("legacy_tls12").
	TLSCipherCompatible = "compatible"
	// TLSCipherLegacy is OpenSSL's whole default list at security level 0,
	// needed for TLSv1/TLSv1.1 clients ("legacy_full").
	TLSCipherLegacy = "legacy"
	// TLSCipherCustom is the site's own ordered list of
	// TLS 1.2 suites (TLSProfile.CipherSuites), every one from
	// TLSCustomCipherSuites. Needs SITE_TLS_CUSTOM_CIPHERS on the node.
	TLSCipherCustom = "custom"
)

const (
	modernCipherList     = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
	compatibleCipherList = modernCipherList + ":ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"
	legacyCipherList     = "DEFAULT:@SECLEVEL=0"
)

// SiteTLSCustomCiphersCapability is the site object capability name of
// CAPABILITY_NAME_SITE_TLS_CUSTOM_CIPHERS: a listener with
// the custom cipher preset.
const (
	SiteTLSCustomCiphersCapability        = "site_tls_custom_ciphers"
	SiteTLSCustomCiphersAPIVersion uint32 = 1
)

// TLSCustomCipherSuites is the whitelist of the custom preset: OpenSSL 3.5
// names of TLS 1.2 suites with ECDHE or RSA key exchange, RSA/ECDSA
// certificates and AES-GCM, ChaCha20-Poly1305 or AES-CBC (the compatible
// preset's list, in its order). Left out: NULL, EXPORT, RC4, DES/3DES, MD5,
// anonymous, PSK/SRP, DSS, and also DHE (nginx without ssl_dhparam never
// negotiates it), CCM/CCM8, ARIA and Camellia (no mainstream client
// offers them only). TLS 1.3 suites stay OpenSSL's default.
var TLSCustomCipherSuites = strings.Split(compatibleCipherList, ":")

// MaxTLSCipherSuites bounds a custom list (no repeats, so the whitelist size).
const MaxTLSCipherSuites = 20

// TLSCipherList is the ssl_ciphers value of a preset ("" is modern; an
// unknown preset is ""). The custom preset's list is the site's own
// (TLSProfile.CipherList).
func TLSCipherList(preset string) string {
	switch preset {
	case "", TLSCipherModern:
		return modernCipherList
	case TLSCipherCompatible:
		return compatibleCipherList
	case TLSCipherLegacy:
		return legacyCipherList
	default:
		return ""
	}
}

// ValidateTLSCipherSuites checks a custom list: 1..MaxTLSCipherSuites
// whitelisted names without repeats, among them an ECDHE-ECDSA and an
// ECDHE-RSA AEAD suite. That keeps a forward-secret AEAD TLS 1.2 handshake
// for either certificate type (an ACME renewal may change the key type),
// so a list can never leave the site with only CBC or static RSA suites,
// or with none at all for its certificate.
func ValidateTLSCipherSuites(suites []string) error {
	if len(suites) == 0 || len(suites) > MaxTLSCipherSuites {
		return fmt.Errorf("%w: custom TLS cipher suites need 1..%d names", ErrInvalidConfig, MaxTLSCipherSuites)
	}
	var ecdsaAEAD, rsaAEAD bool
	for index, suite := range suites {
		if !slices.Contains(TLSCustomCipherSuites, suite) || slices.Contains(suites[:index], suite) {
			return fmt.Errorf("%w: TLS cipher suite %q", ErrInvalidConfig, suite)
		}
		aead := strings.Contains(suite, "-GCM-") || strings.Contains(suite, "CHACHA20-POLY1305")
		ecdsaAEAD = ecdsaAEAD || aead && strings.HasPrefix(suite, "ECDHE-ECDSA-")
		rsaAEAD = rsaAEAD || aead && strings.HasPrefix(suite, "ECDHE-RSA-")
	}
	if !ecdsaAEAD || !rsaAEAD {
		return fmt.Errorf("%w: custom TLS cipher suites need an ECDHE-ECDSA and an ECDHE-RSA AEAD suite", ErrInvalidConfig)
	}
	return nil
}

// Client certificate verification.
const (
	ClientAuthOff      = "off"
	ClientAuthOptional = "optional"
	ClientAuthRequired = "required"
)

// ClientCAPrefix is where a release carries client CA bundles:
// client-ca/<sha256>.pem, referenced by ClientCARef "sha256:<hex>".
const ClientCAPrefix = "client-ca/"

// MaxClientCABytes bounds one client CA bundle.
const MaxClientCABytes = 256 << 10

var clientCARefPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// TLSProfile is the TLS settings of one listener beyond its certificate.
// The zero value is the baseline.
type TLSProfile struct {
	// Protocols nil is the baseline.
	Protocols []string
	// CipherPreset "" is modern.
	CipherPreset string
	// CipherSuites is the custom preset's ordered list (nil otherwise).
	CipherSuites []string
	OCSPStapling bool
	// ClientAuth "" is off; ClientCARef is required with optional/required.
	ClientAuth  string
	ClientCARef string
	// PreferServerCiphers nil follows the preset (PresetPrefersServerCiphers);
	// a document writes it only when it differs
	// (SITE_TLS_OPTIONS).
	PreferServerCiphers *bool
}

// SiteTLSOptionsCapability is the site object capability name of
// CAPABILITY_NAME_SITE_TLS_OPTIONS: per site HTTP/2 off on
// a shared HTTPS port (native patch 27) and an explicit
// ssl_prefer_server_ciphers.
const (
	SiteTLSOptionsCapability        = "site_tls_options"
	SiteTLSOptionsAPIVersion uint32 = 1
)

// PresetPrefersServerCiphers is ssl_prefer_server_ciphers of a cipher
// preset: off for modern (only strong suites, the client's order is fine),
// on for the wider lists (a client must not pick a weak suite first) and
// for custom (the site's order is the point of the list).
func PresetPrefersServerCiphers(preset string) bool {
	return preset == TLSCipherCompatible || preset == TLSCipherLegacy || preset == TLSCipherCustom
}

// CipherList is the profile's ssl_ciphers value.
func (profile TLSProfile) CipherList() string {
	if profile.CipherPreset == TLSCipherCustom {
		return strings.Join(profile.CipherSuites, ":")
	}
	return TLSCipherList(profile.CipherPreset)
}

// Baseline reports whether the profile is the platform baseline (the lazy
// certificate default server's).
func (profile TLSProfile) Baseline() bool {
	return (profile.Protocols == nil || slices.Equal(profile.Protocols, BaselineTLSProtocols())) &&
		(profile.CipherPreset == "" || profile.CipherPreset == TLSCipherModern) && !profile.OCSPStapling &&
		(profile.ClientAuth == "" || profile.ClientAuth == ClientAuthOff) && profile.ClientCARef == "" &&
		profile.PreferServerCiphers == nil
}

// Validate checks a listener's TLS profile.
func (profile TLSProfile) Validate() error {
	if profile.Protocols != nil {
		if err := ValidateSiteTLSProtocols(profile.Protocols); err != nil {
			return err
		}
	}
	protocols := profile.Protocols
	if protocols == nil {
		protocols = BaselineTLSProtocols()
	}
	switch profile.CipherPreset {
	case "", TLSCipherModern, TLSCipherCompatible, TLSCipherLegacy:
		if profile.CipherSuites != nil {
			return fmt.Errorf("%w: TLS cipher suites without the custom preset", ErrInvalidConfig)
		}
	case TLSCipherCustom:
		if err := ValidateTLSCipherSuites(profile.CipherSuites); err != nil {
			return err
		}
		// The list is TLS 1.2 suites only: a TLSv1.3-only site would never
		// use it (TLS 1.3 suites are OpenSSL's default).
		if !slices.Contains(protocols, "TLSv1.2") {
			return fmt.Errorf("%w: custom TLS 1.2 cipher suites need TLSv1.2", ErrInvalidConfig)
		}
	default:
		return fmt.Errorf("%w: TLS cipher preset %q", ErrInvalidConfig, profile.CipherPreset)
	}
	// TLSv1/TLSv1.1 handshakes need the SHA-1 CBC suites only the legacy list
	// keeps (and security level 0 for their SHA-1 signatures).
	if (slices.Contains(protocols, "TLSv1") || slices.Contains(protocols, "TLSv1.1")) && profile.CipherPreset != TLSCipherLegacy {
		return fmt.Errorf("%w: TLSv1/TLSv1.1 need the legacy cipher preset", ErrInvalidConfig)
	}
	// Canonical form: an explicit value only where it differs from the preset.
	if profile.PreferServerCiphers != nil && *profile.PreferServerCiphers == PresetPrefersServerCiphers(profile.CipherPreset) {
		return fmt.Errorf("%w: prefer_server_ciphers equal to the preset's", ErrInvalidConfig)
	}
	switch profile.ClientAuth {
	case "", ClientAuthOff:
		if profile.ClientCARef != "" {
			return fmt.Errorf("%w: client CA without client verification", ErrInvalidConfig)
		}
	case ClientAuthOptional, ClientAuthRequired:
		if !clientCARefPattern.MatchString(profile.ClientCARef) {
			return fmt.Errorf("%w: client verification needs a client CA", ErrInvalidConfig)
		}
	default:
		return fmt.Errorf("%w: client auth %q", ErrInvalidConfig, profile.ClientAuth)
	}
	return nil
}

// ValidateSiteTLSProtocols requires a non-empty, ascending, contiguous range
// of TLSv1..TLSv1.3 (a gap would let a client negotiate around the missing
// version anyway: OpenSSL treats the set as a min/max range).
func ValidateSiteTLSProtocols(protocols []string) error {
	if len(protocols) == 0 {
		return fmt.Errorf("%w: TLS protocols empty", ErrInvalidConfig)
	}
	first := slices.Index(siteTLSProtocolOrder, protocols[0])
	if first < 0 {
		return fmt.Errorf("%w: TLS protocol %q", ErrInvalidConfig, protocols[0])
	}
	for index, protocol := range protocols {
		if first+index >= len(siteTLSProtocolOrder) || siteTLSProtocolOrder[first+index] != protocol {
			return fmt.Errorf("%w: TLS protocols must be an ascending contiguous range", ErrInvalidConfig)
		}
	}
	return nil
}

// ClientCARefFor is the reference of a client CA bundle.
func ClientCARefFor(bundle []byte) string {
	sum := sha256.Sum256(bundle)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ClientCAPath is a client CA bundle's release path.
func ClientCAPath(ref string) string {
	return ClientCAPrefix + strings.TrimPrefix(ref, "sha256:") + ".pem"
}

// ValidateClientCABundle requires one or more PEM CA certificates and
// nothing else.
func ValidateClientCABundle(bundle []byte) error {
	if len(bundle) == 0 || len(bundle) > MaxClientCABytes {
		return fmt.Errorf("%w: client CA bundle size", ErrInvalidConfig)
	}
	rest, count := bundle, 0
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return fmt.Errorf("%w: client CA bundle has non-PEM data", ErrInvalidConfig)
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("%w: client CA bundle block %q", ErrInvalidConfig, block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid {
			return fmt.Errorf("%w: client CA bundle certificate is not a CA", ErrInvalidConfig)
		}
		count++
		rest = remaining
	}
	if count == 0 || count > 64 {
		return fmt.Errorf("%w: client CA bundle needs 1..64 certificates", ErrInvalidConfig)
	}
	return nil
}

// TLSProfileDirectives is the server-level nginx text of a profile for a
// server that has its own certificate. Nil protocols write none (nginx's
// default is the baseline).
func TLSProfileDirectives(profile TLSProfile, releasePath string) string {
	var output strings.Builder
	if profile.Protocols != nil {
		fmt.Fprintf(&output, "    ssl_protocols %s;\n", strings.Join(profile.Protocols, " "))
	}
	fmt.Fprintf(&output, "    ssl_ciphers %s;\n", profile.CipherList())
	prefer := PresetPrefersServerCiphers(profile.CipherPreset)
	if profile.PreferServerCiphers != nil {
		prefer = *profile.PreferServerCiphers
	}
	if prefer {
		output.WriteString("    ssl_prefer_server_ciphers on;\n")
	} else {
		output.WriteString("    ssl_prefer_server_ciphers off;\n")
	}
	if profile.OCSPStapling {
		// The responder answer is verified against the certificate's issuer
		// (the chain the certificate file carries) before it is stapled.
		output.WriteString("    ssl_stapling on;\n    ssl_stapling_verify on;\n")
	}
	switch profile.ClientAuth {
	case ClientAuthOptional, ClientAuthRequired:
		mode := "on"
		if profile.ClientAuth == ClientAuthOptional {
			mode = "optional"
		}
		fmt.Fprintf(&output, "    ssl_client_certificate %s;\n    ssl_verify_client %s;\n    ssl_verify_depth 3;\n",
			strings.TrimSuffix(releasePath, "/")+"/"+ClientCAPath(profile.ClientCARef), mode)
	}
	return output.String()
}

// TLSClientAuthLocation is the location-level nginx text that hands the
// verification result to the origin. Optional verification never rejects;
// required has already rejected a missing or invalid certificate in the
// handshake (nginx answers 400). The client's own header values are
// replaced, never passed through: a site without client authentication
// sets them empty, and nginx then sends no header (a forged
// "X-Client-Verify: SUCCESS" must not reach the origin; the dynamic
// routing cdnca_tls.lua clears them the same way).
func TLSClientAuthLocation(profile TLSProfile) string {
	if profile.ClientAuth != ClientAuthOptional && profile.ClientAuth != ClientAuthRequired {
		return "      proxy_set_header X-Client-Verify \"\";\n" +
			"      proxy_set_header X-Client-Cert-Fingerprint \"\";\n" +
			"      proxy_set_header X-Client-Cert-Subject \"\";\n"
	}
	return "      proxy_set_header X-Client-Verify $ssl_client_verify;\n" +
		"      proxy_set_header X-Client-Cert-Fingerprint $ssl_client_fingerprint;\n" +
		"      proxy_set_header X-Client-Cert-Subject $ssl_client_s_dn;\n"
}
