package edgeconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestValidateSiteTLSProtocolsAcceptsContiguousRanges(t *testing.T) {
	for _, protocols := range [][]string{
		{"TLSv1.3"}, {"TLSv1.2"}, {"TLSv1.2", "TLSv1.3"}, {"TLSv1.1", "TLSv1.2"},
		{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
	} {
		if err := ValidateSiteTLSProtocols(protocols); err != nil {
			t.Fatalf("%v: %v", protocols, err)
		}
	}
	for _, protocols := range [][]string{
		nil, {}, {"SSLv3"}, {"TLSv1.3", "TLSv1.2"}, {"TLSv1", "TLSv1.2"}, {"TLSv1.2", "TLSv1.2"},
		{"TLSv1.4"}, {"tlsv1.2"},
	} {
		if ValidateSiteTLSProtocols(protocols) == nil {
			t.Fatalf("%v accepted", protocols)
		}
	}
}

func TestTLSProfileValidateCombinations(t *testing.T) {
	ref := "sha256:" + strings.Repeat("a", 64)
	valid := []TLSProfile{
		{},
		{Protocols: []string{"TLSv1.3"}},
		{Protocols: []string{"TLSv1.2", "TLSv1.3"}, CipherPreset: TLSCipherCompatible, OCSPStapling: true},
		{Protocols: []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}, CipherPreset: TLSCipherLegacy},
		{ClientAuth: ClientAuthRequired, ClientCARef: ref},
		{ClientAuth: ClientAuthOptional, ClientCARef: ref},
		{CipherPreset: TLSCipherCustom, CipherSuites: customSuites},
		{CipherPreset: TLSCipherCustom, CipherSuites: customSuites, Protocols: []string{"TLSv1.2"}},
	}
	for _, profile := range valid {
		if err := profile.Validate(); err != nil {
			t.Fatalf("%+v: %v", profile, err)
		}
	}
	invalid := []TLSProfile{
		{Protocols: []string{"TLSv1.1", "TLSv1.2"}}, // legacy versions, modern ciphers
		{CipherPreset: TLSCipherModern, CipherSuites: []string{"ECDHE-RSA-AES128-GCM-SHA256"}},
		{CipherPreset: TLSCipherCustom},
		{CipherPreset: TLSCipherCustom, CipherSuites: customSuites, Protocols: []string{"TLSv1.3"}},
		{CipherPreset: TLSCipherCustom, CipherSuites: customSuites, Protocols: []string{"TLSv1", "TLSv1.1", "TLSv1.2"}},
		{Protocols: []string{"TLSv1", "TLSv1.1", "TLSv1.2"}, CipherPreset: TLSCipherCompatible}, // ditto
		{CipherPreset: "custom"},
		{ClientAuth: ClientAuthRequired},
		{ClientAuth: ClientAuthOff, ClientCARef: ref},
		{ClientCARef: ref},
		{ClientAuth: "maybe", ClientCARef: ref},
		{ClientAuth: ClientAuthOptional, ClientCARef: "sha256:nothex"},
	}
	for _, profile := range invalid {
		if profile.Validate() == nil {
			t.Fatalf("%+v accepted", profile)
		}
	}
}

var customSuites = []string{"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-AES128-SHA"}

func TestValidateTLSCipherSuites(t *testing.T) {
	if len(TLSCustomCipherSuites) != MaxTLSCipherSuites || ValidateTLSCipherSuites(TLSCustomCipherSuites) != nil {
		t.Fatalf("whole whitelist (%d) must be a valid list", len(TLSCustomCipherSuites))
	}
	for _, weak := range []string{"NULL", "EXP", "RC4", "DES", "MD5", "DHE-", "PSK", "SRP", "CCM", "ARIA", "CAMELLIA", "DSS", "ADH"} {
		for _, suite := range TLSCustomCipherSuites {
			if strings.Contains(suite, weak) && !(weak == "DHE-" && strings.HasPrefix(suite, "ECDHE-")) {
				t.Fatalf("whitelist has %s (%s)", suite, weak)
			}
		}
	}
	if err := ValidateTLSCipherSuites(customSuites); err != nil {
		t.Fatal(err)
	}
	for name, suites := range map[string][]string{
		"empty":       {},
		"unknown":     {"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305", "DES-CBC3-SHA"},
		"rc4":         {"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305", "RC4-SHA"},
		"string":      {"ECDHE-RSA-AES256-GCM-SHA384:ALL", "ECDHE-ECDSA-CHACHA20-POLY1305"},
		"keyword":     {"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305", "@SECLEVEL=0"},
		"repeat":      {"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-AES256-GCM-SHA384"},
		"lower case":  {"ecdhe-rsa-aes256-gcm-sha384", "ECDHE-ECDSA-CHACHA20-POLY1305"},
		"no ecdsa":    {"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-SHA"},
		"no rsa aead": {"ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-SHA256", "AES128-GCM-SHA256"},
		"cbc only":    {"ECDHE-ECDSA-AES128-SHA", "ECDHE-RSA-AES128-SHA"},
		"too many":    append(slices.Clone(TLSCustomCipherSuites), "ECDHE-RSA-AES128-GCM-SHA256"),
	} {
		if ValidateTLSCipherSuites(suites) == nil {
			t.Fatalf("%s accepted: %v", name, suites)
		}
	}
	got := TLSProfileDirectives(TLSProfile{CipherPreset: TLSCipherCustom, CipherSuites: customSuites}, "/r")
	if !strings.Contains(got, "    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA;\n") ||
		!strings.Contains(got, "ssl_prefer_server_ciphers on;") {
		t.Fatalf("custom directives:\n%s", got)
	}
	if (TLSProfile{CipherPreset: TLSCipherCustom, CipherSuites: customSuites}).Baseline() {
		t.Fatal("custom preset is not the baseline")
	}
}

func TestTLSProfileDirectives(t *testing.T) {
	ref := "sha256:" + strings.Repeat("b", 64)
	got := TLSProfileDirectives(TLSProfile{Protocols: []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
		CipherPreset: TLSCipherLegacy, OCSPStapling: true, ClientAuth: ClientAuthOptional, ClientCARef: ref}, "/var/lib/release/")
	for _, want := range []string{
		"    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\n",
		"    ssl_ciphers DEFAULT:@SECLEVEL=0;\n",
		"    ssl_prefer_server_ciphers on;\n",
		"    ssl_stapling on;\n    ssl_stapling_verify on;\n",
		"    ssl_client_certificate /var/lib/release/client-ca/" + strings.Repeat("b", 64) + ".pem;\n",
		"    ssl_verify_client optional;\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	baseline := TLSProfileDirectives(TLSProfile{}, "/r")
	if strings.Contains(baseline, "ssl_protocols") || !strings.Contains(baseline, "ssl_ciphers "+modernCipherList+";") ||
		!strings.Contains(baseline, "ssl_prefer_server_ciphers off;") || strings.Contains(baseline, "stapling") ||
		strings.Contains(baseline, "verify_client") {
		t.Fatalf("baseline directives:\n%s", baseline)
	}
	required := TLSProfileDirectives(TLSProfile{ClientAuth: ClientAuthRequired, ClientCARef: ref}, "/r")
	if !strings.Contains(required, "ssl_verify_client on;") {
		t.Fatalf("required directives:\n%s", required)
	}
	if !strings.Contains(TLSClientAuthLocation(TLSProfile{}), "proxy_set_header X-Client-Verify \"\";") ||
		!strings.Contains(TLSClientAuthLocation(TLSProfile{ClientAuth: ClientAuthRequired, ClientCARef: ref}), "X-Client-Verify $ssl_client_verify") {
		t.Fatal("client auth location headers")
	}
}

func TestValidateClientCABundle(t *testing.T) {
	ca := testCertificatePEM(t, true)
	if err := ValidateClientCABundle(ca); err != nil {
		t.Fatal(err)
	}
	if err := ValidateClientCABundle(append(append([]byte{}, ca...), ca...)); err != nil {
		t.Fatal(err)
	}
	for name, bundle := range map[string][]byte{
		"empty":   nil,
		"leaf":    testCertificatePEM(t, false),
		"key":     []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
		"garbage": append(append([]byte{}, ca...), []byte("trailing")...),
	} {
		if ValidateClientCABundle(bundle) == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if ref := ClientCARefFor(ca); !strings.HasPrefix(ref, "sha256:") || ClientCAPath(ref) != "client-ca/"+ref[7:]+".pem" {
		t.Fatalf("ref %s path %s", ref, ClientCAPath(ref))
	}
}

func testCertificatePEM(t *testing.T, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: isCA}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
