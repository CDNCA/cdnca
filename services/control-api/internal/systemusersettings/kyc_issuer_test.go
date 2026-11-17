package systemusersettings

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// kycIssuerTestPEM is a CA, a server certificate it signed (chain: leaf then
// CA) with its private key, and a client CA.
type kycIssuerTestPEM struct {
	serverChain, serverKey, clientCA, caAsLeaf, otherKey string
	notAfter                                             time.Time
}

func newKYCIssuerTestPEM(t *testing.T, now time.Time) kycIssuerTestPEM {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		value, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	certificate := func(template, parent *x509.Certificate, public, signer any) (*x509.Certificate, string) {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := x509.ParseCertificate(der)
		return parsed, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	keyPEM := func(value *ecdsa.PrivateKey) string {
		der, err := x509.MarshalPKCS8PrivateKey(value)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	}
	notAfter := now.Add(30 * 24 * time.Hour)
	caKey, serverKey, clientCAKey := key(), key(), key()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "issuer ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	ca, caPEM := certificate(caTemplate, caTemplate, &caKey.PublicKey, caKey)
	_, serverPEM := certificate(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "issuer"},
		DNSNames: []string{"issuer.cdnca.local"}, NotBefore: now.Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		ca, &serverKey.PublicKey, caKey)
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "workload ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	_, clientPEM := certificate(clientTemplate, clientTemplate, &clientCAKey.PublicKey, clientCAKey)
	return kycIssuerTestPEM{serverChain: strings.TrimSpace(serverPEM + caPEM), serverKey: keyPEM(serverKey),
		clientCA: strings.TrimSpace(clientPEM), caAsLeaf: strings.TrimSpace(caPEM), otherKey: keyPEM(key()), notAfter: notAfter}
}

func kycIssuerCompleteSettings(material kycIssuerTestPEM) Settings {
	value := DefaultSettings()
	value.KYCIssuerEnabled, value.KYCIssuerListenAddress = true, "0.0.0.0:19443"
	value.KYCIssuerServerCertificate, value.KYCIssuerClientCA = material.serverChain, material.clientCA
	value.KYCIssuerWorkloadIdentities = "spiffe://control.cdnca.local/workload/kyc/issuer-a|issuer-a,spiffe://control.cdnca.local/workload/kyc/issuer-b|issuer-b"
	value.KYCIssuerKMSEndpoint = "https://kms.example.com"
	return value
}

// The evidence issuer fields of the page are checked on
// save in the form the issuer runtime accepts; an empty value means "not set
// on the page" (the runtime then uses IDENTITY_VERIFICATION_ISSUER_*).
func TestSettingsFieldErrorKYCIssuerFields(t *testing.T) {
	material := newKYCIssuerTestPEM(t, time.Now())
	for name, tc := range map[string]struct {
		set    func(*Settings)
		field  string
		reason string
	}{
		"all empty":         {set: func(value *Settings) { *value = DefaultSettings() }},
		"complete":          {set: func(*Settings) {}},
		"loopback http kms": {set: func(value *Settings) { value.KYCIssuerKMSEndpoint = "http://127.0.0.1:4566" }},
		"listen no port":    {set: func(value *Settings) { value.KYCIssuerListenAddress = "0.0.0.0" }, field: "value.kyc_issuer_listen_address", reason: fielderr.InvalidFormat},
		"listen port 0":     {set: func(value *Settings) { value.KYCIssuerListenAddress = "0.0.0.0:0" }, field: "value.kyc_issuer_listen_address", reason: fielderr.InvalidFormat},
		"listen no host":    {set: func(value *Settings) { value.KYCIssuerListenAddress = ":19443" }, field: "value.kyc_issuer_listen_address", reason: fielderr.InvalidFormat},
		"listen space":      {set: func(value *Settings) { value.KYCIssuerListenAddress = " 0.0.0.0:19443" }, field: "value.kyc_issuer_listen_address", reason: fielderr.InvalidFormat},
		"cert garbage":      {set: func(value *Settings) { value.KYCIssuerServerCertificate = "not a certificate" }, field: "value.kyc_issuer_server_certificate", reason: fielderr.InvalidFormat},
		"cert is ca":        {set: func(value *Settings) { value.KYCIssuerServerCertificate = material.caAsLeaf }, field: "value.kyc_issuer_server_certificate", reason: fielderr.Invalid},
		"cert holds key":    {set: func(value *Settings) { value.KYCIssuerServerCertificate += "\n" + material.serverKey }, field: "value.kyc_issuer_server_certificate", reason: fielderr.InvalidFormat},
		"cert broken chain": {set: func(value *Settings) { value.KYCIssuerServerCertificate += "\n" + material.clientCA }, field: "value.kyc_issuer_server_certificate", reason: fielderr.Invalid},
		"client ca not ca": {set: func(value *Settings) {
			value.KYCIssuerClientCA = strings.SplitAfter(material.serverChain, "-----END CERTIFICATE-----")[0]
		}, field: "value.kyc_issuer_client_ca", reason: fielderr.Invalid},
		"client ca garbage": {set: func(value *Settings) { value.KYCIssuerClientCA = "-----BEGIN CERTIFICATE-----" }, field: "value.kyc_issuer_client_ca", reason: fielderr.InvalidFormat},
		"identity no id": {set: func(value *Settings) {
			value.KYCIssuerWorkloadIdentities = "spiffe://control.cdnca.local/workload/kyc/issuer-a"
		}, field: "value.kyc_issuer_workload_identities", reason: fielderr.InvalidFormat},
		"identity not spiffe": {set: func(value *Settings) { value.KYCIssuerWorkloadIdentities = "https://control.cdnca.local/kyc|issuer-a" }, field: "value.kyc_issuer_workload_identities", reason: fielderr.InvalidFormat},
		"identity duplicate": {set: func(value *Settings) {
			value.KYCIssuerWorkloadIdentities = "spiffe://a.local/w|one,spiffe://a.local/w|two"
		}, field: "value.kyc_issuer_workload_identities", reason: fielderr.InvalidFormat},
		"identity trailing": {set: func(value *Settings) { value.KYCIssuerWorkloadIdentities = "spiffe://a.local/w|one," }, field: "value.kyc_issuer_workload_identities", reason: fielderr.InvalidFormat},
		"kms http remote":   {set: func(value *Settings) { value.KYCIssuerKMSEndpoint = "http://kms.example.com" }, field: "value.kyc_issuer_kms_endpoint", reason: fielderr.InvalidFormat},
		"kms path":          {set: func(value *Settings) { value.KYCIssuerKMSEndpoint = "https://kms.example.com/v1" }, field: "value.kyc_issuer_kms_endpoint", reason: fielderr.InvalidFormat},
	} {
		value := kycIssuerCompleteSettings(material)
		tc.set(&value)
		err := settingsFieldError(value)
		located, ok := fielderr.As(err)
		switch {
		case tc.field == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.field != "" && (!errors.Is(err, ErrInvalidInput) || !ok || located.Field != tc.field || located.Reason != tc.reason):
			t.Errorf("%s: %v, want %s %s", name, err, tc.field, tc.reason)
		}
	}
}

// The server private key is a write-only page secret in PEM (line breaks
// allowed for it alone); other secrets still refuse line breaks.
func TestSecretsFieldErrorKYCIssuerPrivateKey(t *testing.T) {
	material := newKYCIssuerTestPEM(t, time.Now())
	text := func(value string) *string { return &value }
	for name, tc := range map[string]struct {
		name, secret, reason string
	}{
		"pem key":          {name: SecretKYCIssuerServerPrivateKey, secret: material.serverKey},
		"garbage":          {name: SecretKYCIssuerServerPrivateKey, secret: "not-a-private-key", reason: fielderr.InvalidFormat},
		"certificate":      {name: SecretKYCIssuerServerPrivateKey, secret: material.caAsLeaf, reason: fielderr.InvalidFormat},
		"crlf":             {name: SecretKYCIssuerServerPrivateKey, secret: strings.ReplaceAll(material.serverKey, "\n", "\r\n"), reason: fielderr.InvalidFormat},
		"two keys":         {name: SecretKYCIssuerServerPrivateKey, secret: material.serverKey + "\n" + material.otherKey, reason: fielderr.InvalidFormat},
		"too long":         {name: SecretKYCIssuerServerPrivateKey, secret: strings.Repeat("k", 8193), reason: fielderr.TooLong},
		"api key newline":  {name: SecretKYCAPIKey, secret: "page-kyc-api-key\n0001", reason: fielderr.InvalidFormat},
		"turnstile spaces": {name: SecretCaptchaTurnstileSecret, secret: "turnstile secret 0001", reason: fielderr.InvalidFormat},
	} {
		err := secretsFieldError(DefaultSettings(), map[string]*string{tc.name: text(tc.secret)}, nil)
		located, ok := fielderr.As(err)
		switch {
		case tc.reason == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.reason != "" && (!ok || located.Field != tc.name || located.Reason != tc.reason):
			t.Errorf("%s: %v, want %s %s", name, err, tc.name, tc.reason)
		}
	}
}

// On save (not on read, so a stored certificate that later expires keeps
// the page readable): the certificates must be valid now (the server one for
// at least an hour more), and a key sent with a page certificate must match it.
func TestKYCIssuerSaveError(t *testing.T) {
	now := time.Now()
	material := newKYCIssuerTestPEM(t, now)
	text := func(value string) *string { return &value }
	for name, tc := range map[string]struct {
		at      time.Time
		secrets map[string]*string
		field   string
	}{
		"valid":             {at: now},
		"valid with key":    {at: now, secrets: map[string]*string{SecretKYCIssuerServerPrivateKey: text(material.serverKey)}},
		"key mismatch":      {at: now, secrets: map[string]*string{SecretKYCIssuerServerPrivateKey: text(material.otherKey)}, field: "kyc_issuer_server_private_key"},
		"server expiring":   {at: material.notAfter.Add(-30 * time.Minute), field: "value.kyc_issuer_server_certificate"},
		"not yet valid":     {at: now.Add(-2 * time.Hour), field: "value.kyc_issuer_server_certificate"},
		"client ca expired": {at: material.notAfter.Add(time.Minute), field: "value.kyc_issuer_server_certificate"},
	} {
		err := kycIssuerSaveError(kycIssuerCompleteSettings(material), tc.secrets, tc.at)
		located, ok := fielderr.As(err)
		switch {
		case tc.field == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.field != "" && (!errors.Is(err, ErrInvalidInput) || !ok || located.Field != tc.field || located.Reason != fielderr.Invalid):
			t.Errorf("%s: %v, want %s invalid", name, err, tc.field)
		}
	}
	value := kycIssuerCompleteSettings(material)
	value.KYCIssuerServerCertificate = ""
	if err := kycIssuerSaveError(value, nil, material.notAfter.Add(time.Minute)); err == nil {
		t.Fatal("expired client CA accepted")
	} else if located, _ := fielderr.As(err); located.Field != "value.kyc_issuer_client_ca" {
		t.Fatalf("expired client CA: %v", err)
	}
}

// Reads return only whether the server private key is set and its
// fingerprint; the certificates are public and returned as saved.
func TestDocumentKYCIssuerPrivateKeyIsWriteOnly(t *testing.T) {
	material := newKYCIssuerTestPEM(t, time.Now())
	document := Document{Value: kycIssuerCompleteSettings(material)}
	document.setSecrets(secretFingerprints(map[string]string{SecretKYCIssuerServerPrivateKey: material.serverKey}))
	if !document.KYCIssuerServerPrivateKeyConfigured || len(document.KYCIssuerServerPrivateKeyFingerprint) != 16 {
		t.Fatalf("document=%+v", document)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PRIVATE KEY") || !strings.Contains(string(encoded), `"kyc_issuer_server_private_key_configured":true`) {
		t.Fatalf("document = %s", encoded)
	}
}

// The runtime view carries the issuer page values and the opened key.
func TestKYCIssuerRuntimeFromPage(t *testing.T) {
	material := newKYCIssuerTestPEM(t, time.Now())
	var runtime IdentityVerificationRuntime
	setKYCProviderRuntime(&runtime, kycIssuerCompleteSettings(material), map[string]string{SecretKYCIssuerServerPrivateKey: material.serverKey})
	if !runtime.IssuerEnabled || runtime.IssuerListenAddress != "0.0.0.0:19443" || runtime.IssuerServerCertificate != material.serverChain ||
		runtime.IssuerClientCA != material.clientCA || !strings.HasPrefix(runtime.IssuerWorkloadIdentities, "spiffe://") ||
		runtime.IssuerKMSEndpoint != "https://kms.example.com" || string(runtime.IssuerServerPrivateKey) != material.serverKey {
		t.Fatalf("runtime=%+v", runtime)
	}
	runtime.Clear()
	if strings.Trim(string(runtime.IssuerServerPrivateKey), "\x00") != "" {
		t.Fatal("Clear left the issuer private key")
	}
}
