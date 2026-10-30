package certstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

type certificateMaterial struct {
	chainPEM   string
	privatePEM string
	leaf       *x509.Certificate
	root       *x509.Certificate
}

func TestCompileCanonicalizesBindingsAndSingleLabelWildcard(t *testing.T) {
	exact := issueTestMaterial(t, []string{"a.example.test"}, testNow.Add(-time.Hour), testNow.Add(time.Hour), nil)
	wildcard := issueTestMaterial(t, []string{"*.wild.example.test"}, testNow.Add(-time.Hour), testNow.Add(time.Hour), nil)
	bundle := Bundle{
		SchemaVersion: SchemaVersion, VersionID: "cert-v1",
		Bindings: []Binding{
			{SiteID: "site-z", Domains: []string{"*.wild.example.test"}, CertificateChainPEM: wildcard.chainPEM, PrivateKeyPEM: wildcard.privatePEM},
			{SiteID: "site-a", Domains: []string{"a.example.test"}, CertificateChainPEM: exact.chainPEM, PrivateKeyPEM: exact.privatePEM},
		},
	}
	config := RuntimeConfig{StateRoot: filepath.Join(t.TempDir(), "certificates"), ListenAddress: "127.0.0.1", ListenPort: 18443}
	first, err := Compile(bundle, config, testNow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(bundle, config, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || first.Manifest.Bindings[0].SiteID != "site-a" {
		t.Fatalf("compile is not deterministic: first=%#v second=%#v", first.Manifest, second.Manifest)
	}
	nginx := artifactContent(t, first, "nginx.conf")
	if !bytes.Contains(nginx, []byte(`~^[^.]+\.wild\.example\.test$`)) || bytes.Contains(nginx, []byte(`.*\.wild`)) {
		t.Fatalf("wildcard server_name is not single-label bounded:\n%s", nginx)
	}
	for _, directory := range []string{
		clientBodyTempDirectory, proxyTempDirectory, fastCGITempDirectory, uWSGITempDirectory, scgiTempDirectory,
	} {
		if !bytes.Contains(nginx, []byte(filepath.Join(config.StateRoot, "shared", directory))) {
			t.Fatalf("nginx temporary path %q is not outside the immutable release:\n%s", directory, nginx)
		}
	}
	manifest := artifactContent(t, first, "manifest.json")
	if bytes.Contains(manifest, []byte("PRIVATE KEY")) || bytes.Contains(nginx, []byte("PRIVATE KEY")) {
		t.Fatal("private key escaped into metadata or nginx config")
	}
}

func TestCompileRejectsInvalidCertificatesKeysAndBindings(t *testing.T) {
	valid := issueTestMaterial(t, []string{"valid.example.test", "*.wild.example.test", "*.example.test"}, testNow.Add(-time.Hour), testNow.Add(time.Hour), nil)
	other := issueTestMaterial(t, []string{"valid.example.test"}, testNow.Add(-time.Hour), testNow.Add(time.Hour), nil)
	expired := issueTestMaterial(t, []string{"valid.example.test"}, testNow.Add(-2*time.Hour), testNow.Add(-time.Hour), nil)
	weak := issueWeakRSAMaterial(t, "valid.example.test")
	weakSignature := issueWeakSignatureMaterial(t, "valid.example.test")
	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", []byte("secret"), []byte("password"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	base := Bundle{SchemaVersion: SchemaVersion, VersionID: "v1", Bindings: []Binding{{
		SiteID: "site", Domains: []string{"valid.example.test"}, CertificateChainPEM: valid.chainPEM, PrivateKeyPEM: valid.privatePEM,
	}}}
	tests := []struct {
		name   string
		change func(*Bundle)
	}{
		{name: "key mismatch", change: func(value *Bundle) { value.Bindings[0].PrivateKeyPEM = other.privatePEM }},
		{name: "expired", change: func(value *Bundle) {
			value.Bindings[0].CertificateChainPEM, value.Bindings[0].PrivateKeyPEM = expired.chainPEM, expired.privatePEM
		}},
		{name: "weak RSA", change: func(value *Bundle) {
			value.Bindings[0].CertificateChainPEM, value.Bindings[0].PrivateKeyPEM = weak.chainPEM, weak.privatePEM
		}},
		{name: "weak signature", change: func(value *Bundle) {
			value.Bindings[0].CertificateChainPEM, value.Bindings[0].PrivateKeyPEM = weakSignature.chainPEM, weakSignature.privatePEM
		}},
		{name: "encrypted key", change: func(value *Bundle) { value.Bindings[0].PrivateKeyPEM = string(pem.EncodeToMemory(encryptedBlock)) }},
		{name: "extra key PEM", change: func(value *Bundle) { value.Bindings[0].PrivateKeyPEM += valid.privatePEM }},
		{name: "extra certificate garbage", change: func(value *Bundle) { value.Bindings[0].CertificateChainPEM += "garbage" }},
		{name: "missing SAN", change: func(value *Bundle) { value.Bindings[0].Domains = []string{"missing.other.test"} }},
		{name: "wildcard needs wildcard SAN", change: func(value *Bundle) { value.Bindings[0].Domains = []string{"*.missing.example.test"} }},
		{name: "control character", change: func(value *Bundle) { value.Bindings[0].SiteID = "site\nsecret" }},
		{name: "path traversal ID", change: func(value *Bundle) { value.VersionID = "../v2" }},
		{name: "duplicate site", change: func(value *Bundle) { value.Bindings = append(value.Bindings, value.Bindings[0]) }},
		{name: "duplicate SNI", change: func(value *Bundle) {
			value.Bindings = append(value.Bindings, Binding{SiteID: "other", Domains: []string{"valid.example.test"}, CertificateChainPEM: valid.chainPEM, PrivateKeyPEM: valid.privatePEM})
		}},
		{name: "exact wildcard conflict", change: func(value *Bundle) {
			value.Bindings = append(value.Bindings, Binding{SiteID: "wild", Domains: []string{"*.example.test"}, CertificateChainPEM: valid.chainPEM, PrivateKeyPEM: valid.privatePEM})
		}},
	}
	config := RuntimeConfig{StateRoot: filepath.Join(t.TempDir(), "state"), ListenAddress: "127.0.0.1", ListenPort: 18443}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneBundle(t, base)
			test.change(&candidate)
			if _, err := Compile(candidate, config, testNow); !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("Compile() error = %v, want ErrInvalidBundle", err)
			}
		})
	}
}

func TestCompileJSONRejectsUnknownDuplicateAndOversizedInput(t *testing.T) {
	config := RuntimeConfig{StateRoot: filepath.Join(t.TempDir(), "state"), ListenAddress: "127.0.0.1", ListenPort: 18443}
	for name, raw := range map[string][]byte{
		"unknown":   []byte(`{"schema_version":"cdnca.edge.certificates/v1","version_id":"v1","bindings":[],"unknown":true}`),
		"duplicate": []byte(`{"schema_version":"cdnca.edge.certificates/v1","version_id":"v1","version_id":"v2","bindings":[]}`),
		"multiple":  []byte(`{} {}`),
		"oversized": bytes.Repeat([]byte(" "), MaxBundleBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileJSON(raw, config, testNow); !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("CompileJSON() error = %v", err)
			}
		})
	}
}

func TestWildcardConflictsOnlyWithOneLabel(t *testing.T) {
	binding := func(site string, domains ...string) normalizedBinding {
		return normalizedBinding{SiteID: site, Domains: domains}
	}
	if err := rejectSNIConflicts([]normalizedBinding{binding("wild", "*.example.test"), binding("one", "one.example.test")}); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("single-label name under a wildcard: %v", err)
	}
	for _, domain := range []string{"example.test", "two.one.example.test", "*.one.example.test"} {
		if err := rejectSNIConflicts([]normalizedBinding{binding("wild", "*.example.test"), binding("other", domain)}); err != nil {
			t.Fatalf("wildcard conflicted with %q: %v", domain, err)
		}
	}
}

func cloneBundle(t *testing.T, input Bundle) Bundle {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var output Bundle
	if err := json.Unmarshal(raw, &output); err != nil {
		t.Fatal(err)
	}
	return output
}

func artifactContent(t *testing.T, artifact Artifact, name string) []byte {
	t.Helper()
	for _, file := range artifact.Files {
		if file.Path == name {
			return file.Content
		}
	}
	t.Fatalf("artifact file %q missing", name)
	return nil
}

func issueTestMaterial(t *testing.T, dnsNames []string, notBefore, notAfter time.Time, leafKey *ecdsa.PrivateKey) certificateMaterial {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: testNow.Add(-24 * time.Hour), NotAfter: testNow.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:           x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"},
		NotBefore: testNow.Add(-12 * time.Hour), NotAfter: testNow.Add(12 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:           x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, intermediateKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	if leafKey == nil {
		leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: dnsNames[0]}, DNSNames: dnsNames,
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, leafKey.Public(), intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return certificateMaterial{
		chainPEM:   string(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER})...)),
		privatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
		leaf:       leaf, root: root,
	}
}

func issueWeakRSAMaterial(t *testing.T, domain string) certificateMaterial {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "RSA root"}, NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SignatureAlgorithm: x509.SHA256WithRSA}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(11), DNSNames: []string{domain}, NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, SignatureAlgorithm: x509.SHA256WithRSA}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, leafKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER := x509.MarshalPKCS1PrivateKey(leafKey)
	return certificateMaterial{
		chainPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		privatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER})), root: root,
	}
}

func issueWeakSignatureMaterial(t *testing.T, domain string) certificateMaterial {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(20), Subject: pkix.Name{CommonName: "SHA-1 root"}, NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SignatureAlgorithm: x509.SHA256WithRSA}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(21), DNSNames: []string{domain}, NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, SignatureAlgorithm: x509.SHA1WithRSA}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, leafKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER := x509.MarshalPKCS1PrivateKey(leafKey)
	return certificateMaterial{
		chainPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		privatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER})), root: root,
	}
}

func TestNoPrivateMaterialInPublicStructures(t *testing.T) {
	for _, value := range []any{Manifest{}, ManifestBinding{}, Status{}, Result{}} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(raw)), "private_key_pem") {
			t.Fatalf("public state includes private key field: %s", raw)
		}
	}
}
