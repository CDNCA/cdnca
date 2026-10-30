package certificateasset

import (
	"bytes"
	"crypto/x509"
	"testing"
)

// 修复无法申请证书的问题：生产 ACME resolver 解出的是
// acmeruntime 包装的 PKCS#8 DER（不是 PEM）；发布材料必须能用它，否则签出来
// 的 ACME 证书永远发布不到节点（ErrEnvelopeUnavailable）。
func TestACMEResolvedDERPrivateKeyPreparesForPublication(t *testing.T) {
	fixture := newCertificateFixture(t, leafOptions{})
	der, err := x509.MarshalPKCS8PrivateKey(fixture.leafKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, resolved := range map[string][]byte{"pkcs8 der": der, "pem": fixture.privateKeyPEM} {
		t.Run(name, func(t *testing.T) {
			keyPEM := acmeResolvedPrivateKeyPEM(resolved)
			defer zeroBytes(keyPEM)
			prepared, err := prepareCertificate(fixture.certificatePEM, keyPEM, nil, certificateTestNow)
			if err != nil {
				t.Fatalf("prepareCertificate(resolved %s) = %v", name, err)
			}
			if len(prepared.CanonicalPrivateKey) == 0 || !bytes.HasPrefix(prepared.CanonicalPrivateKey, []byte("-----BEGIN ")) {
				t.Fatalf("canonical key is not PEM: %q", prepared.CanonicalPrivateKey)
			}
			zeroBytes(prepared.CanonicalPrivateKey)
		})
	}
	// The returned copy is separate: zeroing it leaves the resolver's bytes.
	keyPEM := acmeResolvedPrivateKeyPEM(fixture.privateKeyPEM)
	zeroBytes(keyPEM)
	if !bytes.HasPrefix(fixture.privateKeyPEM, []byte("-----BEGIN ")) {
		t.Fatal("acmeResolvedPrivateKeyPEM aliased its input")
	}
}
