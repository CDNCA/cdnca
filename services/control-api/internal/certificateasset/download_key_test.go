package certificateasset

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

// fix-certops 下载证书：上传证书的信封里是 PKCS#8 PEM，ACME 解包后是 PKCS#8 DER；
// 两种都输出 PKCS#8 PEM，且必须与证书公钥一致。
func TestDownloadPrivateKeyPEMAcceptsPEMAndDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	spki, _ := x509.MarshalPKIXPublicKey(key.Public())
	digest := sha256.Sum256(spki)
	want := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for name, input := range map[string][]byte{"pem": want, "der": der,
		"ec pem": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustEC(t, key)})} {
		got, err := downloadPrivateKeyPEM(input, digest)
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s: %v %q", name, err, got)
		}
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.MarshalPKCS8PrivateKey(other)
	if _, err := downloadPrivateKeyPEM(otherDER, digest); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("mismatched key = %v", err)
	}
	if _, err := downloadPrivateKeyPEM([]byte("garbage"), digest); err == nil {
		t.Fatal("garbage accepted")
	}
}

func mustEC(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
