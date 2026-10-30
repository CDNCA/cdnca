package edgegolden

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// PKI is the run's certificate authorities, made fresh for every run: keys
// and certificate bytes differ between runs, so observations record only the
// names, serials and issuers. "site" issues site certificates, "origin" and
// "other" origin certificates and trust anchors.
type PKI struct {
	CAs map[string]*CA
}

type CA struct {
	Name        string
	Certificate *x509.Certificate
	PEM         []byte
	key         *ecdsa.PrivateKey
}

// CANames are the authorities every run has.
var CANames = []string{"site", "origin", "other"}

func NewPKI() (*PKI, error) {
	pki := &PKI{CAs: map[string]*CA{}}
	for index, name := range CANames {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(index + 1)),
			Subject:   pkix.Name{CommonName: "cdnca edge golden " + name + " CA"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		pki.CAs[name] = &CA{Name: name, Certificate: certificate, key: key,
			PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	}
	return pki, nil
}

func (pki *PKI) CA(name string) (*CA, error) {
	ca, ok := pki.CAs[name]
	if !ok {
		return nil, fmt.Errorf("unknown CA %q", name)
	}
	return ca, nil
}

// TrustDigest is the SHA-256 (hex) of the CA's PEM, as origin trust refs name it.
func (ca *CA) TrustDigest() string {
	sum := sha256.Sum256(ca.PEM)
	return hex.EncodeToString(sum[:])
}

// Issue returns a leaf certificate and key (PEM) for names.
func (ca *CA) Issue(serial int64, names ...string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// ClientCertificate is a client authentication certificate for name.
func (ca *CA) ClientCertificate(serial int64, name string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// TLSCertificate is Issue as a tls.Certificate.
func (ca *CA) TLSCertificate(serial int64, names ...string) (tls.Certificate, error) {
	certificate, key, err := ca.Issue(serial, names...)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certificate, key)
}

// Placeholders are the values every renderer can expand in site facts:
// ${trust:<ca>} = "sha256:<digest>", ${trust_hex:<ca>} = "<digest>".
func (pki *PKI) Placeholders() map[string]string {
	values := map[string]string{}
	for name, ca := range pki.CAs {
		values["trust:"+name] = "sha256:" + ca.TrustDigest()
		values["trust_hex:"+name] = ca.TrustDigest()
	}
	return values
}
