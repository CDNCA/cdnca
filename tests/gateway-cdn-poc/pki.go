package main

// PoC PKI: one root CA signs the Gateway server certificate and the CDN edge
// certificate; a separate node CA signs the Ed25519 node client certificate
// with the production SPIFFE URI SAN (spiffe://cdn-platform/node/<uuid>).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const pocNodeID = "0b6f7d3e-5c1a-4e8b-9f2d-7a4c3b2e1d00"

func writePEM(path, kind string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600)
}

func writeKey(path string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(path, "PRIVATE KEY", der)
}

func newCA(name string) (*x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func issue(template *x509.Certificate, parent *x509.Certificate, parentKey crypto.Signer, public crypto.PublicKey) ([]byte, error) {
	template.SerialNumber = big.NewInt(time.Now().UnixNano())
	template.NotBefore = time.Now().Add(-time.Hour)
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(24 * time.Hour)
	}
	template.BasicConstraintsValid = true
	return x509.CreateCertificate(rand.Reader, template, parent, public, parentKey)
}

func runPKI(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	root, rootKey, err := newCA("poc root CA")
	if err != nil {
		return err
	}
	nodeCA, nodeCAKey, err := newCA("poc node CA")
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "root-ca.pem"), "CERTIFICATE", root.Raw); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "node-ca.pem"), "CERTIFICATE", nodeCA.Raw); err != nil {
		return err
	}
	// console = the control-plane management name (serves node-install-defaults);
	// gwedge = a CDN edge certificate for the gateway name itself (the CDN in
	// front of the gateway port presents it, the gateway keeps its own).
	for _, server := range []struct{ file, host string }{{"gateway", "gateway.poc.test"}, {"edge", "cdn.poc.test"}, {"console", "console.poc.test"}, {"gwedge", "gateway.poc.test"}} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := issue(&x509.Certificate{Subject: pkix.Name{CommonName: server.host}, DNSNames: []string{server.host, "localhost", "host.docker.internal"},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, root, rootKey, key.Public())
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, server.file+".pem"), "CERTIFICATE", der); err != nil {
			return err
		}
		if err := writeKey(filepath.Join(dir, server.file+"-key.pem"), key); err != nil {
			return err
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	spiffe, _ := url.Parse("spiffe://cdn-platform/node/" + pocNodeID)
	der, err := issue(&x509.Certificate{Subject: pkix.Name{CommonName: pocNodeID}, URIs: []*url.URL{spiffe},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, nodeCA, nodeCAKey, public)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "node.pem"), "CERTIFICATE", der); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, "node-key.pem"), private); err != nil {
		return err
	}
	fmt.Println("pki written to", dir)
	return nil
}
