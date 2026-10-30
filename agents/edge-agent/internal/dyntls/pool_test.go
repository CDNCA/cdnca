package dyntls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	versionA = "0d4a0000-0000-4000-8000-0000000000a1"
	versionB = "0d4a0000-0000-4000-8000-0000000000b2"
)

type testCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

func newCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "d4 test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(der)
	return testCA{certificate: certificate, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns leaf, chain PEM (leaf + CA) and key PEM.
func (ca testCA) issue(t *testing.T, serial int64, names ...string) (*x509.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.pem...)
	return leaf, chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func (ca testCA) ocsp(t *testing.T, leaf *x509.Certificate, status int, next time.Time) []byte {
	t.Helper()
	response, err := ocsp.CreateResponse(ca.certificate, ca.certificate, ocsp.Response{Status: status, SerialNumber: leaf.SerialNumber,
		ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: next}, crypto.Signer(ca.key))
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestPutCertificate(t *testing.T) {
	ca := newCA(t)
	pool := Pool{Root: filepath.Join(t.TempDir(), "pool"), GID: -1}
	_, chain, key := ca.issue(t, 10, "a.test")
	if err := pool.PutCertificate(versionA, chain, key); err != nil {
		t.Fatal(err)
	}
	if err := pool.PutCertificate(versionA, chain, key); err != nil {
		t.Fatalf("idempotent put: %v", err)
	}
	for _, suffix := range []string{".crt", ".key"} {
		info, err := os.Stat(pool.path(versionA, suffix))
		if err != nil || info.Mode().Perm() != 0o440 {
			t.Fatalf("%s: %v %v", suffix, info.Mode(), err)
		}
	}
	if info, _ := os.Stat(pool.Root); info.Mode().Perm() != 0o750 {
		t.Fatalf("pool mode %v", info.Mode())
	}
	_, other, otherKey := ca.issue(t, 11, "a.test")
	if err := pool.PutCertificate(versionA, other, otherKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a version's content changed: %v", err)
	}
	if err := pool.PutCertificate(versionB, chain, otherKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched key accepted: %v", err)
	}
	for name, input := range map[string][2][]byte{
		"empty chain":   {nil, key},
		"key in chain":  {append(append([]byte{}, chain...), key...), key},
		"garbage chain": {[]byte("not pem"), key},
		"empty key":     {chain, nil},
	} {
		if err := pool.PutCertificate(versionB, input[0], input[1]); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if err := pool.PutCertificate("../escape", chain, key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("path in version accepted: %v", err)
	}
	versions, err := pool.Versions()
	if err != nil || !slices.Equal(versions, []string{versionA}) {
		t.Fatalf("versions %v %v", versions, err)
	}
}

func TestOCSP(t *testing.T) {
	ca := newCA(t)
	pool := Pool{Root: filepath.Join(t.TempDir(), "pool"), GID: -1}
	leaf, chain, key := ca.issue(t, 20, "a.test")
	if err := pool.PutCertificate(versionA, chain, key); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	good := ca.ocsp(t, leaf, ocsp.Good, now.Add(time.Hour))
	if err := pool.PutOCSP(versionA, good, nil, now); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(pool.path(versionA, ".ocsp")); string(raw) != string(good) {
		t.Fatal("OCSP response not stored")
	}
	other, _, _ := ca.issue(t, 21, "b.test")
	for name, response := range map[string][]byte{
		"revoked":        ca.ocsp(t, leaf, ocsp.Revoked, now.Add(time.Hour)),
		"expired":        ca.ocsp(t, leaf, ocsp.Good, now.Add(-time.Second)),
		"other leaf":     ca.ocsp(t, other, ocsp.Good, now.Add(time.Hour)),
		"other issuer":   newCA(t).ocsp(t, leaf, ocsp.Good, now.Add(time.Hour)),
		"not a response": []byte("garbage"),
		"empty":          nil,
	} {
		if err := pool.PutOCSP(versionA, response, nil, now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if raw, _ := os.ReadFile(pool.path(versionA, ".ocsp")); string(raw) != string(good) {
		t.Fatal("a rejected response replaced the good one")
	}
	if err := pool.RemoveOCSP(versionA); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pool.path(versionA, ".ocsp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("OCSP response not removed")
	}
	// A leaf without its issuer in the chain cannot be stapled (nginx
	// validates the response against the chain's issuer).
	leafOnly, chainWithIssuer, leafKey := ca.issue(t, 22, "c.test")
	block, _ := pem.Decode(chainWithIssuer)
	if err := pool.PutCertificate(versionB, pem.EncodeToMemory(block), leafKey); err != nil {
		t.Fatal(err)
	}
	if err := pool.PutOCSP(versionB, ca.ocsp(t, leafOnly, ocsp.Good, now.Add(time.Hour)), nil, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stapling without an issuer in the chain: %v", err)
	}
}

func TestRetain(t *testing.T) {
	ca := newCA(t)
	pool := Pool{Root: filepath.Join(t.TempDir(), "pool"), GID: -1}
	leaf, chain, key := ca.issue(t, 30, "a.test")
	for _, version := range []string{versionA, versionB} {
		if err := pool.PutCertificate(version, chain, key); err != nil {
			t.Fatal(err)
		}
	}
	if err := pool.PutOCSP(versionB, ca.ocsp(t, leaf, ocsp.Good, time.Now().Add(time.Hour)), nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pool.Root, ".x.crt.tmp-1"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := pool.Retain([]string{versionA})
	if err != nil || removed != 1 {
		t.Fatalf("removed %d %v", removed, err)
	}
	entries, _ := os.ReadDir(pool.Root)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if !slices.Equal(names, []string{versionA + ".crt", versionA + ".key"}) {
		t.Fatalf("left %v", names)
	}
}

func TestPlaceholder(t *testing.T) {
	directory := t.TempDir()
	certificate, key := filepath.Join(directory, "placeholder.crt"), filepath.Join(directory, "placeholder.key")
	if err := WritePlaceholder(certificate, key, -1); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(certificate)
	if err := WritePlaceholder(certificate, key, -1); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(certificate)
	if string(first) != string(again) {
		t.Fatal("placeholder rewritten although present")
	}
	keyPEM, _ := os.ReadFile(key)
	leaf, _, err := ParseChain(first, keyPEM)
	if err != nil || leaf.Subject.CommonName != PlaceholderName || !slices.Equal(leaf.DNSNames, []string{PlaceholderName}) {
		t.Fatalf("placeholder %v %v", leaf, err)
	}
}
