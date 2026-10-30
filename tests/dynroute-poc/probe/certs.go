package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type issued struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

var serial int64 = 1000

func issue(cn string, dns []string, parent *issued, isCA bool, notBefore, notAfter time.Time) issued {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fail(err)
	}
	serial++
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if isCA {
		template.IsCA, template.BasicConstraintsValid = true, true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.ExtKeyUsage = nil
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		fail(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return issued{cert: cert, der: der, key: key}
}

func writePEM(path string, blocks ...issued) {
	var out []byte
	for _, block := range blocks {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.der})...)
	}
	must(os.WriteFile(path, out, 0o644))
}

func writeKey(path string, item issued) {
	der, err := x509.MarshalECPrivateKey(item.key)
	must(err)
	must(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o644))
}

func must(err error) {
	if err != nil {
		fail(err)
	}
}

// runCerts writes
//
//	edge/ca.crt and edge/<name>.{crt,key}: client-facing certificates (CN = name)
//	origin/caA.crt caB.crt trustAB.crt: tenant roots (and the merged anti-pattern)
//	origin/<case>.{crt,key}: origin certificates served by tlsorigin
func runCerts(args []string) error {
	flags := flag.NewFlagSet("certs", flag.ContinueOnError)
	out := flags.String("out", "", "directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	now := time.Now()
	valid := func() (time.Time, time.Time) { return now.Add(-time.Hour), now.Add(48 * time.Hour) }
	nb, na := valid()

	edge := filepath.Join(*out, "edge")
	must(os.MkdirAll(edge, 0o755))
	edgeCA := issue("dynroute-poc edge CA", nil, nil, true, nb, na)
	writePEM(filepath.Join(edge, "ca.crt"), edgeCA)
	for name, dns := range map[string][]string{
		"a.test":      {"a.test"},
		"b.test":      {"b.test"},
		"wild.w.test": {"*.w.test"},
		"tls12.test":  {"tls12.test"},
		"tls13.test":  {"tls13.test"},
		"slow.test":   {"slow.test"},
		"rot.test-v1": {"rot.test"},
		"rot.test-v2": {"rot.test"},
		// placeholder of the shared TLS server; served only if the Lua phase failed open
		"fallback.invalid": {"fallback.invalid"},
	} {
		leaf := issue(name, dns, &edgeCA, false, nb, na)
		writePEM(filepath.Join(edge, name+".crt"), leaf)
		writeKey(filepath.Join(edge, name+".key"), leaf)
	}

	origin := filepath.Join(*out, "origin")
	must(os.MkdirAll(origin, 0o755))
	rootA := issue("tenant-A root", nil, nil, true, nb, na)
	intA := issue("tenant-A intermediate", nil, &rootA, true, nb, na)
	rootB := issue("tenant-B root", nil, nil, true, nb, na)
	intB := issue("tenant-B intermediate", nil, &rootB, true, nb, na)
	writePEM(filepath.Join(origin, "caA.crt"), rootA)
	writePEM(filepath.Join(origin, "caB.crt"), rootB)
	writePEM(filepath.Join(origin, "trustAB.crt"), rootA, rootB)
	leaf := func(name, cn string, parent issued, chain bool, notBefore, notAfter time.Time) {
		item := issue(cn, []string{cn}, &parent, false, notBefore, notAfter)
		if chain {
			writePEM(filepath.Join(origin, name+".crt"), item, parent)
		} else {
			writePEM(filepath.Join(origin, name+".crt"), item)
		}
		writeKey(filepath.Join(origin, name+".key"), item)
	}
	leaf("a-good", "origin-a.internal", intA, true, nb, na)
	leaf("a-noint", "origin-a.internal", intA, false, nb, na)
	leaf("a-expired", "origin-a.internal", intA, true, now.Add(-72*time.Hour), now.Add(-24*time.Hour))
	leaf("a-wrongname", "other.internal", intA, true, nb, na)
	leaf("b-good", "origin-b.internal", intB, true, nb, na)
	// one origin host serving two names (virtual hosts on one address)
	multi := issue("one.internal", []string{"one.internal", "two.internal"}, &intA, false, nb, na)
	writePEM(filepath.Join(origin, "a-multi.crt"), multi, intA)
	writeKey(filepath.Join(origin, "a-multi.key"), multi)
	// Tenant A controls its own CA and issues a certificate for tenant B's
	// origin name: only per-pool trust stops this.
	leaf("b-evil", "origin-b.internal", intA, true, nb, na)
	return nil
}
