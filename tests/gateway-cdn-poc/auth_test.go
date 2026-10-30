package main

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testFixture(t *testing.T) (agentIdentity, *tokenVerifier, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pki")
	if err := runPKI(dir); err != nil {
		t.Fatal(err)
	}
	id, err := loadAgentIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	nodeCAs, err := loadPool(filepath.Join(dir, "node-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return id, &tokenVerifier{audience: "cdnca-gateway", nodeCAs: nodeCAs, nonces: &nonceCache{seen: map[string]time.Time{}}}, dir
}

func TestSignedHeaderAccepts(t *testing.T) {
	id, verifier, _ := testFixture(t)
	cert, auth, err := nodeToken(id.leaf, id.key, "cdnca-gateway", "/m", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	nodeID, err := verifier.verify(cert, auth, "/m", time.Now())
	if err != nil || nodeID != pocNodeID {
		t.Fatalf("nodeID=%q err=%v", nodeID, err)
	}
}

func TestSignedHeaderRejects(t *testing.T) {
	id, verifier, dir := testFixture(t)
	now := time.Now()
	cert, auth, _ := nodeToken(id.leaf, id.key, "cdnca-gateway", "/m", now)
	if _, err := verifier.verify(cert, auth, "/m", now); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() (string, string, string, time.Time){
		"replayed nonce": func() (string, string, string, time.Time) { return cert, auth, "/m", now },
		"other method": func() (string, string, string, time.Time) {
			c, a, _ := nodeToken(id.leaf, id.key, "cdnca-gateway", "/m", now)
			return c, a, "/other", now
		},
		"other audience": func() (string, string, string, time.Time) {
			c, a, _ := nodeToken(id.leaf, id.key, "other-gateway", "/m", now)
			return c, a, "/m", now
		},
		"stale token": func() (string, string, string, time.Time) {
			c, a, _ := nodeToken(id.leaf, id.key, "cdnca-gateway", "/m", now.Add(-2*time.Minute))
			return c, a, "/m", now
		},
		"tampered signature": func() (string, string, string, time.Time) {
			c, a, _ := nodeToken(id.leaf, id.key, "cdnca-gateway", "/m", now)
			return c, a[:len(a)-4] + "AAA=", "/m", now
		},
		"certificate from another CA": func() (string, string, string, time.Time) {
			_, _, otherDir := testFixture(t)
			other, _ := loadAgentIdentity(otherDir)
			c, a, _ := nodeToken(other.leaf, other.key, "cdnca-gateway", "/m", now)
			return c, a, "/m", now
		},
		"expired certificate": func() (string, string, string, time.Time) {
			c, a, _ := nodeToken(id.leaf, id.key, "cdnca-gateway", "/m", now.Add(25*time.Hour))
			return c, a, "/m", now.Add(25 * time.Hour)
		},
	}
	_ = dir
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			c, a, method, at := build()
			if _, err := verifier.verify(c, a, method, at); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// A TLS-terminating proxy cannot forward the node's TLS client certificate
// proof: a header carrying only the certificate (no signature) must fail.
func TestCertificateWithoutSignatureRejected(t *testing.T) {
	id, verifier, _ := testFixture(t)
	cert, _, _ := nodeToken(id.leaf, id.key, "cdnca-gateway", "/m", time.Now())
	if _, err := verifier.verify(cert, "", "/m", time.Now()); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("err=%v", err)
	}
	_ = tls.Certificate{}
	_ = x509.Certificate{}
}
