package gatewaytunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testNodeID = "018f47a2-5b9c-7d31-8a60-104c9c0b717f"

// Same vector as agent-gateway TestTunnelSignedTextVector.
func TestSignedTextVector(t *testing.T) {
	got := SignedText("aud", TunnelPath, testNodeID, "1a", 1700000000, "00112233445566778899aabbccddeeff")
	want := "cdnca-gw-auth-v1\naud\n/agent/v1/tunnel\n" + testNodeID + "\n1a\n1700000000\n00112233445566778899aabbccddeeff"
	if string(got) != want {
		t.Fatalf("signed text = %q", got)
	}
}

func TestTokenHeaderSignsWithNodeKey(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	uri, _ := url.Parse("spiffe://cdn-platform/node/" + testNodeID)
	template := &x509.Certificate{SerialNumber: big.NewInt(0x2b), Subject: pkix.Name{CommonName: "node"}, URIs: []*url.URL{uri},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	now := time.Unix(1700000000, 0)
	header, err := TokenHeader(leaf, private, "aud", TunnelPath, now, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if header.Get(certificateHeader) != base64.StdEncoding.EncodeToString(der) {
		t.Fatal("certificate header is not the leaf DER")
	}
	parts := strings.Split(header.Get(authHeader), ".")
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != "1700000000" || parts[2] != strings.Repeat("00", 16) {
		t.Fatalf("auth header = %q", header.Get(authHeader))
	}
	signature, _ := base64.StdEncoding.DecodeString(parts[3])
	if !ed25519.Verify(public, SignedText("aud", TunnelPath, testNodeID, "2b", 1700000000, parts[2]), signature) {
		t.Fatal("signature does not verify")
	}
	if _, err := TokenHeader(leaf, private, "", TunnelPath, now, nil); err == nil {
		t.Fatal("empty audience accepted")
	}
}
