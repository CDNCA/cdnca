package main

// Outer (CDN-visible) node authentication used by the PoC:
//
//   Cdnca-Node-Cert: base64(DER node leaf certificate)
//   Cdnca-Node-Auth: v1.<iat unix seconds>.<nonce hex>.<base64 Ed25519 signature>
//
// signed text = "cdnca-gw-auth-v1\n" + audience + "\n" + method + "\n" +
//               node_id + "\n" + serial_hex + "\n" + iat + "\n" + nonce
//
// The Gateway checks the certificate chains to the node CA with clientAuth,
// carries exactly one node SPIFFE URI SAN, the signature verifies with the
// certificate key, |now - iat| <= 60s and the nonce was not seen in 120s.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	headerNodeCert = "Cdnca-Node-Cert"
	headerNodeAuth = "Cdnca-Node-Auth"
	tokenSkew      = 60 * time.Second
	nonceWindow    = 120 * time.Second
)

func signedText(audience, method, nodeID, serial string, iat int64, nonce string) []byte {
	return []byte(strings.Join([]string{"cdnca-gw-auth-v1", audience, method, nodeID, serial, strconv.FormatInt(iat, 10), nonce}, "\n"))
}

func nodeToken(leaf *x509.Certificate, key ed25519.PrivateKey, audience, method string, now time.Time) (string, string, error) {
	nodeID, err := nodeIDFromCertificate(leaf)
	if err != nil {
		return "", "", err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	nonce := hex.EncodeToString(raw)
	iat := now.Unix()
	signature := ed25519.Sign(key, signedText(audience, method, nodeID, leaf.SerialNumber.Text(16), iat, nonce))
	return base64.StdEncoding.EncodeToString(leaf.Raw),
		fmt.Sprintf("v1.%d.%s.%s", iat, nonce, base64.StdEncoding.EncodeToString(signature)), nil
}

type nonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (c *nonceCache) accept(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, at := range c.seen {
		if now.Sub(at) > nonceWindow {
			delete(c.seen, key)
		}
	}
	if _, ok := c.seen[nonce]; ok {
		return false
	}
	c.seen[nonce] = now
	return true
}

type tokenVerifier struct {
	audience string
	nodeCAs  *x509.CertPool
	nonces   *nonceCache
}

func (v *tokenVerifier) verify(certHeader, authHeader, method string, now time.Time) (string, error) {
	der, err := base64.StdEncoding.DecodeString(certHeader)
	if err != nil {
		return "", errors.New("node certificate header is invalid")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return "", errors.New("node certificate is invalid")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: v.nodeCAs, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", fmt.Errorf("node certificate does not chain to the node CA: %w", err)
	}
	nodeID, err := nodeIDFromCertificate(leaf)
	if err != nil {
		return "", err
	}
	parts := strings.Split(authHeader, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return "", errors.New("node auth header is malformed")
	}
	iat, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New("node auth iat is invalid")
	}
	if delta := now.Sub(time.Unix(iat, 0)); delta > tokenSkew || delta < -tokenSkew {
		return "", errors.New("node auth token is outside the allowed clock window")
	}
	signature, err := base64.StdEncoding.DecodeString(parts[3])
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if err != nil || !ok || !ed25519.Verify(public, signedText(v.audience, method, nodeID, leaf.SerialNumber.Text(16), iat, parts[2]), signature) {
		return "", errors.New("node auth signature is invalid")
	}
	if !v.nonces.accept(parts[2], now) {
		return "", errors.New("node auth nonce was replayed")
	}
	return nodeID, nil
}
