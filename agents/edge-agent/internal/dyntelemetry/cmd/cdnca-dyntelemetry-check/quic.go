package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
)

// quicListen: a TLS + QUIC reuseport port, IPv4 and IPv6, as the skeleton
// renders an HTTP/3 port (docs/edge/node-skeleton.md §2).
func quicListen() string {
	certificate, key := filepath.Join(*stateRoot+"-tls", "c.pem"), filepath.Join(*stateRoot+"-tls", "k.pem")
	_ = os.MkdirAll(filepath.Dir(certificate), 0o755)
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "placeholder.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	keyDER, _ := x509.MarshalECPrivateKey(private)
	_ = os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o644)
	return "    listen 127.0.0.1:18443 ssl default_server;\n    listen 127.0.0.1:18443 quic reuseport default_server;\n" +
		"    listen [::1]:18443 ssl default_server;\n    listen [::1]:18443 quic reuseport default_server;\n" +
		"    http3 on;\n    ssl_protocols TLSv1.2 TLSv1.3;\n" +
		"    ssl_certificate " + certificate + ";\n    ssl_certificate_key " + key + ";\n"
}

// checkQUICNoise: reloads with quic reuseport write the known noise; the
// error log reader skips exactly those lines (the run's error-log check then
// requires no other severe line).
func checkQUICNoise(n *node) {
	reader := &dyntelemetry.ErrorLog{Path: filepath.Join(n.prefix, "nginx", "logs", "error.log")}
	_, _ = reader.Read()
	for range 2 {
		if err := openresty("-s", "reload"); err != nil {
			check("quic-reload", false, "%v", err)
			return
		}
		time.Sleep(800 * time.Millisecond)
	}
	summary, err := reader.Read()
	// 2 reloads × 2 workers × 2 QUIC sockets, at least one per reload.
	check("quic-noise-filtered", err == nil && summary.Noise >= 2 && len(summary.Severe) == 0,
		"noise %d severe %v %v", summary.Noise, summary.Severe, err)
}
