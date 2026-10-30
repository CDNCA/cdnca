//go:build ignore

// Authorization center stand-in for tests/signer-trust-push-e2e/run.sh. The
// license service publishes operator-uploaded offline-signed node signer trust
// documents at GET /public/v1/edge-signer-trust (verification, versioning and
// audit are covered by the license PG integration tests); this process serves
// the latest bytes (<dir>/downloads/edge-agent/signer-trust.json, written by the
// control half) on that path over HTTPS with a fresh self-signed certificate
// (<dir>/authority-ca.pem).
//
//	go run authority.go <dir>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: go run authority.go <dir>")
	}
	dir := os.Args[1]
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{CommonName: "signer-trust-push-e2e authority"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(6 * time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authority-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		log.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		log.Fatal(err)
	}
	downloads := filepath.Join(dir, "downloads")
	mux := http.NewServeMux()
	mux.Handle("/downloads/", http.StripPrefix("/downloads/", http.FileServer(http.Dir(downloads))))
	// Stand-in for the license service publication endpoint (GET /public/v1/edge-signer-trust,
	// signercheckpointhttp): the latest published bytes, 404 before the first publication.
	mux.HandleFunc("/public/v1/edge-signer-trust", func(response http.ResponseWriter, request *http.Request) {
		encoded, err := os.ReadFile(filepath.Join(downloads, "edge-agent", "signer-trust.json"))
		if err != nil {
			http.Error(response, `{"code":"not_published"}`, http.StatusNotFound)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(encoded)
	})
	encoded, _ := json.Marshal(map[string]string{"origin": "https://" + listener.Addr().String(),
		"ca_file": filepath.Join(dir, "authority-ca.pem"), "downloads_dir": downloads})
	if err := os.WriteFile(filepath.Join(dir, "authority.json.tmp"), encoded, 0o600); err != nil {
		log.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "authority.json.tmp"), filepath.Join(dir, "authority.json")); err != nil {
		log.Fatal(err)
	}
	log.Printf("authority download origin %s serving %s", "https://"+listener.Addr().String(), downloads)
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		log.Printf("GET %s", request.URL.Path)
		mux.ServeHTTP(response, request)
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		for {
			if _, err := os.Stat(filepath.Join(dir, "finished")); err == nil {
				_ = server.Close()
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
