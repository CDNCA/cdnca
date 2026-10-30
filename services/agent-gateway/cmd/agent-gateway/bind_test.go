package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GW-10: `agent-gateway bind` generates both private keys on the Gateway
// host, sends only CSRs with the one-time token and writes what the
// installer needs (certificates, CAs and the endpoint environment).
func TestBindWritesKeysCertificatesAndEnvironment(t *testing.T) {
	ca := newRenewalCA(t)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	sum := sha256.Sum256(ca.cert.Raw)
	token := "gwt1.018f47a2-5b9c-7d31-8a60-104c9c0b717f." + hex.EncodeToString(sum[:16]) + ".c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA"
	var request map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/gateway-bindings/complete" || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad route", http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		clientCSR := parseRequestCSR(t, request["client_csr_der"])
		serverCSR := parseRequestCSR(t, request["server_csr_der"])
		if _, ok := clientCSR.PublicKey.(ed25519.PublicKey); !ok {
			t.Errorf("client CSR key %T", clientCSR.PublicKey)
		}
		if key, ok := serverCSR.PublicKey.(*ecdsa.PublicKey); !ok || key.Curve != elliptic.P256() {
			t.Errorf("server CSR key %T", serverCSR.PublicKey)
		}
		client := ca.sign(t, clientCSR.PublicKey, "spiffe://cdn-platform/gateway/018f47a2-5b9c-7d31-8a60-104c9c0b717f", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		serverCert := ca.sign(t, serverCSR.PublicKey, "spiffe://cdn-platform/gateway/018f47a2-5b9c-7d31-8a60-104c9c0b717f", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"gateway_id": "018f47a2-5b9c-7d31-8a60-104c9c0b717f", "installation_id": "9a3f47a2-5b9c-4d31-8a60-104c9c0b7100",
			"workload_uri_san":       "spiffe://cdn-platform/gateway/018f47a2-5b9c-7d31-8a60-104c9c0b717f",
			"client_certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: client})),
			"server_certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert})),
			"root_ca_pem":            string(rootPEM), "node_ca_pem": "-----BEGIN CERTIFICATE-----\nnode\n-----END CERTIFICATE-----\n",
			"endpoints": map[string]string{"control_internal_address": "control.example.com:9446", "control_internal_server_name": "control.example.com",
				"redis_url": "rediss://cdnca-gateway:p@control.example.com:6380/0", "nats_url": "wss://cdnca-gateway:p@control.example.com:4223",
				"telemetry_nats_url": "wss://control.example.com:4223"},
		})
	}))
	defer server.Close()
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root-ca.pem")
	if err := os.WriteFile(rootFile, rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	options := bindOptions{controlOrigin: server.URL, token: token, rootCAFile: rootFile, outputDir: filepath.Join(dir, "pki"),
		enrollmentPort: 21443, agentPort: 21444, version: "1.0.35", httpClient: server.Client()}
	if err := runBind(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	if request["token"] != token || request["enrollment_port"] != float64(21443) || request["agent_port"] != float64(21444) || request["version"] != "1.0.35" {
		t.Fatalf("bind request = %v", request)
	}
	for name, mode := range map[string]os.FileMode{"control-client-key.pem": 0o600, "server-key.pem": 0o600, "control-client.pem": 0o644,
		"server.pem": 0o644, "root-ca.pem": 0o644, "node-ca.pem": 0o644, "binding.env": 0o600} {
		info, err := os.Stat(filepath.Join(options.outputDir, name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v", name, info, err)
		}
	}
	// The written key pairs load as the Gateway's control client identity.
	if _, err := loadCertificate(filepath.Join(options.outputDir, "control-client.pem"), filepath.Join(options.outputDir, "control-client-key.pem"), x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("client pair: %v", err)
	}
	env, _ := os.ReadFile(filepath.Join(options.outputDir, "binding.env"))
	for _, line := range []string{"CDNCA_GATEWAY_INSTANCE_ID=018f47a2-5b9c-7d31-8a60-104c9c0b717f",
		"CDNCA_CONTROL_ADDRESS=control.example.com:9446", "CDNCA_CONTROL_SERVER_NAME=control.example.com",
		"CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN=spiffe://cdn-platform/gateway/018f47a2-5b9c-7d31-8a60-104c9c0b717f",
		"CDNCA_REDIS_URL=rediss://cdnca-gateway:p@control.example.com:6380/0", "CDNCA_NATS_URL=wss://cdnca-gateway:p@control.example.com:4223",
		"CDNCA_TELEMETRY_NATS_URL=wss://control.example.com:4223"} {
		if !strings.Contains(string(env), line+"\n") {
			t.Fatalf("binding.env missing %q:\n%s", line, env)
		}
	}
}

func TestBindRejectsTokenForAnotherRootCA(t *testing.T) {
	ca := newRenewalCA(t)
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root-ca.pem")
	_ = os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), 0o600)
	called := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()
	err := runBind(t.Context(), bindOptions{controlOrigin: server.URL, rootCAFile: rootFile, outputDir: filepath.Join(dir, "pki"),
		token:          "gwt1.018f47a2-5b9c-7d31-8a60-104c9c0b717f.00000000000000000000000000000000.c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA",
		enrollmentPort: 21443, agentPort: 21444, version: "1.0.35", httpClient: server.Client()})
	if err == nil || called {
		t.Fatalf("mismatched root CA: err=%v called=%v", err, called)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "pki")); statErr == nil {
		t.Fatal("output written before the fingerprint check")
	}
}

func parseRequestCSR(t *testing.T, value any) *x509.CertificateRequest {
	t.Helper()
	encoded, _ := value.(string)
	der, err := base64Std(encoded)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("csr: %v", err)
	}
	return csr
}
