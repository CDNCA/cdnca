package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
)

func TestEdgePublishRemoteSignerSignsLargeArtifactsAndFailsClosed(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const (
		keyID = "edge-remote-2026"
		token = "remote-signer-test-token"
	)
	invalidSignature := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/sign" ||
			request.Header.Get("Authorization") != "Bearer "+token ||
			request.Header.Get("X-CDNCA-Signing-Key-ID") != keyID ||
			request.Header.Get("X-CDNCA-Signature-Algorithm") != "ed25519" ||
			request.Header.Get("Content-Type") != "application/octet-stream" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		payload, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		signature := ed25519.Sign(privateKey, payload)
		if invalidSignature {
			signature[0] ^= 0xff
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{
			"key_id": keyID, "algorithm": "ed25519",
			"signature_base64url": base64.RawURLEncoding.EncodeToString(signature),
		})
	}))
	t.Cleanup(server.Close)

	directory := t.TempDir()
	publicKeyFile := filepath.Join(directory, "edge-signing-public.pem")
	encodedPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	writeEdgePublishSignerTestFile(t, publicKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encodedPublicKey}), 0o644)
	caFile := filepath.Join(directory, "remote-ca.pem")
	writeEdgePublishSignerTestFile(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o644)
	tokenFile := filepath.Join(directory, "remote-token")
	writeEdgePublishSignerTestFile(t, tokenFile, []byte(token), 0o600)

	for name, value := range map[string]string{
		"EDGE_PUBLISH_SIGNER_PROVIDER":                 "remote",
		"EDGE_PUBLISH_SIGNING_KEY_ID":                  keyID,
		"EDGE_PUBLISH_SIGNING_PRIVATE_KEY_FILE":        "",
		"EDGE_PUBLISH_SIGNING_PUBLIC_KEY_FILE":         publicKeyFile,
		"EDGE_PUBLISH_SIGNER_REMOTE_ENDPOINT":          server.URL + "/v1/sign",
		"EDGE_PUBLISH_SIGNER_REMOTE_CA_FILE":           caFile,
		"EDGE_PUBLISH_SIGNER_REMOTE_BEARER_TOKEN_FILE": tokenFile,
		"EDGE_PUBLISH_SIGNER_REMOTE_TIMEOUT":           "2s",
	} {
		t.Setenv(name, value)
	}
	signer, err := loadEdgePublishArtifactSigner(true)
	if err != nil {
		t.Fatalf("load remote signer: %v", err)
	}
	t.Cleanup(signer.Close)
	payload := make([]byte, 8192)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		t.Fatalf("remote signature = (%d bytes, %v)", len(signature), err)
	}
	invalidSignature = true
	if _, err := signer.Sign(context.Background(), payload); !errors.Is(err, edgepublish.ErrSigningFailed) {
		t.Fatalf("invalid remote signature error = %v", err)
	}
}

func TestEdgePublishRemoteSignerConfigurationFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name     string
		provider string
		private  string
		endpoint string
	}{
		{name: "unknown provider", provider: "kms"},
		{name: "remote with local private key", provider: "remote", private: "/secret/key.pem", endpoint: "https://signer.example.test/v1/sign"},
		{name: "remote over cleartext", provider: "remote", endpoint: "http://signer.example.test/v1/sign"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range map[string]string{
				"EDGE_PUBLISH_SIGNER_PROVIDER":          test.provider,
				"EDGE_PUBLISH_SIGNING_KEY_ID":           "edge-remote-2026",
				"EDGE_PUBLISH_SIGNING_PRIVATE_KEY_FILE": test.private,
				"EDGE_PUBLISH_SIGNER_REMOTE_ENDPOINT":   test.endpoint,
			} {
				t.Setenv(name, value)
			}
			if signer, err := loadEdgePublishArtifactSigner(true); err == nil || signer != nil {
				if signer != nil {
					signer.Close()
				}
				t.Fatalf("load signer = (%v, %v), want fail-closed", signer, err)
			}
		})
	}
}

func writeEdgePublishSignerTestFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
}
