package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestControlUpgradeSignerProvidersKeepFileDefaultAndAllowIndependentRemoteDomains(t *testing.T) {
	publicControl, privateControl, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicEdge, privateEdge, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controlServer, controlCalls := newControlUpgradeSignerTestServer(t, "control-remote-2026", privateControl)
	edgeServer, edgeCalls := newControlUpgradeSignerTestServer(t, "edge-remote-2026", privateEdge)

	directory := t.TempDir()
	controlPublicFile := filepath.Join(directory, "control-public.pem")
	edgePublicFile := filepath.Join(directory, "edge-public.pem")
	writeControlUpgradePublicKey(t, controlPublicFile, publicControl)
	writeControlUpgradePublicKey(t, edgePublicFile, publicEdge)
	controlCAFile := filepath.Join(directory, "control-ca.pem")
	edgeCAFile := filepath.Join(directory, "edge-ca.pem")
	writeControlUpgradeFile(t, controlCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: controlServer.Certificate().Raw}), 0o644)
	writeControlUpgradeFile(t, edgeCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: edgeServer.Certificate().Raw}), 0o644)
	controlTokenFile := filepath.Join(directory, "control-token")
	edgeTokenFile := filepath.Join(directory, "edge-token")
	writeControlUpgradeFile(t, controlTokenFile, []byte("control-remote-token"), 0o600)
	writeControlUpgradeFile(t, edgeTokenFile, []byte("edge-remote-token"), 0o600)

	control, err := openControlUpgradeSigningProvider(controlUpgradeSignerProviderConfig{
		Provider: controlUpgradeSignerProviderRemote, KeyID: "control-remote-2026",
		PublicKeyFile: controlPublicFile, RemoteEndpoint: controlServer.URL + "/v1/sign",
		RemoteCAFile: controlCAFile, RemoteBearerTokenFile: controlTokenFile, RemoteTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("open control remote signer: %v", err)
	}
	defer control.Close()
	edge, err := openControlUpgradeSigningProvider(controlUpgradeSignerProviderConfig{
		Provider: controlUpgradeSignerProviderRemote, KeyID: "edge-remote-2026",
		PublicKeyFile: edgePublicFile, RemoteEndpoint: edgeServer.URL + "/v1/sign",
		RemoteCAFile: edgeCAFile, RemoteBearerTokenFile: edgeTokenFile, RemoteTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("open edge remote signer: %v", err)
	}
	defer edge.Close()

	payload := []byte("control-upgrade-domain-payload")
	controlSignature, err := control.Sign(context.Background(), payload)
	if err != nil || !ed25519.Verify(publicControl, payload, controlSignature) || control.KeyID() != "control-remote-2026" {
		t.Fatalf("control signature = (%x,%v)", controlSignature, err)
	}
	edgeSignature, err := edge.Sign(context.Background(), payload)
	if err != nil || !ed25519.Verify(publicEdge, payload, edgeSignature) || edge.KeyID() != "edge-remote-2026" {
		t.Fatalf("edge signature = (%x,%v)", edgeSignature, err)
	}
	if atomic.LoadInt32(controlCalls) != 1 || atomic.LoadInt32(edgeCalls) != 1 {
		t.Fatalf("independent remote endpoints calls = (%d,%d)", atomic.LoadInt32(controlCalls), atomic.LoadInt32(edgeCalls))
	}

	fileEnvironment := controlUpgradeValidRuntimeEnvironment(t)
	config, err := loadControlUpgradeRuntimeConfigFromEnv(fileEnvironment)
	if err != nil || config.ControlSigner.Provider != controlUpgradeSignerProviderFile || config.EdgeSigner.Provider != controlUpgradeSignerProviderFile {
		t.Fatalf("default file providers = (%+v,%v)", config, err)
	}
}

func TestControlUpgradeRemoteSignerFailsClosedOnIdentityTransportAndBounds(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	publicFile := filepath.Join(directory, "public.pem")
	writeControlUpgradePublicKey(t, publicFile, publicKey)
	tokenFile := filepath.Join(directory, "token")
	writeControlUpgradeFile(t, tokenFile, []byte("strict-remote-token"), 0o600)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer strict-remote-token" ||
			request.Header.Get("X-CDNCA-Signing-Key-ID") != "control-strict-2026" ||
			request.Header.Get("X-CDNCA-Signature-Algorithm") != "ed25519" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		payload, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		signature := ed25519.Sign(privateKey, payload)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"key_id":"wrong-key","algorithm":"ed25519","signature_base64url":"` + base64.RawURLEncoding.EncodeToString(signature) + `"}`))
	}))
	defer server.Close()
	caFile := filepath.Join(directory, "ca.pem")
	writeControlUpgradeFile(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o644)
	signer, err := openControlUpgradeSigningProvider(controlUpgradeSignerProviderConfig{
		Provider: controlUpgradeSignerProviderRemote, KeyID: "control-strict-2026", PublicKeyFile: publicFile,
		RemoteEndpoint: server.URL + "/sign", RemoteCAFile: caFile, RemoteBearerTokenFile: tokenFile, RemoteTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	remote := signer.(*controlUpgradeRemoteSigner)
	if _, err := signer.Sign(context.Background(), []byte("identity")); err == nil {
		t.Fatal("wrong key-id response was accepted")
	}
	if len(remote.token) == 0 {
		t.Fatal("remote token was not retained for request")
	}
	signer.Close()
	if remote.token != nil || remote.publicKey != nil || remote.client != nil || remote.endpoint != "" {
		t.Fatalf("remote signer secrets/resources were not cleared: %+v", remote)
	}

	for _, raw := range []string{
		"http://signer.example.test/v1/sign",
		"https://signer.example.test/v1/sign?x=1",
		"https://user:pass@signer.example.test/v1/sign",
		"https://signer.example.test/v1//sign",
	} {
		if _, err := controlUpgradeSignerEndpoint(raw); err == nil {
			t.Fatalf("endpoint %q was accepted", raw)
		}
	}
}

func TestControlUpgradeRemoteSignerRejectsRedirectTimeoutAndOversizedResponse(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	publicFile := filepath.Join(directory, "public.pem")
	writeControlUpgradePublicKey(t, publicFile, publicKey)
	tokenFile := filepath.Join(directory, "token")
	writeControlUpgradeFile(t, tokenFile, []byte("strict-remote-token"), 0o600)
	// mode is written by the subtests and read by the server goroutines (a
	// timed out request's handler may still run when the next subtest starts).
	var mode atomic.Value
	mode.Store("redirect")
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch mode.Load().(string) {
		case "redirect":
			http.Redirect(writer, request, server.URL+"/sign", http.StatusTemporaryRedirect)
		case "timeout":
			time.Sleep(200 * time.Millisecond)
		case "oversized":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(bytes.Repeat([]byte("x"), controlUpgradeSignerMaximumResponse+1))
		case "invalid-signature":
			writer.Header().Set("Content-Type", "application/json")
			bad := ed25519.Sign(privateKey, []byte("different-payload"))
			_ = json.NewEncoder(writer).Encode(controlUpgradeRemoteSignature{
				KeyID: "control-strict-2026", Algorithm: "ed25519",
				SignatureBase64URL: base64.RawURLEncoding.EncodeToString(bad),
			})
		}
	}))
	defer server.Close()
	caFile := filepath.Join(directory, "ca.pem")
	writeControlUpgradeFile(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o644)
	signer, err := openControlUpgradeSigningProvider(controlUpgradeSignerProviderConfig{
		Provider: controlUpgradeSignerProviderRemote, KeyID: "control-strict-2026", PublicKeyFile: publicFile,
		RemoteEndpoint: server.URL + "/sign", RemoteCAFile: caFile, RemoteBearerTokenFile: tokenFile,
		RemoteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	for _, test := range []struct {
		name string
		want string
	}{
		{name: "redirect", want: "redirect"},
		{name: "timeout", want: "timeout"},
		{name: "oversized", want: "oversized"},
		{name: "local verification", want: "invalid-signature"},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode.Store(test.want)
			if _, err := signer.Sign(context.Background(), []byte("payload")); err == nil {
				t.Fatalf("mode %s was accepted", test.want)
			}
		})
	}
}

func TestControlUpgradeSignerConfigurationRejectsProviderMixingAndRemotePrivateKeys(t *testing.T) {
	environment := controlUpgradeValidRuntimeEnvironment(t)
	directory := t.TempDir()
	publicFile := filepath.Join(directory, "public.pem")
	writeControlUpgradePublicKey(t, publicFile, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	caFile := filepath.Join(directory, "ca.pem")
	writeControlUpgradeFile(t, caFile, []byte("not-a-ca"), 0o644)
	tokenFile := filepath.Join(directory, "token")
	writeControlUpgradeFile(t, tokenFile, []byte("remote-token"), 0o600)
	remote := []string{
		controlUpgradeControlSignerProviderEnv + "=remote",
		controlUpgradeControlSigningPublicKeyFileEnv + "=" + publicFile,
		controlUpgradeControlSignerRemoteEndpointEnv + "=https://signer.example.test/v1/sign",
		controlUpgradeControlSignerRemoteCAFileEnv + "=" + caFile,
		controlUpgradeControlSignerRemoteBearerTokenFileEnv + "=" + tokenFile,
		controlUpgradeControlSignerRemoteTimeoutEnv + "=1s",
	}
	for _, test := range []struct {
		name   string
		mutate func([]string) []string
	}{
		{name: "file rejects residual remote variables", mutate: func(values []string) []string {
			return append(values, controlUpgradeControlSignerRemoteEndpointEnv+"=")
		}},
		{name: "remote rejects private key", mutate: func(values []string) []string {
			values = append(values, remote...)
			return values
		}},
		{name: "unknown provider", mutate: func(values []string) []string {
			return append(values, controlUpgradeControlSignerProviderEnv+"=kms")
		}},
		{name: "remote token must be owner-only", mutate: func(values []string) []string {
			for _, value := range remote {
				values = append(values, value)
			}
			if err := os.Chmod(tokenFile, 0o644); err != nil {
				t.Fatal(err)
			}
			return controlUpgradeDropEnvironment(values, controlUpgradeControlSigningPrivateKeyFileEnv)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := append([]string(nil), environment...)
			if config, err := loadControlUpgradeRuntimeConfigFromEnv(test.mutate(candidate)); err == nil || config.Enabled {
				t.Fatalf("invalid signer configuration = (%+v,%v)", config, err)
			}
		})
	}
}

func TestControlUpgradeRuntimeCloseClosesBothSignerProviders(t *testing.T) {
	control := &controlUpgradeTrackingSigner{keyID: "control-close-2026"}
	edge := &controlUpgradeTrackingSigner{keyID: "edge-close-2026"}
	runtime := &controlUpgradeProductionRuntime{controlSigner: control, edgeSigner: edge}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if !control.closed || !edge.closed {
		t.Fatalf("signer close = (%t,%t)", control.closed, edge.closed)
	}
}

type controlUpgradeTrackingSigner struct {
	keyID  string
	closed bool
}

func (signer *controlUpgradeTrackingSigner) KeyID() string { return signer.keyID }
func (*controlUpgradeTrackingSigner) Sign(context.Context, []byte) ([]byte, error) {
	return bytes.Repeat([]byte{1}, ed25519.SignatureSize), nil
}
func (*controlUpgradeTrackingSigner) PublicKey() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
}
func (signer *controlUpgradeTrackingSigner) Close() { signer.closed = true }

func newControlUpgradeSignerTestServer(t *testing.T, keyID string, privateKey ed25519.PrivateKey) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&calls, 1)
		payload, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{
			"key_id": keyID, "algorithm": "ed25519",
			"signature_base64url": base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
		})
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func writeControlUpgradePublicKey(t *testing.T, path string, key ed25519.PublicKey) {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeControlUpgradeFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0o644)
}

func writeControlUpgradeFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
}
