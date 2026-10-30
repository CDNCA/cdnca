//go:build !windows

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgradehttp"
	"github.com/google/uuid"
)

func TestNativeLoopbackPlanSourceRequiresMTLS(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	clientCAFile, clientFile, keyFile := writeOPS06ClientPKI(t, root)
	clientCA, err := os.ReadFile(clientCAFile)
	if err != nil {
		t.Fatal(err)
	}
	clients := x509.NewCertPool()
	if !clients.AppendCertsFromPEM(clientCA) {
		t.Fatal("client CA is invalid")
	}
	installationID := uuid.NewString()
	const token = "native-loopback-plan-32-byte-token"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set(controlplaneupgradehttp.SystemdPlanInstallationHeader, installationID)
		response.Header().Set(controlplaneupgradehttp.SystemdPlanOperationHeader, controlplaneupgrade.SystemdControlUpgradeOperation)
		response.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients}
	server.StartTLS()
	t.Cleanup(server.Close)
	serverCAFile, tokenFile := filepath.Join(root, "server-ca.pem"), filepath.Join(root, "token")
	for filename, body := range map[string][]byte{
		serverCAFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		tokenFile:    []byte(token),
	} {
		if err := os.WriteFile(filename, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CONTROL_UPGRADE_TARGET", string(controlplaneupgrade.TargetNativeStandalone))
	t.Setenv("CONTROL_UPGRADE_INTERNAL_TOKEN_FILE", tokenFile)
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_URL", server.URL+controlplaneupgradehttp.SystemdPlanSourcePath)
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_CA_FILE", serverCAFile)
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_CERT_FILE", clientFile)
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE", keyFile)
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_TIMEOUT", "2s")
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES", "1048576")
	t.Setenv("CONTROL_UPGRADE_PLAN_LKG_FILE", filepath.Join(root, "last-known-plan.json"))
	source, _, _, err := openHTTPPlanRuntime(installationID)
	if err != nil {
		t.Fatalf("native loopback mTLS plan source rejected: %v", err)
	}
	transport := source.client.Transport.(*http.Transport)
	t.Cleanup(transport.CloseIdleConnections)
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS13 || transport.TLSClientConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatal("native loopback relaxed production transport security")
	}
	if _, err := source.Fetch(t.Context()); !errors.Is(err, ErrHTTPPlanNotPublished) {
		t.Fatalf("authenticated empty plan source: %v", err)
	}
	for _, scenario := range []string{"no client certificate", "wrong client issuer", "wrong server trust", "wrong token"} {
		t.Run(scenario, func(t *testing.T) {
			candidate, _, _, err := openHTTPPlanRuntime(installationID)
			if err != nil {
				t.Fatal(err)
			}
			candidateTransport := candidate.client.Transport.(*http.Transport)
			t.Cleanup(candidateTransport.CloseIdleConnections)
			switch scenario {
			case "no client certificate":
				candidateTransport.TLSClientConfig.Certificates = nil
			case "wrong client issuer":
				_, wrongCert, wrongKey := writeOPS06ClientPKI(t, t.TempDir())
				certificate, err := tls.LoadX509KeyPair(wrongCert, wrongKey)
				if err != nil {
					t.Fatal(err)
				}
				candidateTransport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
			case "wrong server trust":
				candidateTransport.TLSClientConfig.RootCAs = clients
			case "wrong token":
				candidate.token = token + "wrong"
			}
			if _, err := candidate.Fetch(t.Context()); !errors.Is(err, ErrHTTPPlanSourceUnavailable) {
				t.Fatalf("insecure plan request was not rejected: %v", err)
			}
		})
	}
	for _, target := range []string{"", string(controlplaneupgrade.TargetSystemd), string(controlplaneupgrade.TargetKubernetes)} {
		t.Setenv("CONTROL_UPGRADE_TARGET", target)
		if _, _, _, err := openHTTPPlanRuntime(installationID); !errors.Is(err, ErrHTTPPlanSourceInvalid) {
			t.Fatalf("non-native target %q accepted loopback: %v", target, err)
		}
	}
	t.Setenv("CONTROL_UPGRADE_TARGET", string(controlplaneupgrade.TargetNativeStandalone))
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_URL", "https://[::1]"+controlplaneupgradehttp.SystemdPlanSourcePath)
	if _, _, _, err := openHTTPPlanRuntime(installationID); err != nil {
		t.Fatalf("native IPv6 loopback configuration rejected: %v", err)
	}
	for _, address := range []string{"127.0.0.2", "0.0.0.0", "[::]", "10.0.0.1", "169.254.169.254", "[fd00::1]"} {
		t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_URL", "https://"+address+controlplaneupgradehttp.SystemdPlanSourcePath)
		if _, _, _, err := openHTTPPlanRuntime(installationID); !errors.Is(err, ErrHTTPPlanSourceInvalid) {
			t.Fatalf("non-approved native local address %q accepted: %v", address, err)
		}
	}
}
