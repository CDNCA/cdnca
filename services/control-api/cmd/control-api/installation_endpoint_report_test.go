package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func endpointCLIRequest() installationEndpointRequest {
	return installationEndpointRequest{Schema: installationEndpointSchema,
		RequestID: "22222222-2222-4222-8222-222222222222", InstallationID: "11111111-1111-4111-8111-111111111111",
		ControlURL: "https://control.example.com:8443", GatewayHost: "gateway.example.com", EnrollmentPort: 19443, ControlPort: 19444,
		ObservedAt: "2026-10-08T00:00:00Z"}
}

func TestInstallationEndpointCLIDispatch(t *testing.T) {
	err := run([]string{"report-installation-endpoints", "--license-service", "http://authorization.example", "--installation-key", "unused", "--request-file", "unused"})
	if err == nil || err.Error() != "authorization server must be an HTTPS origin without credentials or path" {
		t.Fatalf("endpoint report command did not reach its validator: %v", err)
	}
}

func TestInstallationEndpointCLIProofAndStrictInput(t *testing.T) {
	request := endpointCLIRequest()
	if got := hex.EncodeToString(installationEndpointProofMessage(request)); got != "166bc6cc94fe097fdeca2467043ebdfc8ac4c12f555288f363c70d60d4913eef" {
		t.Fatalf("proof vector=%s", got)
	}
	for _, body := range []string{`{"schema":"a","schema":"b"}`, `{"schema":null}`, `{} {}`, `{"unknown":"secret"}`, `[]`} {
		var value installationEndpointRequest
		if decodeInstallationEndpointJSON([]byte(body), &value) == nil {
			t.Fatalf("accepted malformed JSON %s", body)
		}
	}
	for name, mutate := range map[string]func(*installationEndpointRequest){
		"http":                func(r *installationEndpointRequest) { r.ControlURL = "http://control.example.com" },
		"userinfo":            func(r *installationEndpointRequest) { r.ControlURL = "https://secret@control.example.com" },
		"path":                func(r *installationEndpointRequest) { r.ControlURL += "/path" },
		"query":               func(r *installationEndpointRequest) { r.ControlURL += "?token=secret" },
		"gateway credentials": func(r *installationEndpointRequest) { r.GatewayHost = "secret@gateway.example.com" },
		"date":                func(r *installationEndpointRequest) { r.ObservedAt = "2026-02-30T00:00:00Z" },
		"timezone":            func(r *installationEndpointRequest) { r.ObservedAt = "2026-10-08T08:00:00+08:00" },
		"uuid":                func(r *installationEndpointRequest) { r.RequestID = "other" },
		"port":                func(r *installationEndpointRequest) { r.ControlPort = 65536 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := request
			mutate(&invalid)
			if validateInstallationEndpointRequest(invalid) == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestInstallationEndpointCLISignedTransportAndReceipt(t *testing.T) {
	request := endpointCLIRequest()
	request.ObservedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/activation/v1/installations/"+request.InstallationID+"/endpoints:report" || r.Header.Get("Idempotency-Key") != request.RequestID {
			t.Error("wrong path or request binding")
		}
		var body struct {
			installationEndpointRequest
			Signature string `json:"signature"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.installationEndpointRequest != request {
			t.Error("wrong report body")
		}
		signature, err := base64.RawURLEncoding.DecodeString(body.Signature)
		if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), installationEndpointProofMessage(request), signature) {
			t.Error("invalid installation proof")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			installationEndpointRequest
			ReceivedAt string `json:"received_at"`
		}{request, time.Now().UTC().Format(time.RFC3339Nano)})
	}))
	defer server.Close()
	for index := 0; index < 2; index++ {
		if err := reportInstallationEndpoints(t.Context(), server.Client(), server.URL, request, key); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestInstallationEndpointCLIRejectsRedirectAndMismatchedReceipt(t *testing.T) {
	request := endpointCLIRequest()
	request.ObservedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	for name, reply := range map[string]func(http.ResponseWriter){
		"redirect": func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://secret.invalid/path?token=secret")
			w.WriteHeader(http.StatusTemporaryRedirect)
		},
		"HTML": func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>ok</html>")) },
		"other request": func(w http.ResponseWriter) {
			body := request
			body.RequestID = "33333333-3333-4333-8333-333333333333"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				installationEndpointRequest
				ReceivedAt string `json:"received_at"`
			}{body, request.ObservedAt})
		},
		"old date": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				installationEndpointRequest
				ReceivedAt string `json:"received_at"`
			}{request, "2000-01-01T00:00:00Z"})
		},
		"expired": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"request_expired","secret":"hidden"}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reply(w) }))
			defer server.Close()
			err := reportInstallationEndpoints(t.Context(), server.Client(), server.URL, request, key)
			if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "hidden") {
				t.Fatalf("unsafe or missing error=%v", err)
			}
			if name == "expired" && !strings.Contains(err.Error(), "--refresh-request") {
				t.Fatal("missing explicit recovery instruction")
			}
		})
	}
}

func TestInstallationEndpointCLIPrivateRequestFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "request.json")
	body, _ := json.Marshal(endpointCLIRequest())
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--license-service", "https://auth.example.com", "--installation-key", filepath.Join(directory, "absent.key"), "--request-file", path}
	if err := runReportInstallationEndpoints(args); err == nil || !strings.Contains(err.Error(), "private regular file") {
		t.Fatalf("world-readable=%v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "request-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	args[len(args)-1] = link
	if err := runReportInstallationEndpoints(args); err == nil || !strings.Contains(err.Error(), "private regular file") {
		t.Fatalf("symlink=%v", err)
	}
}

func TestInstallationEndpointCLIRefreshIsExplicitAndKeepsRecoveryRequest(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "request.json")
	keyPath := filepath.Join(directory, "installation.key")
	controlUpgradeWritePrivateKey(t, keyPath, 9)
	original := endpointCLIRequest()
	original.ObservedAt = time.Now().UTC().Add(-25 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	body, _ := json.Marshal(original)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	args := []string{"--license-service", server.URL, "--installation-key", keyPath, "--request-file", path}
	if err := runReportInstallationEndpoints(args); err == nil {
		t.Fatal("untrusted TLS unexpectedly accepted")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, body) {
		t.Fatal("failed ordinary retry rewrote the persistent request")
	}
	if err := runReportInstallationEndpoints(append(args, "--refresh-request")); err == nil {
		t.Fatal("untrusted TLS unexpectedly accepted")
	}
	preserved, err := os.ReadFile(path + "." + original.RequestID + ".previous")
	if err != nil || !bytes.Equal(preserved, body) {
		t.Fatal("explicit refresh lost the original recovery request")
	}
	refreshed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var current installationEndpointRequest
	if err := decodeInstallationEndpointJSON(refreshed, &current); err != nil {
		t.Fatal(err)
	}
	if current.RequestID == original.RequestID || current.ObservedAt == original.ObservedAt || current.ControlURL != original.ControlURL || current.InstallationID != original.InstallationID {
		t.Fatal("refreshed request changed identity/addresses or retained stale identity")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("refreshed file is not private")
	}
}
