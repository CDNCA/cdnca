package identityverificationissuerhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"
)

// listenerPEMConfig turns the file fixture into the PEM form the system
// settings page supplies.
func listenerPEMConfig(t *testing.T, config ListenerConfig) ListenerConfig {
	t.Helper()
	read := func(path string) []byte {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return contents
	}
	config.ServerCertificatePEM, config.ServerPrivateKeyPEM, config.ClientCAPEM =
		read(config.ServerCertificateFile), read(config.ServerPrivateKeyFile), read(config.ClientCAFile)
	config.ServerCertificateFile, config.ServerPrivateKeyFile, config.ClientCAFile = "", "", ""
	return config
}

// The TLS material may be given as PEM contents instead of files; the
// listener then enforces the same TLS 1.3 mutual authentication.
func TestListenerAcceptsPEMContents(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	_, clientCertificate, roots, files := listenerPKI(t, now)
	config := listenerPEMConfig(t, files)
	if err := CheckListenerConfig(config); err != nil {
		t.Fatalf("check PEM config: %v", err)
	}
	listener, err := NewListener(t.Context(), config, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- listener.Run(ctx) }()
	for deadline := time.Now().Add(time.Second); listener.Ready() != nil && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	clientConfig := func(certificates []tls.Certificate) *http.Client {
		return &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots,
			Certificates: certificates, Time: func() time.Time { return now },
		}}}
	}
	response, err := clientConfig([]tls.Certificate{clientCertificate}).Post("https://"+listener.Address()+IssuePath, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("verified response status = %d", response.StatusCode)
	}
	if response, err := clientConfig(nil).Post("https://"+listener.Address()+IssuePath, "application/json", nil); err == nil {
		_ = response.Body.Close()
		t.Fatal("request without a client certificate reached the handler")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("listener shutdown error = %v", err)
	}
}

// CheckListenerConfig runs every check of NewListener except binding, so a
// new configuration can be checked before the running listener is closed.
func TestCheckListenerConfigRejectsUnusableMaterial(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	_, _, _, files := listenerPKI(t, now)
	_, _, _, otherFiles := listenerPKI(t, now)
	pemConfig := listenerPEMConfig(t, files)
	other := listenerPEMConfig(t, otherFiles)
	if err := CheckListenerConfig(files); err != nil {
		t.Fatalf("check file config: %v", err)
	}
	for name, change := range map[string]func(*ListenerConfig){
		"file and PEM":        func(config *ListenerConfig) { config.ServerCertificateFile = files.ServerCertificateFile },
		"no client CA":        func(config *ListenerConfig) { config.ClientCAPEM = nil },
		"key of another cert": func(config *ListenerConfig) { config.ServerPrivateKeyPEM = other.ServerPrivateKeyPEM },
		"CA as server cert":   func(config *ListenerConfig) { config.ServerCertificatePEM = config.ClientCAPEM },
		"server cert as CA":   func(config *ListenerConfig) { config.ClientCAPEM = config.ServerCertificatePEM },
		"expiring server cert": func(config *ListenerConfig) {
			config.Clock = func() time.Time { return now.Add(23*time.Hour + 30*time.Minute) }
		},
		"oversized PEM":      func(config *ListenerConfig) { config.ClientCAPEM = make([]byte, maximumTLSMaterialBytes+1) },
		"bad listen address": func(config *ListenerConfig) { config.ListenAddress = "127.0.0.1" },
	} {
		config := pemConfig
		change(&config)
		if err := CheckListenerConfig(config); !errors.Is(err, ErrListenerInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
