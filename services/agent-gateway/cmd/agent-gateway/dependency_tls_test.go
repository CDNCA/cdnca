package main

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

// GW-09: a bound standalone Gateway reaches the control host's Redis
// (rediss://) and NATS (wss:// websocket listener) over TLS with its control
// client certificate and the installation root CA.
func TestReadConfigAcceptsRemoteTLSDependencies(t *testing.T) {
	values := cloneEnvironment(validEnvironment())
	values["CDNCA_REDIS_URL"] = "rediss://cdnca-gateway:do-not-log@control.example.com:6380/0"
	values["CDNCA_NATS_URL"] = "wss://cdnca-gateway:do-not-log@control.example.com:4223"
	values["CDNCA_TELEMETRY_NATS_URL"] = "wss://control.example.com:4223"
	if _, err := readConfig(mapLookup(values)); err != nil {
		t.Fatalf("remote TLS dependencies rejected: %v", err)
	}
	values["CDNCA_TELEMETRY_NATS_URL"] = "ws://control.example.com:4223"
	if _, err := readConfig(mapLookup(values)); err == nil {
		t.Fatal("plaintext remote websocket telemetry accepted")
	}
	values["CDNCA_TELEMETRY_NATS_URL"] = "wss://control.example.com:4223"
	values["CDNCA_NATS_URL"] = "ws://cdnca-gateway:do-not-log@control.example.com:4223"
	if _, err := readConfig(mapLookup(values)); err == nil {
		t.Fatal("plaintext websocket command bus accepted")
	}
}

func TestDependencyTLSUsesControlClientIdentity(t *testing.T) {
	roots := x509.NewCertPool()
	called := false
	control := &tls.Config{RootCAs: roots, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		called = true
		return &tls.Certificate{}, nil
	}}
	for _, raw := range []string{"rediss://u:p@control.example.com:6380/0", "wss://control.example.com:4223", "tls://control.example.com:4222"} {
		got := dependencyTLS(raw, control)
		if got == nil || got.RootCAs != roots || got.ServerName != "control.example.com" || got.MinVersion != tls.VersionTLS12 {
			t.Fatalf("%s: dependency TLS = %+v", raw, got)
		}
		called = false
		if _, err := got.GetClientCertificate(nil); err != nil || !called {
			t.Fatalf("%s: client certificate callback not the control identity", raw)
		}
	}
	for _, raw := range []string{"redis://127.0.0.1:6379/0", "nats://127.0.0.1:4222"} {
		if dependencyTLS(raw, control) != nil {
			t.Fatalf("%s: plaintext loopback must keep the default dialer", raw)
		}
	}
}
