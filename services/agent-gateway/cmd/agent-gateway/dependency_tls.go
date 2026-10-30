package main

import (
	"crypto/tls"
	"net/url"
)

// dependencyTLS is the TLS a bound standalone Gateway uses for the control
// host's Redis (rediss://) and NATS (tls:// or the wss:// websocket listener)
// (ADR 0013 §3.3, GW-09): the installation root CA verifies the control host
// and the Gateway's control client certificate (renewed in place) is its
// identity. nil for plaintext loopback URLs. Only bound Gateways use it
// (Compose/Helm keep their own dependency TLS).
func dependencyTLS(raw string, control *tls.Config) *tls.Config {
	parsed, err := url.Parse(raw)
	if err != nil || control == nil {
		return nil
	}
	switch parsed.Scheme {
	case "rediss", "wss", "tls":
	default:
		return nil
	}
	clientCertificate := control.GetClientCertificate
	if clientCertificate == nil && len(control.Certificates) > 0 {
		certificate := control.Certificates[0]
		clientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &certificate, nil }
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: control.RootCAs, ServerName: parsed.Hostname(),
		GetClientCertificate: clientCertificate}
}
