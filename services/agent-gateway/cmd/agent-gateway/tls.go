package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"
)

const maxPEMFileBytes = 4 << 20

func loadListenerTLS(c config) (*tls.Config, *tls.Config, error) {
	certificate, err := loadCertificate(c.serverCertificateFile, c.serverKeyFile, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, nil, stageError{stage: "load Gateway server certificate", err: err}
	}
	agentRoots, err := loadCAPool(c.agentClientCAFile)
	if err != nil {
		return nil, nil, stageError{stage: "load Agent client CA", err: err}
	}
	enrollment := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.NoClientCert,
	}
	agent := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    agentRoots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	return enrollment, agent, nil
}

// loadTunnelCertificate loads the optional public certificate presented on
// the outer TLS of the WebSocket tunnel paths (install-control.sh --mode
// gateway --server-cert/--server-key): what a CDN that verifies its origin
// sees. gRPC direct sessions and the inner tunnel TLS keep the certificate
// signed by the installation root CA, the only one nodes trust there. Public
// CA certificates often carry clientAuth too, so only serverAuth is required.
func loadTunnelCertificate(c config) (*tls.Certificate, error) {
	if c.tunnelCertificateFile == "" && c.tunnelKeyFile == "" {
		return nil, nil
	}
	certificatePEM, err := readRegularFile(c.tunnelCertificateFile, false)
	if err != nil {
		return nil, stageError{stage: "load public tunnel certificate", err: err}
	}
	keyPEM, err := readRegularFile(c.tunnelKeyFile, true)
	if err != nil {
		return nil, stageError{stage: "load public tunnel certificate", err: err}
	}
	defer clearBytes(keyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, stageError{stage: "load public tunnel certificate", err: fmt.Errorf("invalid certificate or private key")}
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, stageError{stage: "load public tunnel certificate", err: fmt.Errorf("invalid leaf certificate")}
	}
	now := time.Now()
	serverAuth := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || !serverAuth {
		return nil, stageError{stage: "load public tunnel certificate", err: fmt.Errorf("leaf certificate is not currently valid for server authentication")}
	}
	certificate.Leaf = leaf
	return &certificate, nil
}

func loadControlTLS(c config) (*tls.Config, error) {
	if !validWorkloadURISAN(c.controlClientWorkloadURISAN) {
		return nil, stageError{stage: "validate ControlInternal client workload identity", err: fmt.Errorf("configured workload identity is invalid")}
	}
	certificate, err := loadCertificate(c.controlCertificateFile, c.controlKeyFile, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, stageError{stage: "load ControlInternal client certificate", err: err}
	}
	if !matchesWorkloadURISAN(certificate.Leaf, c.controlClientWorkloadURISAN) {
		return nil, stageError{stage: "validate ControlInternal client workload identity", err: fmt.Errorf("client certificate workload identity mismatch")}
	}
	serverRoots, err := loadCAPool(c.controlServerCAFile)
	if err != nil {
		return nil, stageError{stage: "load ControlInternal server CA", err: err}
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      serverRoots,
		ServerName:   c.controlServerName,
	}, nil
}

func loadCertificate(certificateFile, keyFile string, usage x509.ExtKeyUsage) (tls.Certificate, error) {
	certificatePEM, err := readRegularFile(certificateFile, false)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := readRegularFile(keyFile, true)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clearBytes(keyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("invalid certificate or private key")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("invalid leaf certificate")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("leaf certificate is not currently valid")
	}
	if !allowsExtendedUsage(leaf, usage) {
		return tls.Certificate{}, fmt.Errorf("leaf certificate has the wrong extended key usage")
	}
	certificate.Leaf = leaf
	return certificate, nil
}

func allowsExtendedUsage(certificate *x509.Certificate, required x509.ExtKeyUsage) bool {
	return len(certificate.ExtKeyUsage) == 1 && certificate.ExtKeyUsage[0] == required
}

func loadCAPool(path string) (*x509.CertPool, error) {
	contents, err := readRegularFile(path, false)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(contents)) > 0 {
		block, rest := pem.Decode(contents)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("CA file must contain only PEM certificates")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("CA file contains an invalid CA certificate")
		}
		pool.AddCert(certificate)
		count++
		contents = rest
	}
	if count == 0 {
		return nil, fmt.Errorf("CA file contains no certificates")
	}
	return pool, nil
}

func readRegularFile(path string, private bool) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open required PEM file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPEMFileBytes {
		return nil, fmt.Errorf("required PEM path is not a bounded regular file")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key file permissions are too broad")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxPEMFileBytes+1))
	if err != nil || len(contents) == 0 || len(contents) > maxPEMFileBytes {
		return nil, fmt.Errorf("read required PEM file")
	}
	return contents, nil
}

func matchesWorkloadURISAN(certificate *x509.Certificate, expected string) bool {
	return certificate != nil && len(certificate.URIs) == 1 && certificate.URIs[0] != nil &&
		certificate.URIs[0].String() == expected
}

func clearBytes(contents []byte) {
	clear(contents)
}
