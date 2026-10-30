package controlgrpc

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxPEMFileBytes = 4 << 20

var ErrInvalidTLSMaterial = errors.New("invalid ControlInternal TLS material")

type stageError struct {
	stage string
	files []string
	cause error
}

func (e stageError) Error() string {
	if len(e.files) == 0 {
		return e.stage
	}
	return fmt.Sprintf("%s (%s)", e.stage, strings.Join(e.files, ", "))
}

func (e stageError) Unwrap() error { return e.cause }

func LoadTLS(config Config, now func() time.Time) (*tls.Config, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		return nil, invalidConfig("clock is required")
	}
	certificatePEM, err := readPEMFile(config.ServerCertificateFile, "read server certificate", false)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readPEMFile(config.ServerPrivateKeyFile, "read server private key", true)
	if err != nil {
		return nil, err
	}
	defer clearBytes(keyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, tlsMaterialError("parse server certificate and private key", config.ServerCertificateFile, config.ServerPrivateKeyFile)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, tlsMaterialError("parse server leaf certificate", config.ServerCertificateFile)
	}
	currentTime := now()
	if currentTime.IsZero() {
		return nil, invalidConfig("clock returned the zero time")
	}
	if leaf.IsCA || !hasExtendedKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return nil, tlsMaterialError("validate server certificate usage", config.ServerCertificateFile)
	}
	if currentTime.Before(leaf.NotBefore) || !currentTime.Add(config.MinimumCertificateValidity).Before(leaf.NotAfter) {
		return nil, tlsMaterialError("validate server certificate lifetime", config.ServerCertificateFile)
	}
	certificate.Leaf = leaf

	clientCAs, err := loadCAPool(config.GatewayClientCAFile, currentTime)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, nil
}

func readPEMFile(path, stage string, private bool) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, tlsMaterialError(stage, path)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPEMFileBytes {
		return nil, tlsMaterialError(stage, path)
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, tlsMaterialError("validate server private key permissions", path)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxPEMFileBytes+1))
	if err != nil || len(contents) == 0 || len(contents) > maxPEMFileBytes {
		return nil, tlsMaterialError(stage, path)
	}
	return contents, nil
}

func loadCAPool(path string, now time.Time) (*x509.CertPool, error) {
	contents, err := readPEMFile(path, "read Gateway client CA bundle", false)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	count := 0
	for remaining := bytes.TrimSpace(contents); len(remaining) > 0; {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, tlsMaterialError("parse Gateway client CA bundle", path)
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, tlsMaterialError("parse Gateway client CA bundle", path)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, tlsMaterialError("validate Gateway client CA bundle", path)
		}
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return nil, tlsMaterialError("validate Gateway client CA lifetime", path)
		}
		pool.AddCert(certificate)
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, tlsMaterialError("parse Gateway client CA bundle", path)
	}
	return pool, nil
}

func hasExtendedKeyUsage(certificate *x509.Certificate, required x509.ExtKeyUsage) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == required {
			return true
		}
	}
	return false
}

func tlsMaterialError(stage string, paths ...string) error {
	files := make([]string, 0, len(paths))
	for _, path := range paths {
		files = append(files, filepath.Base(path))
	}
	return stageError{stage: stage, files: files, cause: ErrInvalidTLSMaterial}
}

func clearBytes(contents []byte) {
	clear(contents)
}
