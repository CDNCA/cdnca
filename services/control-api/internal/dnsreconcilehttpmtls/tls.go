package dnsreconcilehttpmtls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"time"
)

const maximumPEMFileBytes = 4 << 20

func tlsVersionConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
}

func loadTLS(config *Config, now func() time.Time) (*tls.Config, error) {
	if err := config.Validate(); err != nil || now == nil {
		return nil, ErrInvalidConfig
	}
	current := now()
	certificatePEM, err := readPEMFile(config.ServerCertificateFile, false)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	keyPEM, err := readPEMFile(config.ServerPrivateKeyFile, true)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	defer clear(keyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, ErrInvalidConfig
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.IsCA || current.Before(leaf.NotBefore) || !current.Add(config.MinimumCertificateValidity).Before(leaf.NotAfter) ||
		!allowsUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return nil, ErrInvalidConfig
	}
	if err := validateIncludedServerCertificateChain(certificate.Certificate, leaf, current); err != nil {
		return nil, err
	}
	certificate.Leaf = leaf
	clientCAs, err := loadClientCAs(config.ClientCAFile, current)
	if err != nil {
		return nil, err
	}
	tlsConfig := tlsVersionConfig()
	tlsConfig.Certificates = []tls.Certificate{certificate}
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = clientCAs
	tlsConfig.Time = now
	return tlsConfig, nil
}

func validateIncludedServerCertificateChain(rawChain [][]byte, leaf *x509.Certificate, now time.Time) error {
	child := leaf
	for _, rawIssuer := range rawChain[1:] {
		issuer, err := x509.ParseCertificate(rawIssuer)
		if err != nil || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) || child.CheckSignatureFrom(issuer) != nil {
			return ErrInvalidConfig
		}
		child = issuer
	}
	return nil
}

func readPEMFile(path string, private bool) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumPEMFileBytes || private && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrInvalidConfig
	}
	return io.ReadAll(io.LimitReader(file, maximumPEMFileBytes))
}

func loadClientCAs(path string, now time.Time) (*x509.CertPool, error) {
	contents, err := readPEMFile(path, false)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	pool := x509.NewCertPool()
	count := 0
	for remaining := bytes.TrimSpace(contents); len(remaining) > 0; {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrInvalidConfig
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return nil, ErrInvalidConfig
		}
		pool.AddCert(certificate)
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, ErrInvalidConfig
	}
	return pool, nil
}

func allowsUsage(certificate *x509.Certificate, required x509.ExtKeyUsage) bool {
	return len(certificate.ExtKeyUsage) == 0 || func() bool {
		for _, usage := range certificate.ExtKeyUsage {
			if usage == required || usage == x509.ExtKeyUsageAny {
				return true
			}
		}
		return false
	}()
}
