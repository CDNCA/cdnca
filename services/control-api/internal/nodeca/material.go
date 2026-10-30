package nodeca

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxMaterialFileBytes = 4 << 20

var ErrInvalidMaterial = errors.New("invalid node CA material")

// LoadSignerFromFiles builds the local file-backed signer. Managed KMS/HSM
// integrations can construct Signer directly with their crypto.Signer.
func LoadSignerFromFiles(certificateChainFile, privateKeyFile string) (*Signer, error) {
	chain, err := loadCertificateChain(certificateChainFile)
	if err != nil {
		return nil, err
	}
	privateKey, err := loadPrivateSigner(privateKeyFile)
	if err != nil {
		return nil, err
	}
	signer, err := NewSigner(privateKey, chain[0], chain)
	if err != nil {
		return nil, materialError("validate certificate chain and signing key")
	}
	return signer, nil
}

func loadCertificateChain(path string) ([]*x509.Certificate, error) {
	contents, err := readMaterialFile(path, false)
	if err != nil {
		return nil, materialError("read certificate chain")
	}
	defer clearMaterial(contents)

	chain := make([]*x509.Certificate, 0, maxChainDepth)
	for remaining := bytes.TrimSpace(contents); len(remaining) > 0; {
		if len(chain) == maxChainDepth {
			return nil, materialError("parse certificate chain")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, materialError("parse certificate chain")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, materialError("parse certificate chain")
		}
		chain = append(chain, certificate)
		remaining = bytes.TrimSpace(rest)
	}
	if len(chain) == 0 {
		return nil, materialError("parse certificate chain")
	}
	return chain, nil
}

func loadPrivateSigner(path string) (crypto.Signer, error) {
	contents, err := readMaterialFile(path, true)
	if err != nil {
		return nil, materialError("read private key")
	}
	defer clearMaterial(contents)

	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, materialError("parse private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clearMaterial(block.Bytes)
	if err != nil {
		return nil, materialError("parse private key")
	}
	privateKey, ok := parsed.(crypto.Signer)
	if !ok || isNil(privateKey) {
		return nil, materialError("parse private key")
	}
	return privateKey, nil
}

func readMaterialFile(path string, restricted bool) ([]byte, error) {
	if path == "" || strings.TrimSpace(path) != path {
		return nil, ErrInvalidMaterial
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidMaterial
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxMaterialFileBytes {
		return nil, ErrInvalidMaterial
	}
	if restricted && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrInvalidMaterial
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxMaterialFileBytes+1))
	if err != nil || len(contents) == 0 || len(contents) > maxMaterialFileBytes {
		clearMaterial(contents)
		return nil, ErrInvalidMaterial
	}
	return contents, nil
}

func materialError(stage string) error {
	return fmt.Errorf("%w: %s", ErrInvalidMaterial, stage)
}

func clearMaterial(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
