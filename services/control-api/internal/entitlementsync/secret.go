package entitlementsync

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxSecretBytes = 16 * 1024

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	encoded, err := readRestrictedFile(path)
	if err != nil {
		return nil, fmt.Errorf("read installation private key: %w", err)
	}
	defer clearBytes(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("installation private key must be one PKCS#8 PEM block")
	}
	defer clearBytes(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid installation private key")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("installation private key must be Ed25519")
	}
	return append(ed25519.PrivateKey(nil), privateKey...), nil
}

func ReadActivationCredential(path string, stdin io.Reader) (string, error) {
	var encoded []byte
	var err error
	if path == "-" {
		if stdin == nil {
			return "", errors.New("activation credential stdin is unavailable")
		}
		encoded, err = io.ReadAll(io.LimitReader(stdin, maxSecretBytes+1))
		if err != nil || len(encoded) > maxSecretBytes {
			return "", errors.New("read activation credential from stdin")
		}
	} else {
		encoded, err = readRestrictedFile(path)
		if err != nil {
			return "", fmt.Errorf("read activation credential file: %w", err)
		}
	}
	credential := strings.TrimSpace(string(encoded))
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(credential)
	clearBytes(encoded)
	defer clearBytes(decoded)
	if decodeErr != nil || len(decoded) != 32 {
		return "", errors.New("activation credential is invalid")
	}
	return credential, nil
}

func readRestrictedFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("secret file path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("secret file must be regular and inaccessible to group and other users")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maxSecretBytes {
		return nil, errors.New("secret file size is invalid")
	}
	return encoded, nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
