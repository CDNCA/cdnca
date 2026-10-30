package entitlementsync

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// The installation encryption key (ADR 0007 §6.1, PA-14) is an X25519 key
// generated for this purpose only (never derived from the Ed25519 identity
// key). The license service wraps the content keys of encrypted rule packs
// to its public half; the private half stays in an owner-only file, never in
// the database.

// LoadEncryptionKey reads an owner-only PKCS#8 PEM X25519 private key and
// returns its raw 32 bytes.
func LoadEncryptionKey(path string) ([]byte, error) {
	encoded, err := readRestrictedFile(path)
	if err != nil {
		return nil, fmt.Errorf("read installation encryption key: %w", err)
	}
	defer clearBytes(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("installation encryption key must be one PKCS#8 PEM block")
	}
	defer clearBytes(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid installation encryption key")
	}
	key, ok := parsed.(*ecdh.PrivateKey)
	if !ok || key.Curve() != ecdh.X25519() {
		return nil, errors.New("installation encryption key must be X25519")
	}
	return key.Bytes(), nil
}

// GenerateEncryptionKey writes a new X25519 key to path (owner-only, the
// file must not exist) and returns its raw public key.
func GenerateEncryptionKey(path string) ([]byte, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clearBytes(der)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create installation encryption key: %w", err)
	}
	writeErr := pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("write installation encryption key: %w", writeErr)
	}
	return key.PublicKey().Bytes(), nil
}
