// Package dyntls is the node side of the dynamic routing TLS entry (D4,
// docs/edge/dynroute-tls.md): the worker-readable certificate pool that
// edge/openresty/dynroute/cdnca_tls.lua reads in ssl_certificate_by_lua, the
// OCSP responses stapled from it, and the shared servers' placeholder
// certificate.
//
// Pool layout (one flat directory, 0750, files 0440, group = the worker
// group; the same trade as v7's lazy certificate pool: the workers can read
// private keys, they never list the directory's other tenants by name only):
//
//	<root>/<certificate version>.crt   certificate chain PEM, leaf first
//	<root>/<certificate version>.key   private key PEM
//	<root>/<certificate version>.ocsp  DER OCSP response (optional, replaced)
//
// A version's .crt/.key never change (a new certificate is a new version);
// PutCertificate refuses different content under an existing version. The
// .ocsp file is replaced atomically when a fresher response arrives; Lua
// rereads it at most every ocsp_refresh seconds.
package dyntls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

var ErrInvalid = errors.New("dynamic TLS: invalid input")

// PlaceholderName is the only name of the placeholder certificate: a client
// that ever sees it means the certificate phase failed open.
const PlaceholderName = "fallback.invalid"

const (
	MaxChainBytes = 128 << 10 // certstore.MaxCertificateBytes
	MaxKeyBytes   = 32 << 10  // certstore.MaxPrivateKeyBytes
	MaxOCSPBytes  = 64 << 10
)

var versionPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Pool is the certificate pool directory. GID < 0 keeps the process group.
type Pool struct {
	Root string
	GID  int
}

func (pool Pool) path(version, suffix string) string {
	return filepath.Join(pool.Root, version+suffix)
}

func (pool Pool) ensureRoot() error {
	info, err := os.Lstat(pool.Root)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(pool.Root, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	case err != nil:
		return err
	case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
		return fmt.Errorf("%w: %s is not a directory", ErrInvalid, pool.Root)
	}
	return pool.apply(pool.Root, 0o750)
}

func (pool Pool) apply(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if pool.GID >= 0 {
		return os.Lchown(path, -1, pool.GID)
	}
	return nil
}

func (pool Pool) write(name string, content []byte) error {
	temp, err := os.CreateTemp(pool.Root, "."+name+".tmp-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := pool.apply(tempPath, 0o440); err != nil {
		return err
	}
	return os.Rename(tempPath, filepath.Join(pool.Root, name))
}

// ParseChain checks a certificate chain PEM (leaf first) and its private
// key: both parse, the key is the leaf's, nothing but CERTIFICATE blocks in
// the chain. It returns the leaf and, when present, its issuer.
func ParseChain(chainPEM, keyPEM []byte) (*x509.Certificate, *x509.Certificate, error) {
	if len(chainPEM) == 0 || len(chainPEM) > MaxChainBytes || len(keyPEM) == 0 || len(keyPEM) > MaxKeyBytes {
		return nil, nil, fmt.Errorf("%w: certificate or key size", ErrInvalid)
	}
	var chain []*x509.Certificate
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("%w: chain holds a %s block", ErrInvalid, block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: chain: %v", ErrInvalid, err)
		}
		chain = append(chain, certificate)
	}
	if len(chain) == 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, fmt.Errorf("%w: chain is not PEM certificates only", ErrInvalid)
	}
	keyBlock, keyRest := pem.Decode(keyPEM)
	if keyBlock == nil || len(bytes.TrimSpace(keyRest)) != 0 {
		return nil, nil, fmt.Errorf("%w: private key PEM", ErrInvalid)
	}
	key, err := parsePrivateKey(keyBlock)
	if err != nil {
		return nil, nil, err
	}
	if !publicKeyMatches(chain[0].PublicKey, key.Public()) {
		return nil, nil, fmt.Errorf("%w: private key does not match the leaf certificate", ErrInvalid)
	}
	var issuer *x509.Certificate
	if len(chain) > 1 {
		issuer = chain[1]
	}
	return chain[0], issuer, nil
}

func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	var parsed any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: private key block %s", ErrInvalid, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: private key: %v", ErrInvalid, err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: private key type", ErrInvalid)
	}
	return signer, nil
}

func publicKeyMatches(certificate, key crypto.PublicKey) bool {
	switch public := certificate.(type) {
	case *ecdsa.PublicKey:
		return public.Equal(key)
	case *rsa.PublicKey:
		return public.Equal(key)
	case ed25519.PublicKey:
		return public.Equal(key)
	}
	return false
}

// PutCertificate stores a certificate version (idempotent; different content
// under an existing version is refused).
func (pool Pool) PutCertificate(version string, chainPEM, keyPEM []byte) error {
	if !versionPattern.MatchString(version) {
		return fmt.Errorf("%w: certificate version %q", ErrInvalid, version)
	}
	if _, _, err := ParseChain(chainPEM, keyPEM); err != nil {
		return err
	}
	if err := pool.ensureRoot(); err != nil {
		return err
	}
	// Key first: the .crt is what makes a version visible to a reader that
	// finds only one of the two (it caches the miss for negative_ttl).
	for _, file := range []struct {
		suffix  string
		content []byte
	}{{".key", keyPEM}, {".crt", chainPEM}} {
		existing, err := os.ReadFile(pool.path(version, file.suffix))
		switch {
		case err == nil && bytes.Equal(existing, file.content):
			continue
		case err == nil:
			return fmt.Errorf("%w: certificate version %s already holds other content", ErrInvalid, version)
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}
		if err := pool.write(version+file.suffix, file.content); err != nil {
			return err
		}
	}
	return nil
}

// PutOCSP replaces a version's stapled OCSP response. The response must be
// signed for the version's leaf by its issuer (the chain's second
// certificate, or issuer when given), say "good" and not be expired.
func (pool Pool) PutOCSP(version string, response []byte, issuer *x509.Certificate, now time.Time) error {
	if !versionPattern.MatchString(version) || len(response) == 0 || len(response) > MaxOCSPBytes {
		return fmt.Errorf("%w: OCSP response for %q", ErrInvalid, version)
	}
	chainPEM, err := os.ReadFile(pool.path(version, ".crt"))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(pool.path(version, ".key"))
	if err != nil {
		return err
	}
	leaf, chainIssuer, err := ParseChain(chainPEM, keyPEM)
	if err != nil {
		return err
	}
	if issuer == nil {
		issuer = chainIssuer
	}
	if issuer == nil {
		// nginx/ngx_lua validate a stapled response against the chain's
		// issuer: without one in the chain nothing can be stapled.
		return fmt.Errorf("%w: certificate version %s has no issuer in its chain", ErrInvalid, version)
	}
	parsed, err := ocsp.ParseResponseForCert(response, leaf, issuer)
	if err != nil {
		return fmt.Errorf("%w: OCSP response: %v", ErrInvalid, err)
	}
	if parsed.Status != ocsp.Good || !parsed.NextUpdate.IsZero() && !now.Before(parsed.NextUpdate) ||
		now.Before(parsed.ThisUpdate.Add(-5*time.Minute)) {
		return fmt.Errorf("%w: OCSP response is not good and current", ErrInvalid)
	}
	return pool.write(version+".ocsp", response)
}

// RemoveOCSP stops stapling for a version (absent is fine).
func (pool Pool) RemoveOCSP(version string) error {
	if !versionPattern.MatchString(version) {
		return fmt.Errorf("%w: certificate version %q", ErrInvalid, version)
	}
	if err := os.Remove(pool.path(version, ".ocsp")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Versions lists the versions with a certificate in the pool.
func (pool Pool) Versions() ([]string, error) {
	entries, err := os.ReadDir(pool.Root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var versions []string
	for _, entry := range entries {
		if version, ok := strings.CutSuffix(entry.Name(), ".crt"); ok && versionPattern.MatchString(version) {
			versions = append(versions, version)
		}
	}
	return versions, nil
}

// Retain removes every version not in keep (the certificate versions the
// current and the previous site index generation reference) with its key
// and OCSP response, and stale temporary files. It returns how many versions
// it removed.
func (pool Pool) Retain(keep []string) (int, error) {
	wanted := make(map[string]bool, len(keep))
	for _, version := range keep {
		wanted[version] = true
	}
	entries, err := os.ReadDir(pool.Root)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") && strings.Contains(name, ".tmp-") {
			_ = os.Remove(filepath.Join(pool.Root, name))
			continue
		}
		version, _, found := strings.Cut(name, ".")
		if !found || !versionPattern.MatchString(version) || wanted[version] {
			continue
		}
		if err := os.Remove(filepath.Join(pool.Root, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return len(removed), err
		}
		removed[version] = true
	}
	return len(removed), nil
}

// WritePlaceholder writes the shared servers' placeholder certificate and
// key (self-signed, CN and SAN fallback.invalid, ECDSA P-256) unless both
// files already hold a pair. nginx needs ssl_certificate on a TLS server and
// ngx_lua's certificate phase needs the server's SSL_CTX; cdnca_tls always
// replaces it, so it is never served.
func WritePlaceholder(certificatePath, keyPath string, gid int) error {
	if existingCert, err := os.ReadFile(certificatePath); err == nil {
		if existingKey, err := os.ReadFile(keyPath); err == nil {
			if leaf, _, err := ParseChain(existingCert, existingKey); err == nil && leaf.Subject.CommonName == PlaceholderName {
				return nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: PlaceholderName}, DNSNames: []string{PlaceholderName},
		NotBefore: time.Unix(0, 0).UTC(), NotAfter: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	for _, file := range []struct {
		path    string
		content []byte
	}{
		{keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
		{certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})},
	} {
		placeholder := Pool{Root: filepath.Dir(file.path), GID: gid}
		if err := placeholder.write(filepath.Base(file.path), file.content); err != nil {
			return err
		}
	}
	return nil
}
