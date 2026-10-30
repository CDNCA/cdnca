// Command cdnca-ed25519 replaces the installers' OpenSSL Ed25519 calls with a
// static, standard-library-only implementation. See
// docs/install/ed25519-tool-security.md for the trust chain.
//
//	genkey OUT                       new 0600 PKCS#8 PEM private key
//	pubkey KEY [--der]               SPKI public key (PEM, or DER) on stdout
//	sign KEY MESSAGE                 64-byte raw signature on stdout
//	verify PUBLIC MESSAGE SIGNATURE  exit 0 if valid, 1 otherwise
//	check-public PUBLIC              exit 0 if PUBLIC is an Ed25519 SPKI PEM
//	--version                        tool identity
//
// Formats are byte-compatible with `openssl genpkey -algorithm ED25519`,
// `openssl pkey -pubout` and `openssl pkeyutl -rawin`.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

const (
	version       = "cdnca-ed25519 1"
	maxPEMBytes   = 4 << 10
	maxMessage    = 16 << 20
	privateHeader = "PRIVATE KEY"
	publicHeader  = "PUBLIC KEY"
)

var (
	// RFC 8410 fixed encodings: PKCS#8 OneAsymmetricKey v0 and SubjectPublicKeyInfo.
	pkcs8Prefix = []byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}
	spkiPrefix  = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	errInvalid  = errors.New("invalid input")
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	err := dispatch(args, stdout)
	if err == nil {
		return 0
	}
	if errors.Is(err, errUsage) {
		fmt.Fprintln(stderr, "usage: cdnca-ed25519 genkey OUT | pubkey KEY [--der] | sign KEY MESSAGE | verify PUBLIC MESSAGE SIGNATURE | check-public PUBLIC | --version")
		return 2
	}
	// Never echo inputs: messages and keys may be private.
	fmt.Fprintln(stderr, "cdnca-ed25519: "+err.Error())
	return 1
}

var errUsage = errors.New("usage")

func dispatch(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	switch command, rest := args[0], args[1:]; {
	case command == "--version" && len(rest) == 0:
		_, err := fmt.Fprintln(stdout, version)
		return err
	case command == "genkey" && len(rest) == 1:
		return generate(rest[0])
	case command == "pubkey" && (len(rest) == 1 || len(rest) == 2 && rest[1] == "--der"):
		key, err := readPrivate(rest[0])
		if err != nil {
			return err
		}
		der := append(append([]byte{}, spkiPrefix...), key.Public().(ed25519.PublicKey)...)
		if len(rest) == 2 {
			_, err = stdout.Write(der)
		} else {
			err = pem.Encode(stdout, &pem.Block{Type: publicHeader, Bytes: der})
		}
		return err
	case command == "sign" && len(rest) == 2:
		key, err := readPrivate(rest[0])
		if err != nil {
			return err
		}
		message, err := readLimited(rest[1], maxMessage, false)
		if err != nil {
			return err
		}
		_, err = stdout.Write(ed25519.Sign(key, message))
		return err
	case command == "verify" && len(rest) == 3:
		public, err := readPublic(rest[0])
		if err != nil {
			return err
		}
		message, err := readLimited(rest[1], maxMessage, false)
		if err != nil {
			return err
		}
		signature, err := readLimited(rest[2], ed25519.SignatureSize, false)
		if err != nil || len(signature) != ed25519.SignatureSize {
			return errInvalid
		}
		if !ed25519.Verify(public, message, signature) {
			return errors.New("signature verification failed")
		}
		return nil
	case command == "check-public" && len(rest) == 1:
		_, err := readPublic(rest[0])
		return err
	}
	return errUsage
}

func generate(path string) error {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der := append(append([]byte{}, pkcs8Prefix...), private.Seed()...)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("cannot create a new private key file")
	}
	if err = file.Chmod(0o600); err == nil {
		err = pem.Encode(file, &pem.Block{Type: privateHeader, Bytes: der})
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

// readLimited reads a regular file of at most limit bytes without following a
// final symlink. empty reports whether a zero-length file is acceptable.
func readLimited(path string, limit int64, empty bool) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errInvalid
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errInvalid
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit || len(data) == 0 && !empty {
		return nil, errInvalid
	}
	return data, nil
}

// decodePEM accepts exactly one block of the given type with nothing but
// whitespace around it, and returns its DER bytes.
func decodePEM(path, kind string) ([]byte, error) {
	data, err := readLimited(path, maxPEMBytes, false)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
		len(bytes.TrimSpace(data[:bytes.Index(data, []byte("-----BEGIN"))])) != 0 {
		return nil, errInvalid
	}
	return block.Bytes, nil
}

func readPrivate(path string) (ed25519.PrivateKey, error) {
	der, err := decodePEM(path, privateHeader)
	if err != nil || len(der) != len(pkcs8Prefix)+ed25519.SeedSize || !bytes.Equal(der[:len(pkcs8Prefix)], pkcs8Prefix) {
		return nil, errInvalid
	}
	return ed25519.NewKeyFromSeed(der[len(pkcs8Prefix):]), nil
}

func readPublic(path string) (ed25519.PublicKey, error) {
	der, err := decodePEM(path, publicHeader)
	if err != nil || len(der) != len(spkiPrefix)+ed25519.PublicKeySize || !bytes.Equal(der[:len(spkiPrefix)], spkiPrefix) {
		return nil, errInvalid
	}
	return ed25519.PublicKey(der[len(spkiPrefix):]), nil
}
