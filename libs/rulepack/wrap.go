package rulepack

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"github.com/cloudflare/circl/hpke"
)

// Content key wrapping (ADR 0007 §6.1): the license service wraps a pack
// version's CEK to the installation's X25519 encryption key (registered at
// activation, separate from the Ed25519 identity key); the control plane
// unwraps it and wraps it again to each node's artifact encryption key
// (node_artifact_encryption_keys). HPKE base mode with the suite the edge
// deployment artifacts already use (X25519 / HKDF-SHA256 / AES-256-GCM).
//
// The info binds the purpose, the recipient key and the sealed object, so a
// wrapped key only opens for that recipient and that installation's copy:
// a pack copied to another installation stays sealed. Encapsulation is
// derived from the CEK and the binding, so wrapping is deterministic (the
// catalog digest of a delivery is stable) without ever reusing an ephemeral
// key across recipients or objects.
const (
	WrapPurposeInstallation = "installation"
	WrapPurposeNode         = "node"

	wrapInfoDomain = "cdnca-rule-pack-cek-wrap/v1\x00"
	wrapSeedDomain = "cdnca-rule-pack-cek-wrap-seed/v1\x00"
	wrappedSize    = 32 + CEKSize + 16
)

var (
	// ErrKeyRejected: a wrapped key does not open with this recipient key
	// and binding (another installation's or node's copy, or tampered).
	ErrKeyRejected = errors.New("rule pack content key rejected")

	wrapSuite        = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	recipientPattern = regexp.MustCompile(`^x25519:[0-9a-f]{64}$`)
)

// WrapContext is what a wrapped CEK is bound to.
type WrapContext struct {
	Purpose        string
	RecipientKeyID string
	PackID         string
	Version        string
	SealedSHA256   string
}

// X25519KeyID is the key id of an X25519 public key ("x25519:" + hex
// SHA-256), the form node_artifact_encryption_keys uses.
func X25519KeyID(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return "x25519:" + hex.EncodeToString(digest[:])
}

// X25519PublicKey returns the public key of a raw X25519 private key.
func X25519PublicKey(privateKey []byte) ([]byte, error) {
	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid X25519 private key", ErrKeyRejected)
	}
	return key.PublicKey().Bytes(), nil
}

// WrapKey wraps cek to recipientPublicKey for context and returns the
// base64url (unpadded) wrapped key.
func WrapKey(recipientPublicKey, cek []byte, context WrapContext) (string, error) {
	if len(cek) != CEKSize || X25519KeyID(recipientPublicKey) != context.RecipientKeyID {
		return "", fmt.Errorf("%w: recipient key or content key is invalid", ErrKeyRejected)
	}
	info, err := wrapInfo(context)
	if err != nil {
		return "", err
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	recipient, err := scheme.UnmarshalBinaryPublicKey(recipientPublicKey)
	if err != nil {
		return "", fmt.Errorf("%w: recipient key", ErrKeyRejected)
	}
	sender, err := wrapSuite.NewSender(recipient, info)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeyRejected, err)
	}
	mac := hmac.New(sha256.New, cek)
	mac.Write([]byte(wrapSeedDomain))
	mac.Write(info)
	encapsulation, sealer, err := sender.Setup(bytes.NewReader(mac.Sum(nil)[:scheme.EncapsulationSeedSize()]))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeyRejected, err)
	}
	ciphertext, err := sealer.Seal(cek, info)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeyRejected, err)
	}
	return base64.RawURLEncoding.EncodeToString(append(encapsulation, ciphertext...)), nil
}

// UnwrapKey opens a wrapped CEK with the recipient's raw X25519 private
// key. The caller must clear the result after use.
func UnwrapKey(privateKey []byte, wrapped string, context WrapContext) ([]byte, error) {
	publicKey, err := X25519PublicKey(privateKey)
	if err != nil {
		return nil, err
	}
	if X25519KeyID(publicKey) != context.RecipientKeyID {
		return nil, fmt.Errorf("%w: wrapped for another recipient", ErrKeyRejected)
	}
	info, err := wrapInfo(context)
	if err != nil {
		return nil, err
	}
	wire, err := base64.RawURLEncoding.DecodeString(wrapped)
	if err != nil || len(wire) != wrappedSize || base64.RawURLEncoding.EncodeToString(wire) != wrapped {
		return nil, fmt.Errorf("%w: wrapped key is malformed", ErrKeyRejected)
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	receiverKey, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: recipient key", ErrKeyRejected)
	}
	receiver, err := wrapSuite.NewReceiver(receiverKey, info)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyRejected, err)
	}
	size := scheme.CiphertextSize()
	opener, err := receiver.Setup(wire[:size])
	if err != nil {
		return nil, fmt.Errorf("%w: encapsulation", ErrKeyRejected)
	}
	cek, err := opener.Open(wire[size:], info)
	if err != nil || len(cek) != CEKSize {
		return nil, fmt.Errorf("%w: does not open for this recipient and object", ErrKeyRejected)
	}
	return cek, nil
}

func wrapInfo(context WrapContext) ([]byte, error) {
	if context.Purpose != WrapPurposeInstallation && context.Purpose != WrapPurposeNode ||
		!recipientPattern.MatchString(context.RecipientKeyID) || !sha256Hex(context.SealedSHA256) {
		return nil, fmt.Errorf("%w: wrap context is incomplete", ErrKeyRejected)
	}
	if _, ok := packIDLayer(context.PackID); !ok || context.Version == "" || len(context.Version) > 64 {
		return nil, fmt.Errorf("%w: wrap context pack", ErrKeyRejected)
	}
	info := []byte(wrapInfoDomain)
	for _, field := range []string{context.Purpose, context.RecipientKeyID, context.PackID, context.Version, context.SealedSHA256} {
		info = binary.BigEndian.AppendUint32(info, uint32(len(field)))
		info = append(info, field...)
	}
	return info, nil
}
