package gatewayregistry

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
)

// Binding token: gwt1.<gateway_id>.<root CA SHA-256 first 16 bytes, hex>.<secret>
// (ADR 0013 §3.2). The fingerprint lets the installer reject a control plane
// whose root CA differs (a hijacked address); the secret is 32 random bytes,
// base64url, stored only as its SHA-256.
const tokenPrefix = "gwt1"

type bindingToken struct {
	GatewayID   uuid.UUID
	Fingerprint string
	Secret      string
}

// RootFingerprint is the token's fingerprint of a root CA certificate DER.
func RootFingerprint(rootDER []byte) string {
	sum := sha256.Sum256(rootDER)
	return hex.EncodeToString(sum[:16])
}

func newBindingToken(gatewayID uuid.UUID, fingerprint string) (string, [32]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", [32]byte{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join([]string{tokenPrefix, gatewayID.String(), fingerprint, secret}, "."), sha256.Sum256([]byte(secret)), nil
}

func parseBindingToken(value string) (bindingToken, bool) {
	parts := strings.Split(value, ".")
	if len(value) > 256 || len(parts) != 4 || parts[0] != tokenPrefix {
		return bindingToken{}, false
	}
	id, err := uuid.Parse(parts[1])
	if err != nil || id == uuid.Nil || id.String() != parts[1] {
		return bindingToken{}, false
	}
	if fingerprint, err := hex.DecodeString(parts[2]); err != nil || len(fingerprint) != 16 || hex.EncodeToString(fingerprint) != parts[2] {
		return bindingToken{}, false
	}
	if secret, err := base64.RawURLEncoding.DecodeString(parts[3]); err != nil || len(secret) != 32 {
		return bindingToken{}, false
	}
	return bindingToken{GatewayID: id, Fingerprint: parts[2], Secret: parts[3]}, true
}

func secretMatches(secret string, stored []byte) bool {
	sum := sha256.Sum256([]byte(secret))
	return len(stored) == len(sum) && subtle.ConstantTimeCompare(sum[:], stored) == 1
}
