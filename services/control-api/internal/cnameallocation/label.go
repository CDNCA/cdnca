package cnameallocation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"strings"

	"github.com/google/uuid"
)

const labelDomainSeparator = "cdnca:cname-allocation:label:v1"

// LabelLength: generated labels are 8 chars of a-z0-9 (36^8 ≈ 2.8e12), still
// keyed by the HMAC so they cannot be guessed from tenant/site identity.
const LabelLength = 8

// MaxLabelAttempts bounds the collision retries of one allocation; past it the
// allocation fails with FailureLabelExhausted instead of silently reusing a name.
const MaxLabelAttempts = 16

func GenerateLabel(
	key Key,
	tenantID, providerID, ownerID uuid.UUID,
	mode Mode,
	domain string,
	generation uint64,
) (string, error) {
	domain = normalizeName(domain)
	if !validKey(key) || tenantID == uuid.Nil || providerID == uuid.Nil || ownerID == uuid.Nil ||
		!validMode(mode) || domain == "" || generation == 0 {
		return "", ErrInvalidInput
	}

	secret := append([]byte(nil), key.Secret...)
	defer clear(secret)
	mac := hmac.New(sha256.New, secret)
	writeLabelPart(mac, []byte(labelDomainSeparator))
	writeLabelPart(mac, []byte(key.ID))
	writeLabelPart(mac, tenantID[:])
	writeLabelPart(mac, providerID[:])
	writeLabelPart(mac, ownerID[:])
	writeLabelPart(mac, []byte(mode))
	writeLabelPart(mac, []byte(domain))
	var encodedGeneration [8]byte
	binary.BigEndian.PutUint64(encodedGeneration[:], generation)
	writeLabelPart(mac, encodedGeneration[:])

	return base36Prefix(mac.Sum(nil), LabelLength), nil
}

// base36Prefix returns the first n digits of digest in base36 (big-endian,
// big.Int.Text alphabet 0-9a-z). The leading digit of a 256-bit value ranges
// over 1..6, so 8 digits carry about 39 bits.
func base36Prefix(digest []byte, n int) string {
	encoded := new(big.Int).SetBytes(digest).Text(36)
	if len(encoded) < n {
		encoded = strings.Repeat("0", n-len(encoded)) + encoded
	}
	return encoded[:n]
}

type hashWriter interface {
	Write([]byte) (int, error)
}

func writeLabelPart(writer hashWriter, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(value)
}

func validKey(key Key) bool {
	return validKeyID(key.ID) && len(key.Secret) >= sha256.Size
}

func normalizeName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
