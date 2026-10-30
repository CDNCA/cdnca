package mfa

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"time"
)

const totpSecretBytes = 20

func generateTOTPSecret(random io.Reader) (string, []byte, error) {
	secret := make([]byte, totpSecretBytes)
	if _, err := io.ReadFull(random, secret); err != nil {
		return "", nil, fmt.Errorf("generate TOTP secret: %w", err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	return encoded, secret, nil
}

func decodeTOTPSecret(encoded string) []byte {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		return nil
	}
	return secret
}

func hotp(secret []byte, counter uint64, digits int) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := (uint32(digest[offset])&0x7f)<<24 |
		uint32(digest[offset+1])<<16 |
		uint32(digest[offset+2])<<8 |
		uint32(digest[offset+3])
	modulus := uint32(1)
	for range digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%modulus)
}

func matchTOTP(secret []byte, code string, now time.Time, step time.Duration, window, digits int) (uint64, bool) {
	if step < time.Second || window < 0 || digits < 6 || digits > 8 || len(code) != digits {
		return 0, false
	}
	if _, err := strconv.ParseUint(code, 10, 32); err != nil {
		return 0, false
	}
	current := now.Unix() / int64(step/time.Second)
	for offset := -window; offset <= window; offset++ {
		candidate := current + int64(offset)
		if candidate < 0 {
			continue
		}
		expected := hotp(secret, uint64(candidate), digits)
		if hmac.Equal([]byte(code), []byte(expected)) {
			return uint64(candidate), true
		}
	}
	return 0, false
}
