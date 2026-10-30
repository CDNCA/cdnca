package impersonation

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"

	"github.com/google/uuid"
)

const authorizationCodeBytes = 16 + sha256.Size

func authorizationCode(grantID uuid.UUID, key []byte) string {
	payload := make([]byte, authorizationCodeBytes)
	copy(payload, grantID[:])
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(grantID[:])
	copy(payload[16:], mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString(payload)
}

func parseAuthorizationCode(raw string, key []byte) (uuid.UUID, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) != authorizationCodeBytes {
		return uuid.Nil, ErrInvalidCode
	}
	grantID, err := uuid.FromBytes(decoded[:16])
	if err != nil || grantID == uuid.Nil {
		return uuid.Nil, ErrInvalidCode
	}
	expected := authorizationCode(grantID, key)
	if len(expected) != len(raw) || subtle.ConstantTimeCompare([]byte(expected), []byte(raw)) != 1 {
		return uuid.Nil, ErrInvalidCode
	}
	return grantID, nil
}

func codeDigest(raw string) [sha256.Size]byte {
	return sha256.Sum256([]byte(raw))
}

func validateCodeKey(key []byte) error {
	if len(key) < sha256.Size {
		return errors.New("impersonation authorization code key must contain at least 32 bytes")
	}
	return nil
}
