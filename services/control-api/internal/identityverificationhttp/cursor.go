package identityverificationhttp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	cursorVersion   = 1
	maxCursorBytes  = 4096
	minCursorKeyLen = 32
)

var strictRawURLEncoding = base64.RawURLEncoding.Strict()

type cursorCodec struct {
	key []byte
}

type pageCursor struct {
	Version      int       `json:"v"`
	ScopeBinding string    `json:"scope"`
	Kind         string    `json:"kind,omitempty"`
	Status       string    `json:"status,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ID           uuid.UUID `json:"id"`
}

func newCursorCodec(key []byte) (cursorCodec, error) {
	if len(key) < minCursorKeyLen || len(key) > 128 {
		return cursorCodec{}, ErrInvalidService
	}
	return cursorCodec{key: bytes.Clone(key)}, nil
}

func (codec cursorCodec) encode(value pageCursor) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidStoreResponse
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, codec.key)
	_, _ = mac.Write([]byte(encoded))
	result := encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(result) > maxCursorBytes {
		return "", ErrInvalidStoreResponse
	}
	return result, nil
}

func (codec cursorCodec) decode(raw string, destination *pageCursor) error {
	if destination == nil || raw == "" || len(raw) > maxCursorBytes {
		return ErrInvalidRequest
	}
	payload, signature, ok := strings.Cut(raw, ".")
	if !ok || payload == "" || signature == "" || strings.Contains(signature, ".") {
		return ErrInvalidRequest
	}
	decodedSignature, err := strictRawURLEncoding.DecodeString(signature)
	if err != nil {
		return ErrInvalidRequest
	}
	mac := hmac.New(sha256.New, codec.key)
	_, _ = mac.Write([]byte(payload))
	if !hmac.Equal(decodedSignature, mac.Sum(nil)) {
		return ErrInvalidRequest
	}
	decoded, err := strictRawURLEncoding.DecodeString(payload)
	if err != nil || len(decoded) > 2048 {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	if destination.Version != cursorVersion || !validScopeBinding(destination.ScopeBinding) ||
		destination.ID == uuid.Nil || !validCursorTime(destination.CreatedAt) {
		return ErrInvalidRequest
	}
	return nil
}

func (codec cursorCodec) scopeBinding(scopeID uuid.UUID) string {
	mac := hmac.New(sha256.New, codec.key)
	_, _ = mac.Write([]byte("identity-verification-cursor-scope\x00"))
	_, _ = mac.Write(scopeID[:])
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validScopeBinding(value string) bool {
	decoded, err := strictRawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validCursorTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(value.UTC().Truncate(time.Microsecond))
}
