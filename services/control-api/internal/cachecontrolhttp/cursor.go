package cachecontrolhttp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

const (
	cursorVersion  = 1
	maxCursorBytes = 4096
)

type cursorCodec struct {
	key []byte
}

type pageCursor struct {
	Version          int        `json:"v"`
	Kind             string     `json:"kind"`
	ScopeID          uuid.UUID  `json:"scope_id"`
	SiteID           *uuid.UUID `json:"site_id,omitempty"`
	FilterSHA256     string     `json:"filter_sha256"`
	SnapshotRevision int64      `json:"snapshot_revision,omitempty"`
	BeforeRevision   int64      `json:"before_revision,omitempty"`
	SnapshotPosition int64      `json:"snapshot_position,omitempty"`
	BeforeCreatedAt  *time.Time `json:"before_created_at,omitempty"`
	BeforeID         *uuid.UUID `json:"before_id,omitempty"`
}

func newCursorCodec(key []byte) (cursorCodec, error) {
	if len(key) < 32 || len(key) > 128 {
		return cursorCodec{}, ErrInvalidRequest
	}
	return cursorCodec{key: bytes.Clone(key)}, nil
}

func (codec cursorCodec) encode(value pageCursor) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidStoreResponse
	}
	mac := hmac.New(sha256.New, codec.key)
	_, _ = mac.Write(payload)
	encoded := base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
	if len(encoded) > maxCursorBytes {
		return "", ErrInvalidStoreResponse
	}
	return encoded, nil
}

func (codec cursorCodec) decode(raw string, value *pageCursor) error {
	if raw == "" || len(raw) > maxCursorBytes || value == nil {
		return ErrInvalidRequest
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) <= sha256.Size {
		return ErrInvalidRequest
	}
	payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, codec.key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidRequest
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, payload) || value.Version != cursorVersion ||
		value.ScopeID == uuid.Nil || len(value.FilterSHA256) != sha256.Size*2 {
		return ErrInvalidRequest
	}
	return nil
}

func filterDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidRequest
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
