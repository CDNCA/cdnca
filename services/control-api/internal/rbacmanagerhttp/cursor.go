package rbacmanagerhttp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"github.com/google/uuid"
)

const (
	cursorVersion   = 2
	maxCursorBytes  = 4096
	minCursorKeyLen = 32
)

type cursorCodec struct {
	key []byte
}

type pageCursor struct {
	Version         int       `json:"v"`
	Kind            string    `json:"kind"`
	ScopeID         uuid.UUID `json:"scope_id"`
	FilterDigest    string    `json:"filter_sha256"`
	SnapshotVersion int64     `json:"snapshot_version"`
	AfterVersion    int64     `json:"after_version"`
	AfterID         uuid.UUID `json:"after_id"`
}

func newCursorCodec(key []byte) (cursorCodec, error) {
	if len(key) < minCursorKeyLen || len(key) > 128 {
		return cursorCodec{}, ErrInvalidRequest
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
	decodedSignature, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil {
		return ErrInvalidRequest
	}
	mac := hmac.New(sha256.New, codec.key)
	_, _ = mac.Write([]byte(payload))
	if !hmac.Equal(decodedSignature, mac.Sum(nil)) {
		return ErrInvalidRequest
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(payload)
	if err != nil || len(decoded) > 2048 {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidRequest
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, decoded) || destination.Version != cursorVersion ||
		destination.ScopeID == uuid.Nil || len(destination.FilterDigest) != sha256.Size*2 ||
		strings.ToLower(destination.FilterDigest) != destination.FilterDigest ||
		destination.SnapshotVersion < 1 || destination.AfterVersion < 1 ||
		destination.AfterVersion > destination.SnapshotVersion || destination.AfterID == uuid.Nil {
		return ErrInvalidRequest
	}
	if _, err := hex.DecodeString(destination.FilterDigest); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

func cursorFilterDigest(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
