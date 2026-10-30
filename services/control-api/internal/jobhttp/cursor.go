package jobhttp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
)

const (
	cursorVersion         = 1
	cursorEnvelopeVersion = 1
	minimumCursorKeyBytes = 32
	maximumCursorKeyIDLen = 64
	cursorMACDomain       = "cdnca.jobhttp.cursor"
)

type cursorEnvelope struct {
	Version  int    `json:"v"`
	KeyID    string `json:"kid"`
	Endpoint string `json:"endpoint"`
	Payload  string `json:"payload"`
	MAC      string `json:"mac"`
}

type cursorCodec struct {
	activeKeyID string
	keys        map[string][]byte
}

type cursorScope struct {
	Kind ScopeKind `json:"kind"`
	ID   uuid.UUID `json:"id"`
}

type listCursor struct {
	Version      int         `json:"v"`
	Endpoint     string      `json:"endpoint"`
	Scope        cursorScope `json:"scope"`
	TenantID     *uuid.UUID  `json:"tenant_id,omitempty"`
	FilterTaskID *uuid.UUID  `json:"filter_task_id,omitempty"`
	States       []State     `json:"states,omitempty"`
	Kind         string      `json:"kind,omitempty"`
	Resource     string      `json:"resource,omitempty"`
	From         time.Time   `json:"from"`
	To           time.Time   `json:"to"`
	CreatedAt    time.Time   `json:"created_at"`
	TaskID       uuid.UUID   `json:"task_id"`
}

type attemptCursor struct {
	Version  int         `json:"v"`
	Endpoint string      `json:"endpoint"`
	Scope    cursorScope `json:"scope"`
	TaskID   uuid.UUID   `json:"task_id"`
	Attempt  uint32      `json:"attempt"`
}

type resultCursor struct {
	Version  int         `json:"v"`
	Endpoint string      `json:"endpoint"`
	Scope    cursorScope `json:"scope"`
	TaskID   uuid.UUID   `json:"task_id"`
	Ordinal  int         `json:"ordinal"`
}

func newCursorCodec(config ServiceConfig) (cursorCodec, error) {
	if !validCursorKeyID(config.ActiveCursorKeyID) || len(config.CursorKeys) == 0 {
		return cursorCodec{}, ErrInvalidRequest
	}
	keys := make(map[string][]byte, len(config.CursorKeys))
	for keyID, key := range config.CursorKeys {
		if !validCursorKeyID(keyID) || len(key) < minimumCursorKeyBytes {
			return cursorCodec{}, ErrInvalidRequest
		}
		keys[keyID] = slices.Clone(key)
	}
	if _, ok := keys[config.ActiveCursorKeyID]; !ok {
		return cursorCodec{}, ErrInvalidRequest
	}
	return cursorCodec{activeKeyID: config.ActiveCursorKeyID, keys: keys}, nil
}

func (codec cursorCodec) encode(endpoint string, value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidStoreResponse
	}
	envelope := cursorEnvelope{
		Version:  cursorEnvelopeVersion,
		KeyID:    codec.activeKeyID,
		Endpoint: endpoint,
		Payload:  base64.RawURLEncoding.EncodeToString(payload),
	}
	envelope.MAC = base64.RawURLEncoding.EncodeToString(codec.sign(envelope, payload))
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", ErrInvalidStoreResponse
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func (codec cursorCodec) decode(endpoint, encoded string, target any) error {
	if encoded == "" || len(encoded) > maximumCursorLen {
		return ErrInvalidRequest
	}
	envelopeJSON, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return ErrInvalidRequest
	}
	var envelope cursorEnvelope
	if err := decodeStrictJSON(envelopeJSON, &envelope); err != nil ||
		envelope.Version != cursorEnvelopeVersion || envelope.Endpoint != endpoint {
		return ErrInvalidRequest
	}
	key, ok := codec.keys[envelope.KeyID]
	if !ok {
		return ErrInvalidRequest
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 {
		return ErrInvalidRequest
	}
	providedMAC, err := base64.RawURLEncoding.DecodeString(envelope.MAC)
	if err != nil || len(providedMAC) != sha256.Size {
		return ErrInvalidRequest
	}
	expectedMAC := signCursor(key, envelope, payload)
	if !hmac.Equal(providedMAC, expectedMAC) {
		return ErrInvalidRequest
	}
	if err := decodeStrictJSON(payload, target); err != nil {
		return ErrInvalidRequest
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(payload, canonical) {
		return ErrInvalidRequest
	}
	return nil
}

func (codec cursorCodec) sign(envelope cursorEnvelope, payload []byte) []byte {
	return signCursor(codec.keys[envelope.KeyID], envelope, payload)
}

func signCursor(key []byte, envelope cursorEnvelope, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(cursorMACInput(envelope, payload))
	return mac.Sum(nil)
}

func cursorMACInput(envelope cursorEnvelope, payload []byte) []byte {
	input := appendCursorMACField(nil, []byte(cursorMACDomain))
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], uint32(envelope.Version))
	input = append(input, version[:]...)
	input = appendCursorMACField(input, []byte(envelope.KeyID))
	input = appendCursorMACField(input, []byte(envelope.Endpoint))
	binary.BigEndian.PutUint32(version[:], uint32(cursorVersion))
	input = append(input, version[:]...)
	return appendCursorMACField(input, payload)
}

func appendCursorMACField(input, field []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(field)))
	input = append(input, length[:]...)
	return append(input, field...)
}

func decodeStrictJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidRequest
	}
	return nil
}

func validCursorKeyID(value string) bool {
	if value == "" || len(value) > maximumCursorKeyIDLen {
		return false
	}
	for _, character := range []byte(value) {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func sameListBinding(cursor listCursor, scope ReadScope, request ListRequest) bool {
	return cursor.Version == cursorVersion && cursor.Endpoint == "jobs" &&
		cursor.Scope == cursorScope{Kind: scope.Kind, ID: scope.ID} &&
		equalUUIDPointers(cursor.TenantID, request.TenantID) && equalUUIDPointers(cursor.FilterTaskID, request.TaskID) && reflect.DeepEqual(cursor.States, request.States) &&
		cursor.Kind == request.Kind && cursor.Resource == request.Resource &&
		cursor.From.Equal(request.From) && cursor.To.Equal(request.To) &&
		!cursor.CreatedAt.IsZero() && cursor.TaskID != uuid.Nil
}

func equalUUIDPointers(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
