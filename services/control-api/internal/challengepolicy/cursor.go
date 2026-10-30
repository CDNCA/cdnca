package challengepolicy

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
	cursorVersion     = 1
	cursorSort        = "created_at_desc,id_desc"
	minCursorKeyBytes = 32
	maxCursorKeyBytes = 128
)

type CursorCodec struct {
	audience string
	keyID    string
	key      []byte
}

type cursorPayload struct {
	Version        int        `json:"v"`
	KeyID          string     `json:"kid"`
	Audience       string     `json:"aud"`
	ActorScopeID   uuid.UUID  `json:"as"`
	ActorUserID    uuid.UUID  `json:"au"`
	ActorScopeKind string     `json:"ak"`
	TargetScopeID  uuid.UUID  `json:"ts"`
	SiteID         *uuid.UUID `json:"si,omitempty"`
	Host           string     `json:"ho,omitempty"`
	Enabled        *bool      `json:"en,omitempty"`
	Limit          int        `json:"li"`
	Sort           string     `json:"so"`
	CreatedAt      time.Time  `json:"at"`
	ID             uuid.UUID  `json:"id"`
}

func NewCursorCodec(audience, keyID string, key []byte) (*CursorCodec, error) {
	audience = strings.TrimSpace(audience)
	keyID = strings.TrimSpace(keyID)
	if !metadataPattern.MatchString(audience) || !metadataPattern.MatchString(keyID) ||
		len(key) < minCursorKeyBytes || len(key) > maxCursorKeyBytes {
		return nil, ErrInvalidCursorConfig
	}
	return &CursorCodec{audience: audience, keyID: keyID, key: append([]byte(nil), key...)}, nil
}

func (codec *CursorCodec) encode(actor Actor, filter ListFilter, cursor pageCursor) (string, error) {
	if codec == nil || cursor.CreatedAt.IsZero() || cursor.ID == uuid.Nil {
		return "", ErrUnavailable
	}
	payload := cursorPayload{
		Version: cursorVersion, KeyID: codec.keyID, Audience: codec.audience,
		ActorScopeID: actor.ScopeID, ActorUserID: actor.UserID, ActorScopeKind: actor.ScopeKind,
		TargetScopeID: filter.TargetScopeID, Host: filter.Host, Limit: filter.Limit,
		Sort: cursorSort, CreatedAt: cursor.CreatedAt.UTC(), ID: cursor.ID,
	}
	if filter.SiteID != uuid.Nil {
		siteID := filter.SiteID
		payload.SiteID = &siteID
	}
	if filter.Enabled != nil {
		enabled := *filter.Enabled
		payload.Enabled = &enabled
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", ErrUnavailable
	}
	encoded := codec.sign(raw)
	if len(encoded) > maxCursorBytes {
		return "", ErrUnavailable
	}
	return encoded, nil
}

func (codec *CursorCodec) decode(encoded string, actor Actor, filter ListFilter) (*pageCursor, error) {
	if codec == nil {
		return nil, ErrInvalidInput
	}
	if encoded == "" {
		return nil, nil
	}
	if len(encoded) > maxCursorBytes || strings.Count(encoded, ".") != 1 {
		return nil, ErrInvalidInput
	}
	parts := strings.SplitN(encoded, ".", 2)
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(raw) == 0 || len(raw) > maxCursorBytes || rejectDuplicateKeys(raw) != nil {
		return nil, ErrInvalidInput
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size || !hmac.Equal(signature, codec.signature(raw)) {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload cursorPayload
	if err := decoder.Decode(&payload); err != nil {
		return nil, ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidInput
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, raw) || !payload.matches(codec, actor, filter) {
		return nil, ErrInvalidInput
	}
	return &pageCursor{CreatedAt: payload.CreatedAt, ID: payload.ID}, nil
}

func (payload cursorPayload) matches(codec *CursorCodec, actor Actor, filter ListFilter) bool {
	if payload.Version != cursorVersion || payload.KeyID != codec.keyID || payload.Audience != codec.audience ||
		payload.ActorScopeID != actor.ScopeID || payload.ActorUserID != actor.UserID ||
		payload.ActorScopeKind != actor.ScopeKind || payload.TargetScopeID != filter.TargetScopeID ||
		payload.Host != filter.Host || payload.Limit != filter.Limit || payload.Sort != cursorSort ||
		payload.CreatedAt.IsZero() || payload.ID == uuid.Nil {
		return false
	}
	if (payload.SiteID == nil) != (filter.SiteID == uuid.Nil) ||
		(payload.SiteID != nil && *payload.SiteID != filter.SiteID) ||
		(payload.Enabled == nil) != (filter.Enabled == nil) ||
		(payload.Enabled != nil && *payload.Enabled != *filter.Enabled) {
		return false
	}
	return true
}

func (codec *CursorCodec) sign(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw) + "." +
		base64.RawURLEncoding.EncodeToString(codec.signature(raw))
}

func (codec *CursorCodec) signature(raw []byte) []byte {
	mac := hmac.New(sha256.New, codec.key)
	_, _ = mac.Write(raw)
	return mac.Sum(nil)
}
