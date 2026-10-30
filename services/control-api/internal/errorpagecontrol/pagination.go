package errorpagecontrol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
)

type pageCursor struct {
	Version     int       `json:"v"`
	Endpoint    string    `json:"endpoint"`
	ActorKind   string    `json:"actor_kind"`
	ActorScope  uuid.UUID `json:"actor_scope"`
	TargetScope uuid.UUID `json:"target_scope"`
	CreatedAt   time.Time `json:"created_at"`
	ID          uuid.UUID `json:"id"`
}

func encodePageCursor(endpoint string, actor Actor, targetScope uuid.UUID, createdAt time.Time, id uuid.UUID) (string, error) {
	encoded, err := json.Marshal(pageCursor{
		Version: 1, Endpoint: endpoint, ActorKind: actor.ScopeKind, ActorScope: actor.ScopeID,
		TargetScope: targetScope, CreatedAt: createdAt.UTC(), ID: id,
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodePageCursor(encoded, endpoint string, actor Actor, targetScope uuid.UUID) (*pageCursor, error) {
	if encoded == "" {
		return nil, nil
	}
	if len(encoded) > 512 {
		return nil, ErrInvalidInput
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > 384 {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cursor pageCursor
	if err := decoder.Decode(&cursor); err != nil {
		return nil, ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || cursor.Version != 1 ||
		cursor.Endpoint != endpoint || cursor.ActorKind != actor.ScopeKind || cursor.ActorScope != actor.ScopeID ||
		cursor.TargetScope != targetScope || cursor.CreatedAt.IsZero() || cursor.ID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	return &cursor, nil
}
