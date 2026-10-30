package edgepublishhttp

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestHMACCursorCodecBindingTamperAndRotation(t *testing.T) {
	oldKey := CursorKey{ID: "cursor-2026-06", Secret: bytes.Repeat([]byte{0x16}, 32)}
	newKey := CursorKey{ID: "cursor-2026-07", Secret: bytes.Repeat([]byte{0x17}, 32)}
	oldCodec := mustCursorCodec(t, oldKey)
	scopeID, rolloutID := uuid.New(), uuid.New()
	binding := CursorBinding{
		Audience: AudiencePlatform, ScopeID: scopeID, ResourceKind: CursorResourceDeployments,
		ResourceID: &rolloutID,
	}
	token, err := oldCodec.Encode(binding, "domain_cursor")
	if err != nil || token == "" || !cursorPattern.MatchString(token) {
		t.Fatalf("encoded cursor=%q error=%v", token, err)
	}
	inner, err := oldCodec.Decode(binding, token)
	if err != nil || inner != "domain_cursor" {
		t.Fatalf("decoded cursor=%q error=%v", inner, err)
	}
	if encoded, err := oldCodec.Encode(binding, ""); err != nil || encoded != "" {
		t.Fatalf("empty encoded cursor=%q error=%v", encoded, err)
	}
	if decoded, err := oldCodec.Decode(binding, ""); err != nil || decoded != "" {
		t.Fatalf("empty decoded cursor=%q error=%v", decoded, err)
	}

	otherScope, otherRollout := uuid.New(), uuid.New()
	wrongBindings := []CursorBinding{
		{Audience: AudienceTenant, ScopeID: scopeID, ResourceKind: CursorResourceDeployments, ResourceID: &rolloutID},
		{Audience: AudiencePlatform, ScopeID: otherScope, ResourceKind: CursorResourceDeployments, ResourceID: &rolloutID},
		{Audience: AudiencePlatform, ScopeID: scopeID, ResourceKind: CursorResourcePublications},
		{Audience: AudiencePlatform, ScopeID: scopeID, ResourceKind: CursorResourceDeployments, ResourceID: &otherRollout},
	}
	for _, wrong := range wrongBindings {
		if _, err := oldCodec.Decode(wrong, token); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("wrong binding %+v error=%v", wrong, err)
		}
	}
	tampered := token[:len(token)-1] + differentCursorCharacter(token[len(token)-1])
	if _, err := oldCodec.Decode(binding, tampered); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("tampered cursor error=%v", err)
	}

	rotatedCodec, err := NewHMACCursorCodec(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if inner, err := rotatedCodec.Decode(binding, token); err != nil || inner != "domain_cursor" {
		t.Fatalf("rotated codec old cursor=%q error=%v", inner, err)
	}
	newToken, err := rotatedCodec.Encode(binding, "new_domain_cursor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldCodec.Decode(binding, newToken); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("old codec accepted new key error=%v", err)
	}
	newOnly := mustCursorCodec(t, newKey)
	if _, err := newOnly.Decode(binding, token); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("retired key remained valid error=%v", err)
	}
}

func TestHMACCursorCodecRejectsInvalidConfiguration(t *testing.T) {
	valid := CursorKey{ID: "valid", Secret: bytes.Repeat([]byte{0x31}, 32)}
	invalid := []CursorKey{
		{},
		{ID: "bad key", Secret: bytes.Repeat([]byte{0x31}, 32)},
		{ID: "short", Secret: bytes.Repeat([]byte{0x31}, 31)},
		{ID: "long", Secret: bytes.Repeat([]byte{0x31}, 129)},
	}
	for _, key := range invalid {
		if _, err := NewHMACCursorCodec(key); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid key id=%q secret_length=%d error=%v", key.ID, len(key.Secret), err)
		}
	}
	if _, err := NewHMACCursorCodec(valid, valid); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("duplicate key error=%v", err)
	}
}

func mustCursorCodec(t *testing.T, active CursorKey, verificationKeys ...CursorKey) *HMACCursorCodec {
	t.Helper()
	codec, err := NewHMACCursorCodec(active, verificationKeys...)
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func differentCursorCharacter(current byte) string {
	if current == 'A' {
		return "B"
	}
	return "A"
}
