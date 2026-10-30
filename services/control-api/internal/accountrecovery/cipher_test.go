package accountrecovery

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestDispatchEnvelopeSupportsRotationAndRejectsTampering(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x11}, 32)
	newKey := bytes.Repeat([]byte{0x22}, 32)
	oldRing, err := newDispatchKeyring("old", map[string][]byte{"old": oldKey}, bytes.NewReader(bytes.Repeat([]byte{0x33}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("sealed-recovery-token")
	aad := []byte("immutable-claim-aad")
	keyID, wrapped, sealed, aadHash, err := oldRing.seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if keyID != "old" || aadHash != sha256.Sum256(aad) || bytes.Contains(wrapped, plaintext) || bytes.Contains(sealed, plaintext) {
		t.Fatal("dispatch envelope metadata or confidentiality invariant failed")
	}

	rotated, err := newDispatchKeyring("new", map[string][]byte{
		"old": oldKey,
		"new": newKey,
	}, bytes.NewReader(bytes.Repeat([]byte{0x44}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := rotated.open(keyID, wrapped, sealed, aad)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("open old envelope after rotation: plaintext_match=%t error=%v", bytes.Equal(opened, plaintext), err)
	}
	clear(opened)

	for name, mutate := range map[string]func([]byte, []byte, []byte) ([]byte, []byte, []byte){
		"wrapped key": func(wrapped, sealed, aad []byte) ([]byte, []byte, []byte) {
			wrapped[20] ^= 0xff
			return wrapped, sealed, aad
		},
		"sealed token": func(wrapped, sealed, aad []byte) ([]byte, []byte, []byte) {
			sealed[20] ^= 0xff
			return wrapped, sealed, aad
		},
		"aad": func(wrapped, sealed, aad []byte) ([]byte, []byte, []byte) {
			aad[0] ^= 0xff
			return wrapped, sealed, aad
		},
	} {
		t.Run(name, func(t *testing.T) {
			changedWrapped, changedSealed, changedAAD := mutate(bytes.Clone(wrapped), bytes.Clone(sealed), bytes.Clone(aad))
			if _, err := rotated.open(keyID, changedWrapped, changedSealed, changedAAD); !errors.Is(err, ErrDispatchUnavailable) {
				t.Fatalf("tampered envelope error = %v", err)
			}
		})
	}
}

func TestDispatchKeyringRejectsInvalidConfiguration(t *testing.T) {
	valid := bytes.Repeat([]byte{0x55}, 32)
	for _, test := range []struct {
		active string
		keys   map[string][]byte
	}{
		{"", map[string][]byte{"key": valid}},
		{"missing", map[string][]byte{"key": valid}},
		{"key", map[string][]byte{"key": []byte("short")}},
		{"bad key", map[string][]byte{"bad key": valid}},
	} {
		if _, err := NewDispatchKeyring(test.active, test.keys); !errors.Is(err, ErrDispatchUnavailable) {
			t.Fatalf("NewDispatchKeyring(%q) error = %v", test.active, err)
		}
	}
}
