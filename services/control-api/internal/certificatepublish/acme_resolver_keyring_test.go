package certificatepublish

import (
	"bytes"
	"errors"
	"testing"
)

func TestACMEPublicationResolverKeyringReadsPreviousAndRejectsUnknown(t *testing.T) {
	fixture := newACMEResolverFixture(t)
	activeMaterial := bytes.Repeat([]byte{0xa5}, 32)
	previousMaterial := append([]byte(nil), acmeResolverTestKey...)
	resolver, err := NewACMEPublicationResolverKeyring(
		ACMEPublicationWrappingKey{ID: "acme-publication-kek-v2", Material: activeMaterial},
		ACMEPublicationWrappingKey{ID: acmeResolverTestKeyID, Material: previousMaterial},
	)
	if err != nil {
		t.Fatal(err)
	}
	clear(activeMaterial)
	clear(previousMaterial)
	plaintext, err := resolver(t.Context(), cloneACMERequest(fixture.request))
	if err != nil || !bytes.Equal(plaintext, fixture.privateDER) {
		t.Fatalf("previous key resolve error=%v", err)
	}
	clear(plaintext)

	activeOnly, err := NewACMEPublicationResolverKeyring(
		ACMEPublicationWrappingKey{ID: "acme-publication-kek-v2", Material: bytes.Repeat([]byte{0xa5}, 32)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err = activeOnly(t.Context(), cloneACMERequest(fixture.request)); !errors.Is(err, ErrACMEKeyResolution) || plaintext != nil {
		clear(plaintext)
		t.Fatalf("unknown key result=%d error=%v", len(plaintext), err)
	}
}

func TestACMEPublicationResolverKeyringRejectsUnsafeConfiguration(t *testing.T) {
	valid := func(id string, fill byte) ACMEPublicationWrappingKey {
		return ACMEPublicationWrappingKey{ID: id, Material: bytes.Repeat([]byte{fill}, 32)}
	}
	for name, build := range map[string]func() error{
		"missing active": func() error {
			_, err := NewACMEPublicationResolverKeyring(ACMEPublicationWrappingKey{})
			return err
		},
		"bad length": func() error {
			_, err := NewACMEPublicationResolverKeyring(ACMEPublicationWrappingKey{ID: "active", Material: make([]byte, 31)})
			return err
		},
		"duplicate": func() error {
			_, err := NewACMEPublicationResolverKeyring(valid("active", 1), valid("active", 2))
			return err
		},
		"too many": func() error {
			_, err := NewACMEPublicationResolverKeyring(
				valid("active", 1), valid("previous-1", 2), valid("previous-2", 3),
				valid("previous-3", 4), valid("previous-4", 5),
			)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := build(); !errors.Is(err, ErrACMEResolverConfig) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
