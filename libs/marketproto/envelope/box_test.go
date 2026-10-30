package envelope

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func boxKeys(t *testing.T) (private, public []byte) {
	t.Helper()
	private = make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return private, public
}

func TestBoxRoundTripAndBinding(t *testing.T) {
	const domain = "cdnca.test.box/v1"
	leafPrivate, leafPublic := boxKeys(t)
	otherPrivate, _ := boxKeys(t)
	secret := []byte(`{"secret_access_key":"s3cr3t-value"}`)
	b, err := SealBox(domain, secret, []byte("site=1"), leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.Ciphertext, []byte("s3cr3t-value")) {
		t.Fatal("ciphertext carries the plaintext")
	}
	got, err := OpenBox(domain, b, []byte("site=1"), leafPrivate)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("OpenBox = %q, %v", got, err)
	}
	if _, err := OpenBox(domain, b, []byte("site=1"), otherPrivate); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("another leaf's key opened the box: %v", err)
	}
	if _, err := OpenBox(domain, b, []byte("site=2"), leafPrivate); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("another aad opened the box: %v", err)
	}
	if _, err := OpenBox("cdnca.test.other/v1", b, []byte("site=1"), leafPrivate); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("another domain opened the box: %v", err)
	}
	again, _ := SealBox(domain, secret, []byte("site=1"), leafPublic)
	if bytes.Equal(again.Ciphertext, b.Ciphertext) || bytes.Equal(again.Ephemeral, b.Ephemeral) {
		t.Fatal("two seals share an ephemeral key")
	}
}

func TestBoxRejectsMalformed(t *testing.T) {
	_, public := boxKeys(t)
	if _, err := SealBox("", nil, nil, public); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty domain = %v", err)
	}
	if _, err := SealBox("d", nil, nil, public[:31]); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short key = %v", err)
	}
	private, _ := boxKeys(t)
	if _, err := OpenBox("d", Box{}, nil, private); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty box = %v", err)
	}
}

func TestBoxSeededIsDeterministic(t *testing.T) {
	const domain = "cdnca.test.box/v1"
	private, public := boxKeys(t)
	seed := [32]byte{1, 2, 3}
	a, err := SealBoxSeeded(seed, domain, []byte("secret"), []byte("aad"), public)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SealBoxSeeded(seed, domain, []byte("secret"), []byte("aad"), public)
	c, _ := SealBoxSeeded([32]byte{9}, domain, []byte("secret"), []byte("aad"), public)
	if !bytes.Equal(a.Ciphertext, b.Ciphertext) || !bytes.Equal(a.Ephemeral, b.Ephemeral) {
		t.Fatal("same seed sealed differently")
	}
	if bytes.Equal(a.Ephemeral, c.Ephemeral) {
		t.Fatal("another seed reused the ephemeral key")
	}
	if got, err := OpenBox(domain, a, []byte("aad"), private); err != nil || string(got) != "secret" {
		t.Fatalf("OpenBox = %q, %v", got, err)
	}
}
