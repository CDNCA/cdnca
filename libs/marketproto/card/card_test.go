package card

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, _, _ := ed25519.GenerateKey(rand.Reader)
	c := Card{MemberID: uuid.New(), SigningPublicKey: signPub, BoxPublicKey: make([]byte, 32), IssuedAt: 1}
	signed, err := Sign(c, "m1", priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(map[string]ed25519.PublicKey{"m1": pub}, signed)
	if err != nil || got.MemberID != c.MemberID {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := Verify(map[string]ed25519.PublicKey{"m2": pub}, signed); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(map[string]ed25519.PublicKey{"m1": other}, signed); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	signed.Payload = signed.Payload[:len(signed.Payload)-4] + "AAAA"
	if _, err := Verify(map[string]ed25519.PublicKey{"m1": pub}, signed); err == nil {
		t.Fatal("tampered payload accepted")
	}
}
