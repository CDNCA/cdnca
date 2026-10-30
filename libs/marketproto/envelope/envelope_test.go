package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

type member struct {
	id       uuid.UUID
	signPub  ed25519.PublicKey
	signPriv ed25519.PrivateKey
	boxPriv  []byte
	boxPub   []byte
}

func newMember(t *testing.T) member {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	boxPriv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(boxPriv); err != nil {
		t.Fatal(err)
	}
	boxPub, err := curve25519.X25519(boxPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return member{id: uuid.New(), signPub: pub, signPriv: priv, boxPriv: boxPriv, boxPub: boxPub}
}

func registry(members ...member) KeyLookup {
	return func(id uuid.UUID) (ed25519.PublicKey, error) {
		for _, m := range members {
			if m.id == id {
				return m.signPub, nil
			}
		}
		return nil, errors.New("unknown member")
	}
}

func header(from, to member) Header {
	return Header{
		Schema: SchemaV1, MessageID: uuid.New(), IdempotencyKey: "site-1:rev-7",
		SenderMemberID: from.id, RecipientMember: to.id, GrantID: uuid.New(),
		Operation: "supply.prepare_site", Domains: []string{"www.example.com"},
		ProtocolVersion: 1, CreatedAt: 1_800_000_000,
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	b, a := newMember(t), newMember(t)
	payload := []byte(`{"site":"config with private key"}`)
	sealed, err := Seal(header(b, a), payload, a.boxPub, b.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Ciphertext, []byte("private key")) {
		t.Fatal("payload visible in ciphertext")
	}
	got, opened, err := Open(sealed, registry(a, b), a.id, a.boxPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, payload) || got.Domains[0] != "www.example.com" {
		t.Fatalf("round trip mismatch")
	}
}

func TestRelayInspectSeesHeaderButCannotDecrypt(t *testing.T) {
	b, a, relayMember := newMember(t), newMember(t), newMember(t)
	sealed, err := Seal(header(b, a), []byte("secret"), a.boxPub, b.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	h, err := Inspect(sealed, registry(a, b))
	if err != nil || h.SenderMemberID != b.id {
		t.Fatalf("inspect: %v", err)
	}
	if _, _, err := Open(sealed, registry(a, b), a.id, relayMember.boxPriv); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong private key: want ErrDecrypt, got %v", err)
	}
}

func TestOpenRejectsMisaddressed(t *testing.T) {
	b, a, c := newMember(t), newMember(t), newMember(t)
	sealed, err := Seal(header(b, a), []byte("x"), a.boxPub, b.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(sealed, registry(a, b, c), c.id, a.boxPriv); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	b, a := newMember(t), newMember(t)
	fresh := func() Sealed {
		s, err := Seal(header(b, a), []byte("payload"), a.boxPub, b.signPriv)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	headerSwap := fresh()
	forged := header(b, a)
	forged.Domains = []string{"other.example.com"}
	other, _ := Seal(forged, []byte("payload"), a.boxPub, b.signPriv)
	headerSwap.HeaderBytes = other.HeaderBytes

	cipherFlip := fresh()
	cipherFlip.Ciphertext[0] ^= 1

	for name, s := range map[string]Sealed{"header swap": headerSwap, "ciphertext flip": cipherFlip} {
		if _, err := Inspect(s, registry(a, b)); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: want ErrSignature, got %v", name, err)
		}
	}
}

func TestImpersonationRejected(t *testing.T) {
	b, a, mallory := newMember(t), newMember(t), newMember(t)
	// Mallory signs a header claiming to be B.
	sealed, err := Seal(header(b, a), []byte("x"), a.boxPub, mallory.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(sealed, registry(a, b, mallory)); !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestLowOrderRecipientKeyRejected(t *testing.T) {
	b := newMember(t)
	zero := make([]byte, curve25519.PointSize)
	h := header(b, newMember(t))
	if _, err := Seal(h, []byte("x"), zero, b.signPriv); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestHeaderValidation(t *testing.T) {
	b, a := newMember(t), newMember(t)
	cases := map[string]func(*Header){
		"self send":  func(h *Header) { h.RecipientMember = h.SenderMemberID },
		"operation":  func(h *Header) { h.Operation = "Bad Op" },
		"idempotent": func(h *Header) { h.IdempotencyKey = "" },
		"version":    func(h *Header) { h.ProtocolVersion = 0 },
		"domain":     func(h *Header) { h.Domains = []string{""} },
	}
	for name, mutate := range cases {
		h := header(b, a)
		mutate(&h)
		if _, err := Seal(h, nil, a.boxPub, b.signPriv); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}
