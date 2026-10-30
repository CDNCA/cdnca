package notice

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func sample() Notice {
	sub := uuid.New()
	return Notice{Schema: SchemaV1, ID: uuid.New(), MemberID: uuid.New(), SubscriptionID: &sub, Role: RoleBuyer,
		Kind: KindLimitWarn80, Stage: "monthly_traffic_bytes", PeriodKey: "2026-10", CreatedAt: 1760000000,
		Values: map[string]string{ValueOffer: "华东 BGP", ValueObserved: "80", ValueCap: "100"}}
}

func TestSignVerify(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	keys := map[string]ed25519.PublicKey{"k1": public}
	n := sample()
	signed, err := Sign(n, "k1", private)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(keys, signed, n.MemberID)
	if err != nil || got.ID != n.ID || got.Values[ValueOffer] != "华东 BGP" || *got.SubscriptionID != *n.SubscriptionID {
		t.Fatalf("verify = %+v, %v", got, err)
	}
	if _, err := Verify(keys, signed, uuid.New()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("other recipient: %v", err)
	}
	if _, err := Verify(map[string]ed25519.PublicKey{"k2": public}, signed, n.MemberID); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := Verify(map[string]ed25519.PublicKey{"k1": other}, signed, n.MemberID); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestValidate(t *testing.T) {
	for name, mutate := range map[string]func(*Notice){
		"unknown kind":  func(n *Notice) { n.Kind = "market.other" },
		"role":          func(n *Notice) { n.Role = "leaf" },
		"value key":     func(n *Notice) { n.Values["secret"] = "x" },
		"empty period":  func(n *Notice) { n.PeriodKey = "" },
		"nil sub":       func(n *Notice) { nilSub := uuid.Nil; n.SubscriptionID = &nilSub },
		"schema":        func(n *Notice) { n.Schema = "v0" },
		"value too big": func(n *Notice) { n.Values[ValueOffer] = string(make([]rune, 300)) },
	} {
		n := sample()
		mutate(&n)
		if err := n.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	n := sample()
	n.SubscriptionID = nil
	if err := n.Validate(); err != nil {
		t.Fatalf("node notice without subscription: %v", err)
	}
}

// ML-20 (ADR 0012 §19.1): a reseller on the path learns only that a
// downstream site was attacked, by number and window.
func TestDownstreamAttackedNotice(t *testing.T) {
	n := sample()
	n.Kind, n.Role, n.Stage = KindDownstreamAttacked, RoleSeller, ""
	n.Values = map[string]string{ValueDownstream: "d-0123456789abcdef", ValueWindowStart: "1800000000"}
	if err := n.Validate(); err != nil {
		t.Fatal(err)
	}
	// "site" is a value key since ML-24 (same-site pause names the leaf site
	// ID); the control plane renders only each kind's own variables
	// (marketruntime noticeVariables), so the attacked notice never shows it.
	// A host name is never a key.
	n.Values["host"] = "www.example.com"
	if err := n.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("site identity must not be a notice value: %v", err)
	}
}
