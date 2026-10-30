package directpay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func request() Request {
	return Request{Schema: RequestSchemaV1, TopupID: uuid.New(), SellerMemberID: uuid.New(), BuyerMemberID: uuid.New(),
		BuyerDisplayName: "买方", AmountMinor: 1000, Currency: CurrencyCNY, Method: MethodAlipay, ExpiresAt: 2000, CreatedAt: 1000}
}

func TestRequestRoundTripAndAddressing(t *testing.T) {
	public, private := keys(t)
	r := request()
	signed, err := SignRequest(r, "k1", private)
	if err != nil {
		t.Fatal(err)
	}
	ring := map[string]ed25519.PublicKey{"k1": public}
	got, err := VerifyRequest(ring, signed, r.SellerMemberID)
	if err != nil || got != r {
		t.Fatalf("verify: %+v %v", got, err)
	}
	if _, err := VerifyRequest(ring, signed, r.BuyerMemberID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("other recipient: %v", err)
	}
	if _, err := VerifyRequest(map[string]ed25519.PublicKey{"k2": public}, signed, r.SellerMemberID); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	// A seller-signed (keyless) message must not pass as a market request.
	other, otherKey := keys(t)
	forged, _ := sign(RequestSchemaV1, r, "k1", otherKey)
	if _, err := VerifyRequest(ring, forged, r.SellerMemberID); !errors.Is(err, ErrSignature) {
		t.Fatalf("forged: %v", err)
	}
	_ = other
}

func TestDomainSeparation(t *testing.T) {
	public, private := keys(t)
	paid := Paid{Schema: PaidSchemaV1, TopupID: uuid.New(), SellerMemberID: uuid.New(), BuyerMemberID: uuid.New(),
		AmountMinor: 1000, Currency: CurrencyCNY, Method: MethodWxpay, TradeDigest: strings.Repeat("a", 64), Sequence: 1,
		PaidAt: 1000, CreatedAt: 1001}
	signed, err := SignPaid(paid, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyPaid(public, signed); err != nil {
		t.Fatal(err)
	}
	// The same bytes signed under the paid domain never verify as a reply.
	if _, _, err := VerifyReply(public, signed); !errors.Is(err, ErrSignature) {
		t.Fatalf("cross domain: %v", err)
	}
}

func TestRejectsUnknownFieldsAndBadShapes(t *testing.T) {
	public, private := keys(t)
	payload := `{"schema":"` + PaidSchemaV1 + `","extra":1}`
	signature := ed25519.Sign(private, append(domain(PaidSchemaV1), payload...))
	s := Signed{Payload: base64.StdEncoding.EncodeToString([]byte(payload)), Signature: base64.StdEncoding.EncodeToString(signature)}
	if _, _, err := VerifyPaid(public, s); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field: %v", err)
	}
	bad := []func(*Request){
		func(r *Request) { r.Currency = "USD" },
		func(r *Request) { r.AmountMinor = 0 },
		func(r *Request) { r.AmountMinor = MaxAmount + 1 },
		func(r *Request) { r.Method = "usdt" },
		func(r *Request) { r.BuyerMemberID = r.SellerMemberID },
		func(r *Request) { r.ExpiresAt = r.CreatedAt },
		func(r *Request) { r.BuyerDisplayName = "a\nb" },
	}
	for i, mutate := range bad {
		r := request()
		mutate(&r)
		if _, err := SignRequest(r, "k1", private); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestReplyShapes(t *testing.T) {
	base := Reply{Schema: ReplySchemaV1, TopupID: uuid.New(), SellerMemberID: uuid.New(), CreatedAt: 1}
	ready := base
	ready.Status, ready.ExpiresAt = StatusReady, 10
	ready.Action = &Action{Kind: ActionQRCode, QRContent: "weixin://wxpay/bizpayurl?pr=abc"}
	if err := ready.Validate(); err != nil {
		t.Fatal(err)
	}
	ready.Action = &Action{Kind: ActionRedirect, URL: "https://pay.example.com/submit.php", HTTPMethod: "POST",
		Form: map[string]string{"pid": "1", "sign": "x"}}
	if err := ready.Validate(); err != nil {
		t.Fatal(err)
	}
	for i, action := range []Action{
		{Kind: ActionRedirect, URL: "http://pay.example.com/"},
		{Kind: ActionRedirect, URL: "https://user:pw@pay.example.com/"},
		{Kind: ActionRedirect, URL: "javascript:alert(1)"},
		{Kind: ActionRedirect, URL: "https://pay.example.com/", Form: map[string]string{"a": "b"}},
		{Kind: ActionQRCode},
		{Kind: "crypto_address", URL: "https://x.example/"},
	} {
		r := ready
		r.Action = &action
		if r.Validate() == nil {
			t.Errorf("action %d accepted", i)
		}
	}
	refused := base
	refused.Status, refused.RefusalCode = StatusRefused, RefusedMethodUnavailable
	if err := refused.Validate(); err != nil {
		t.Fatal(err)
	}
	refused.RefusalCode = "other"
	if refused.Validate() == nil {
		t.Fatal("unknown refusal accepted")
	}
}
