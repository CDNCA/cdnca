package marketruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/directpay"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
)

type fakeCheckouts struct {
	replies []directpay.Reply
	public  ed25519.PublicKey
	err     error
}

func (f *fakeCheckouts) DirectCheckout(_ context.Context, id uuid.UUID, signed directpay.Signed) error {
	if f.err != nil {
		return f.err
	}
	reply, _, err := directpay.VerifyReply(f.public, signed)
	if err != nil || reply.TopupID != id {
		return errors.New("bad reply")
	}
	f.replies = append(f.replies, reply)
	return nil
}

type fakePay struct {
	calls int
	err   error
}

func (f *fakePay) MarketCheckout(_ context.Context, r directpay.Request) (directpay.Reply, error) {
	f.calls++
	if f.err != nil {
		return directpay.Reply{}, f.err
	}
	return directpay.Reply{Schema: directpay.ReplySchemaV1, TopupID: r.TopupID, SellerMemberID: r.SellerMemberID,
		Status: directpay.StatusReady, Action: &directpay.Action{Kind: directpay.ActionQRCode, QRContent: "https://qr.example/1"},
		ExpiresAt: r.ExpiresAt, CreatedAt: time.Now().Unix()}, nil
}

func TestAnswerDirectTopup(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	self := marketclient.Identity{MemberID: uuid.New(), SigningKey: private}
	request := directpay.Request{Schema: directpay.RequestSchemaV1, TopupID: uuid.New(), SellerMemberID: self.MemberID,
		BuyerMemberID: uuid.New(), AmountMinor: 100, Currency: "CNY", Method: "alipay",
		CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(30 * time.Minute).Unix()}
	runtime := New(Config{}, nil, &fakeMarket{}, &fakeSupply{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	checkouts := &fakeCheckouts{public: public}

	// Not wired: refused not_selling, signed by this member.
	runtime.WithDirectPay(nil, checkouts)
	if err := runtime.answer(t.Context(), self, marketclient.Inbound{DirectTopup: &request}); err != nil ||
		len(checkouts.replies) != 1 || checkouts.replies[0].RefusalCode != directpay.RefusedNotSelling {
		t.Fatalf("unwired = %v %+v", err, checkouts.replies)
	}
	pay := &fakePay{}
	runtime.WithDirectPay(pay, checkouts)
	if err := runtime.answer(t.Context(), self, marketclient.Inbound{DirectTopup: &request}); err != nil ||
		len(checkouts.replies) != 2 || checkouts.replies[1].Status != directpay.StatusReady {
		t.Fatalf("ready = %v %+v", err, checkouts.replies)
	}
	// Transient failures redeliver (error); a 4xx from the market does not.
	pay.err = errors.New("db down")
	if err := runtime.answer(t.Context(), self, marketclient.Inbound{DirectTopup: &request}); err == nil {
		t.Fatal("checkout failure was acknowledged")
	}
	pay.err, checkouts.err = nil, &marketclient.RejectedError{Status: http.StatusConflict, Code: "conflict"}
	if err := runtime.answer(t.Context(), self, marketclient.Inbound{DirectTopup: &request}); err != nil {
		t.Fatalf("market 409 = %v", err)
	}
	checkouts.err = errors.New("market unreachable")
	if err := runtime.answer(t.Context(), self, marketclient.Inbound{DirectTopup: &request}); err == nil {
		t.Fatal("unreachable market was acknowledged")
	}
	// Expired long ago: no checkout is opened.
	checkouts.err, pay.calls = nil, 0
	old := request
	old.CreatedAt, old.ExpiresAt = time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
	if err := runtime.answer(t.Context(), self, marketclient.Inbound{DirectTopup: &old}); err != nil || pay.calls != 0 {
		t.Fatalf("expired = %v calls=%d", err, pay.calls)
	}
}
