package marketruntime

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/directpay"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
)

// DirectPay opens a checkout on this seller's own market_direct channel
// (paymentchannel.Service.MarketCheckout, ADR 0015 §3.3).
type DirectPay interface {
	MarketCheckout(ctx context.Context, request directpay.Request) (directpay.Reply, error)
}

// DirectCheckouts sends the signed reply (marketclient.Client).
type DirectCheckouts interface {
	DirectCheckout(ctx context.Context, topupID uuid.UUID, signed directpay.Signed) error
}

// WithDirectPay answers market.direct_topup requests. Without it every
// request is refused not_selling (this controller takes no direct top-ups).
func (r *Runtime) WithDirectPay(pay DirectPay, market DirectCheckouts) *Runtime {
	r.mu.Lock()
	r.directPay, r.directMarket = pay, market
	r.mu.Unlock()
	return r
}

// directReplyGrace: a request older than its expiry is answered refused
// without opening a checkout nobody can use.
const directReplyGrace = time.Minute

func (r *Runtime) answerDirectTopup(ctx context.Context, self marketclient.Identity, request directpay.Request) error {
	r.mu.Lock()
	pay, market := r.directPay, r.directMarket
	r.mu.Unlock()
	if market == nil {
		if m, ok := r.market.(DirectCheckouts); ok {
			market = m
		}
	}
	if market == nil {
		return nil // nobody to answer; the market marks the top-up unreachable
	}
	var reply directpay.Reply
	switch {
	case pay == nil:
		reply = directpay.Reply{Schema: directpay.ReplySchemaV1, TopupID: request.TopupID, SellerMemberID: self.MemberID,
			Status: directpay.StatusRefused, RefusalCode: directpay.RefusedNotSelling, CreatedAt: time.Now().Unix()}
	case time.Now().After(time.Unix(request.ExpiresAt, 0).Add(directReplyGrace)):
		// Redelivered after the buyer gave up: the market has expired it.
		return nil
	default:
		var err error
		if reply, err = pay.MarketCheckout(ctx, request); err != nil {
			return err // transient: redeliver
		}
	}
	signed, err := directpay.SignReply(reply, self.SigningKey)
	if err != nil {
		return nil // cannot become valid later
	}
	err = market.DirectCheckout(ctx, request.TopupID, signed)
	if status, _, rejected := marketclient.Rejected(err); rejected && status >= 400 && status < 500 && status != 408 && status != 429 {
		// Late reply (unreachable) or a conflicting one: the market keeps its
		// state; redelivering cannot change that.
		r.log.Warn("market refused direct top-up checkout", "topup_id", request.TopupID, "status", status)
		return nil
	}
	if errors.Is(err, directpay.ErrInvalid) {
		return nil
	}
	return err
}
