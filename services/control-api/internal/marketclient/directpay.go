package marketclient

import (
	"context"
	"net/http"

	"github.com/cdnca/cdnca/libs/marketproto/directpay"
	"github.com/google/uuid"
)

// Direct top-ups (ADR 0015 §3.2): this controller as a seller reports which
// methods its own market_direct channels serve, answers checkout requests
// and reports paid trades, all signed with the member key.

// DirectPayMethod is one method a seller's channels serve (no merchant data).
type DirectPayMethod struct {
	Method      string `json:"method"`
	DisplayName string `json:"display_name"`
	MinMinor    int64  `json:"min_minor"`
	MaxMinor    int64  `json:"max_minor"`
}

// DirectPaySettings is PUT /v1/direct-pay/settings.
type DirectPaySettings struct {
	Enabled  bool              `json:"enabled"`
	Currency string            `json:"currency"`
	Methods  []DirectPayMethod `json:"methods"`
}

func (c *Client) DirectPaySettings(ctx context.Context, settings DirectPaySettings) error {
	return c.do(ctx, http.MethodPut, "/v1/direct-pay/settings", settings, nil, requestTimeout)
}

// DirectCheckout sends the signed CheckoutReply of a top-up.
func (c *Client) DirectCheckout(ctx context.Context, topupID uuid.UUID, signed directpay.Signed) error {
	return c.do(ctx, http.MethodPost, "/v1/direct-topups/"+topupID.String()+"/checkout", signed, nil, requestTimeout)
}

// DirectPaid sends the signed PaidReport of one paid trade.
func (c *Client) DirectPaid(ctx context.Context, topupID uuid.UUID, signed directpay.Signed) error {
	return c.do(ctx, http.MethodPost, "/v1/direct-topups/"+topupID.String()+"/paid", signed, nil, requestTimeout)
}
