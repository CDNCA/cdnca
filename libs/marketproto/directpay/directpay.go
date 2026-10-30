// Package directpay is the node market direct top-up contract (ADR 0015): a
// subscriber tops up its balance with one seller by paying the seller's own
// merchant account. The seller's merchant keys never leave the seller
// controller; the market only relays the checkout request and records the
// balance from the seller's signed report.
//
//   - Request: market -> seller controller, relay operation
//     market.direct_topup, signed with the market key (same key ring as member
//     cards and market.notice).
//   - Reply: seller -> market, POST /v1/direct-topups/{id}/checkout, signed
//     with the seller member key: the payment link or QR content, or a refusal.
//   - Paid: seller -> market, POST /v1/direct-topups/{id}/paid, signed with
//     the seller member key: one succeeded payment of the top-up, confirmed
//     by the seller's channel (notification verified + gateway query).
package directpay

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
)

const (
	RequestSchemaV1 = "cdnca.market.directpay.request/v1"
	ReplySchemaV1   = "cdnca.market.directpay.checkout/v1"
	PaidSchemaV1    = "cdnca.market.directpay.paid/v1"

	// Operation is the relay operation of a Request (market-originated).
	Operation = "market.direct_topup"

	// CurrencyCNY is the only currency: seller channels book CNY only.
	CurrencyCNY = "CNY"

	MaxPayload   = 64 << 10
	MaxAmount    = 100_000_000 // 1,000,000.00 CNY in fen
	MaxSequence  = 100
	maxSkew      = 60
	maxURL       = 2048
	maxQR        = 1024
	maxFormItems = 32
	maxFormValue = 4096
	maxName      = 64
)

// Methods a buyer may pick (libs/payment MethodAlipay / MethodWxpay).
const (
	MethodAlipay = "alipay"
	MethodWxpay  = "wxpay"
)

var Methods = []string{MethodAlipay, MethodWxpay}

// Reply statuses and refusal codes.
const (
	StatusReady   = "ready"
	StatusRefused = "refused"

	RefusedMethodUnavailable  = "method_unavailable"
	RefusedAmountOutOfRange   = "amount_out_of_range"
	RefusedFeatureDenied      = "feature_denied"
	RefusedChannelUnavailable = "channel_unavailable"
	RefusedNotSelling         = "not_selling"
)

var refusals = []string{RefusedMethodUnavailable, RefusedAmountOutOfRange, RefusedFeatureDenied,
	RefusedChannelUnavailable, RefusedNotSelling}

// Action kinds (libs/payment ActionRedirect / ActionQRCode).
const (
	ActionRedirect = "redirect"
	ActionQRCode   = "qr_code"
)

var (
	ErrInvalid    = errors.New("invalid direct top-up message")
	ErrSignature  = errors.New("direct top-up signature rejected")
	ErrUnknownKey = errors.New("direct top-up signing key unknown")

	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	formKey       = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// Request asks the seller controller to create a checkout on its own channel.
type Request struct {
	Schema           string    `json:"schema"`
	TopupID          uuid.UUID `json:"topup_id"`
	SellerMemberID   uuid.UUID `json:"seller_member_id"`
	BuyerMemberID    uuid.UUID `json:"buyer_member_id"`
	BuyerDisplayName string    `json:"buyer_display_name"`
	AmountMinor      int64     `json:"amount_minor"`
	Currency         string    `json:"currency"`
	Method           string    `json:"method"`
	ExpiresAt        int64     `json:"expires_at"`
	CreatedAt        int64     `json:"created_at"`
}

func (r Request) Validate() error {
	if r.Schema != RequestSchemaV1 || r.TopupID == uuid.Nil || r.SellerMemberID == uuid.Nil ||
		r.BuyerMemberID == uuid.Nil || r.SellerMemberID == r.BuyerMemberID || !validAmount(r.AmountMinor) ||
		r.Currency != CurrencyCNY || !slices.Contains(Methods, r.Method) || r.CreatedAt <= 0 ||
		r.ExpiresAt <= r.CreatedAt || !validName(r.BuyerDisplayName) {
		return ErrInvalid
	}
	return nil
}

// Action is how the buyer pays: open URL (optionally as a POST form) or
// render QRContent as a QR code.
type Action struct {
	Kind       string            `json:"kind"`
	URL        string            `json:"url,omitempty"`
	HTTPMethod string            `json:"http_method,omitempty"`
	Form       map[string]string `json:"form,omitempty"`
	QRContent  string            `json:"qr_content,omitempty"`
}

func (a Action) Validate() error {
	switch a.Kind {
	case ActionRedirect:
		if a.QRContent != "" || !httpsURL(a.URL) || (a.HTTPMethod != "" && a.HTTPMethod != "GET" && a.HTTPMethod != "POST") ||
			len(a.Form) > maxFormItems || (len(a.Form) > 0 && a.HTTPMethod != "POST") {
			return ErrInvalid
		}
		for k, v := range a.Form {
			if !formKey.MatchString(k) || len(v) > maxFormValue || !utf8.ValidString(v) {
				return ErrInvalid
			}
		}
	case ActionQRCode:
		if a.URL != "" || a.HTTPMethod != "" || len(a.Form) > 0 || a.QRContent == "" || len(a.QRContent) > maxQR ||
			!utf8.ValidString(a.QRContent) || strings.ContainsAny(a.QRContent, "\x00\r\n") {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Reply is the seller's answer to a Request.
type Reply struct {
	Schema             string    `json:"schema"`
	TopupID            uuid.UUID `json:"topup_id"`
	SellerMemberID     uuid.UUID `json:"seller_member_id"`
	Status             string    `json:"status"`
	RefusalCode        string    `json:"refusal_code,omitempty"`
	Action             *Action   `json:"action,omitempty"`
	ChannelDisplayName string    `json:"channel_display_name,omitempty"`
	ExpiresAt          int64     `json:"expires_at,omitempty"`
	CreatedAt          int64     `json:"created_at"`
}

func (r Reply) Validate() error {
	if r.Schema != ReplySchemaV1 || r.TopupID == uuid.Nil || r.SellerMemberID == uuid.Nil || r.CreatedAt <= 0 {
		return ErrInvalid
	}
	switch r.Status {
	case StatusReady:
		if r.RefusalCode != "" || r.Action == nil || r.Action.Validate() != nil || r.ExpiresAt <= 0 ||
			(r.ChannelDisplayName != "" && !validName(r.ChannelDisplayName)) {
			return ErrInvalid
		}
	case StatusRefused:
		if !slices.Contains(refusals, r.RefusalCode) || r.Action != nil || r.ChannelDisplayName != "" || r.ExpiresAt != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Paid reports one succeeded payment of a top-up. TradeDigest is
// hex(sha256(channel_id ":" external trade number)): it identifies the trade
// without disclosing the seller's merchant data. Sequence numbers the
// distinct succeeded trades of one top-up (1 normally; 2+ when an aggregator
// let the buyer pay the same checkout twice) and is the credit's idempotency
// key on the market.
type Paid struct {
	Schema         string    `json:"schema"`
	TopupID        uuid.UUID `json:"topup_id"`
	SellerMemberID uuid.UUID `json:"seller_member_id"`
	BuyerMemberID  uuid.UUID `json:"buyer_member_id"`
	AmountMinor    int64     `json:"amount_minor"`
	Currency       string    `json:"currency"`
	Method         string    `json:"method"`
	TradeDigest    string    `json:"trade_digest"`
	Sequence       int       `json:"sequence"`
	PaidAt         int64     `json:"paid_at"`
	CreatedAt      int64     `json:"created_at"`
}

func (p Paid) Validate() error {
	if p.Schema != PaidSchemaV1 || p.TopupID == uuid.Nil || p.SellerMemberID == uuid.Nil || p.BuyerMemberID == uuid.Nil ||
		p.SellerMemberID == p.BuyerMemberID || !validAmount(p.AmountMinor) || p.Currency != CurrencyCNY ||
		!slices.Contains(Methods, p.Method) || !digestPattern.MatchString(p.TradeDigest) ||
		p.Sequence < 1 || p.Sequence > MaxSequence || p.CreatedAt <= 0 || p.PaidAt <= 0 || p.PaidAt > p.CreatedAt+maxSkew {
		return ErrInvalid
	}
	return nil
}

// Signed is the wire form of every message. KeyID names the market key for a
// Request and is empty for seller-signed messages (the seller has one key,
// market_members.signing_public_key).
type Signed struct {
	KeyID     string `json:"key_id,omitempty"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type message interface {
	Validate() error
}

func domain(schema string) []byte { return []byte(schema + "\n") }

func sign(schema string, m message, keyID string, key ed25519.PrivateKey) (Signed, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Signed{}, ErrInvalid
	}
	if err := m.Validate(); err != nil {
		return Signed{}, err
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return Signed{}, err
	}
	if len(payload) > MaxPayload {
		return Signed{}, ErrInvalid
	}
	return Signed{KeyID: keyID, Payload: base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append(domain(schema), payload...)))}, nil
}

func verify(schema string, public ed25519.PublicKey, s Signed, into message) ([]byte, error) {
	if len(public) != ed25519.PublicKeySize {
		return nil, ErrSignature
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(s.Payload)
	if err != nil || len(payload) > MaxPayload {
		return nil, ErrInvalid
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(public, append(domain(schema), payload...), signature) {
		return nil, ErrSignature
	}
	if err := spec.DecodeStrict(payload, into); err != nil {
		return nil, ErrInvalid
	}
	if err := into.Validate(); err != nil {
		return nil, err
	}
	return payload, nil
}

func SignRequest(r Request, keyID string, key ed25519.PrivateKey) (Signed, error) {
	if keyID == "" {
		return Signed{}, ErrInvalid
	}
	return sign(RequestSchemaV1, r, keyID, key)
}

// VerifyRequest checks the market signature and that the request is
// addressed to self.
func VerifyRequest(keys map[string]ed25519.PublicKey, s Signed, self uuid.UUID) (Request, error) {
	public, ok := keys[s.KeyID]
	if !ok {
		return Request{}, ErrUnknownKey
	}
	var r Request
	if _, err := verify(RequestSchemaV1, public, s, &r); err != nil {
		return Request{}, err
	}
	if r.SellerMemberID != self {
		return Request{}, ErrInvalid
	}
	return r, nil
}

func SignReply(r Reply, key ed25519.PrivateKey) (Signed, error) {
	return sign(ReplySchemaV1, r, "", key)
}

// VerifyReply returns the reply and the exact signed bytes.
func VerifyReply(public ed25519.PublicKey, s Signed) (Reply, []byte, error) {
	var r Reply
	payload, err := verify(ReplySchemaV1, public, s, &r)
	return r, payload, err
}

func SignPaid(p Paid, key ed25519.PrivateKey) (Signed, error) { return sign(PaidSchemaV1, p, "", key) }

// VerifyPaid returns the report and the exact signed bytes.
func VerifyPaid(public ed25519.PublicKey, s Signed) (Paid, []byte, error) {
	var p Paid
	payload, err := verify(PaidSchemaV1, public, s, &p)
	return p, payload, err
}

func validAmount(v int64) bool { return v > 0 && v <= MaxAmount }

func validName(v string) bool {
	return utf8.ValidString(v) && utf8.RuneCountInString(v) <= maxName && !strings.ContainsAny(v, "\x00\r\n")
}

func httpsURL(raw string) bool {
	if raw == "" || len(raw) > maxURL {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}
