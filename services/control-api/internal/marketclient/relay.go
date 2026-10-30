package marketclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/directpay"
	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/notice"
	"github.com/google/uuid"
)

// Outbound describes one relay message to a peer controller.
type Outbound struct {
	// MessageID is optional; callers that wait for a reply fix it so the
	// reply ("reply-<message id>") can be matched. Defaults to a random id.
	MessageID      uuid.UUID
	To             uuid.UUID
	GrantID        uuid.UUID
	Operation      string
	Domains        []string
	IdempotencyKey string
	Payload        []byte
}

// Send seals payload to the peer's card key and submits it. The returned seq
// is stable for retries with the same IdempotencyKey.
func (c *Client) Send(ctx context.Context, self Identity, out Outbound) (int64, error) {
	peer, err := c.Card(ctx, out.To)
	if err != nil {
		return 0, err
	}
	messageID := out.MessageID
	if messageID == uuid.Nil {
		messageID = uuid.New()
	}
	sealed, err := envelope.Seal(envelope.Header{
		Schema: envelope.SchemaV1, MessageID: messageID, IdempotencyKey: out.IdempotencyKey,
		SenderMemberID: self.MemberID, RecipientMember: out.To, GrantID: out.GrantID, Operation: out.Operation,
		Domains: out.Domains, ProtocolVersion: 1, CreatedAt: c.now().Unix(),
	}, out.Payload, peer.BoxPublicKey, self.SigningKey)
	if err != nil {
		return 0, err
	}
	var accepted struct {
		Seq int64 `json:"seq"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/relay/messages", sealed, &accepted, requestTimeout); err != nil {
		return 0, err
	}
	return accepted.Seq, nil
}

// Inbound is a decrypted, sender-authenticated relay message, a market
// notice (Notice set, Header zero) or a direct top-up checkout request
// (DirectTopup set, ADR 0015) the market signed for this member.
type Inbound struct {
	Seq         int64
	Header      envelope.Header
	Payload     []byte
	Notice      *notice.Notice
	DirectTopup *directpay.Request
}

// Receive long-polls for messages after cursor and opens them. A message that
// fails authentication or decryption is skipped and reported in errs; the
// caller still advances past it (it can never become valid later).
func (c *Client) Receive(ctx context.Context, self Identity, cursor int64) (messages []Inbound, next int64, errs []error) {
	var response struct {
		Items []struct {
			Seq       int64           `json:"seq"`
			Operation string          `json:"operation"`
			Sealed    envelope.Sealed `json:"sealed"`
			Notice    *notice.Signed  `json:"notice"`
		} `json:"items"`
	}
	path := "/v1/relay/inbox?after=" + itoa(cursor) + "&wait=" + itoa(longPollSeconds)
	if err := c.do(ctx, http.MethodGet, path, nil, &response, (longPollSeconds+15)*time.Second); err != nil {
		return nil, cursor, []error{err}
	}
	next = cursor
	lookup := func(member uuid.UUID) (ed25519.PublicKey, error) {
		peer, err := c.Card(ctx, member)
		if err != nil {
			return nil, err
		}
		return peer.SigningPublicKey, nil
	}
	for _, item := range response.Items {
		if item.Seq <= next {
			errs = append(errs, errors.New("relay returned out-of-order sequence"))
			continue
		}
		next = item.Seq
		if item.Operation == notice.Operation {
			if item.Notice == nil {
				errs = append(errs, ErrProtocol)
				continue
			}
			n, err := notice.Verify(c.keys, *item.Notice, self.MemberID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			messages = append(messages, Inbound{Seq: item.Seq, Notice: &n})
			continue
		}
		if item.Operation == directpay.Operation {
			// Same wire field as a notice: a payload the market signed itself.
			if item.Notice == nil {
				errs = append(errs, ErrProtocol)
				continue
			}
			request, err := directpay.VerifyRequest(c.keys, directpay.Signed(*item.Notice), self.MemberID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			messages = append(messages, Inbound{Seq: item.Seq, DirectTopup: &request})
			continue
		}
		header, payload, err := envelope.Open(item.Sealed, lookup, self.MemberID, self.BoxPrivate)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		messages = append(messages, Inbound{Seq: item.Seq, Header: header, Payload: payload})
	}
	return messages, next, errs
}

// Ack lets the relay forget everything up to seq for this member.
func (c *Client) Ack(ctx context.Context, seq int64) error {
	return c.do(ctx, http.MethodPost, "/v1/relay/ack", map[string]int64{"seq": seq}, nil, requestTimeout)
}
