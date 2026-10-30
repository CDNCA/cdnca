package marketsubscribe

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/card"
	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/secdigest"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Attack digests relayed by leaves (ADR 0012 §19.1, ML-21): the envelope is
// already opened and sender-authenticated by marketclient; the digest's own
// member signature is checked against the sender's card again so the stored
// copy stays attributable to the leaf. The digest is bound to the local site
// that has this leaf's leaf_site_id in site_supply_leaf_sites and written to
// ClickHouse for the attack log page and attack alerts.

var ErrDigestForeign = errors.New("market subscribe: security digest does not match a site of this leaf")

// Cards returns a member's market-signed card (marketclient.Client.Card).
type Cards interface {
	Card(ctx context.Context, member uuid.UUID) (card.Card, error)
}

// DigestStore is securityanalytics.ClickHouse.
type DigestStore interface {
	WriteMarketSecurity(ctx context.Context, m securityanalytics.MarketSecurity) error
}

// WithCards sets the member cards alone (origin auth seals to leaf cards,
// compile_origin_auth.go); WithDigests sets them too.
func (s *Service) WithCards(cards Cards) *Service {
	s.cards = cards
	return s
}

// WithDigests turns on ReceiveDigest.
func (s *Service) WithDigests(cards Cards, store DigestStore) *Service {
	s.cards, s.digests = cards, store
	return s
}

// ReceiveDigest verifies and stores one digest. A digest that cannot be
// attributed (bad signature, another leaf's site, a site no longer bound)
// is dropped with a log line: redelivering it would never succeed. Only a
// storage failure is returned, so the relay redelivers it.
func (s *Service) ReceiveDigest(ctx context.Context, header envelope.Header, payload []byte) error {
	if s.cards == nil || s.digests == nil {
		return nil
	}
	d, err := s.verifyDigest(ctx, header, payload)
	if err != nil {
		slog.Warn("market security digest dropped", "sender", header.SenderMemberID, "grant_id", header.GrantID, "err", err)
		return nil
	}
	var m securityanalytics.MarketSecurity
	err = s.pool.QueryRow(ctx, `SELECT scope.tenant_id, leaf.site_id, leaf.supply_id FROM site_supply_leaf_sites leaf
		JOIN sites site ON site.id=leaf.site_id AND site.deleted_at IS NULL
		JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
		WHERE leaf.leaf_member_id=$1 AND leaf.leaf_site_id=$2
		ORDER BY leaf.updated_at DESC LIMIT 1`, header.SenderMemberID, d.LeafSiteID).Scan(&m.TenantID, &m.SiteID, &m.SupplyID)
	if errors.Is(err, pgx.ErrNoRows) {
		slog.Warn("market security digest dropped", "sender", header.SenderMemberID, "leaf_site_id", d.LeafSiteID,
			"err", ErrDigestForeign)
		return nil
	}
	if err != nil {
		return err
	}
	m.LeafMemberID, m.LeafRef, m.ReceivedAt, m.Digest = header.SenderMemberID, LeafRef(header.SenderMemberID), s.now().UTC(), d
	return s.digests.WriteMarketSecurity(ctx, m)
}

func (s *Service) verifyDigest(ctx context.Context, header envelope.Header, payload []byte) (secdigest.Digest, error) {
	var signed secdigest.Signed
	if err := json.Unmarshal(payload, &signed); err != nil {
		return secdigest.Digest{}, secdigest.ErrInvalid
	}
	peer, err := s.cards.Card(ctx, header.SenderMemberID)
	if err != nil {
		return secdigest.Digest{}, err
	}
	d, _, err := secdigest.Verify(ed25519.PublicKey(peer.SigningPublicKey), signed)
	if err != nil {
		return secdigest.Digest{}, err
	}
	window, ok := secdigest.WindowOfKey(header.IdempotencyKey)
	if d.LeafMemberID != header.SenderMemberID || d.GrantID != header.GrantID || !ok || window != d.WindowStart ||
		header.IdempotencyKey != secdigest.IdempotencyKey(d.LeafSiteID, d.WindowStart) {
		return secdigest.Digest{}, ErrDigestForeign
	}
	// A window far in the future is not something a leaf has seen yet.
	if time.Unix(d.WindowStart, 0).After(s.now().Add(10 * time.Minute)) {
		return secdigest.Digest{}, secdigest.ErrInvalid
	}
	return d, nil
}

// LeafRef is the short display number of a leaf on the subscriber's pages
// ("市场供给 · 叶子编号"): the first 8 hex digits of its member ID, which
// the subscriber already sees in its supply list.
func LeafRef(member uuid.UUID) string { return member.String()[:8] }
