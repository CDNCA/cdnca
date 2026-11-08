package marketsupply

import (
	"context"
	"strings"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/google/uuid"
)

// The hidden tenant's display name: "市场订阅 ·
// <the seller's offer name> · <subscriber code>", so the seller's site list,
// user list and 订阅者 read the same thing and the buyer's identity stays
// hidden. The offer name is the one frozen at purchase that the buyer also
// sees; a market that does not send it leaves the supply group name. The
// name follows on the next grant
// sync (every grant round); the username (mkt-<Key>) never changes.

const tenantNamePrefix = "市场订阅"

// SubscriberCode is the short code of a grant's subscriber both sides can
// read: the root subscription's first 8 hex for a direct buyer (the buyer's
// 已购供给 shows its subscription id, the seller's 订阅者 the same id), the
// market's downstream ref for a resold path (订阅者 shows that ref).
func SubscriberCode(g grant.Grant) string {
	if g.DownstreamRef != "" {
		return g.DownstreamRef
	}
	if len(g.SubscriptionPath) == 0 {
		return ""
	}
	return g.SubscriptionPath[0].String()[:8]
}

// tenantDisplayName fits users.display_name (1..128 runes, trimmed): the
// group name is cut first, the prefix and code always stay.
func tenantDisplayName(group string, g grant.Grant) string {
	code := SubscriberCode(g)
	group = strings.TrimSpace(group)
	if group == "" {
		return tenantNamePrefix + " · " + code
	}
	room := 128 - len([]rune(tenantNamePrefix+" ·  · "+code))
	if runes := []rune(group); len(runes) > room {
		group = strings.TrimSpace(string(runes[:room]))
	}
	return tenantNamePrefix + " · " + group + " · " + code
}

// nameTenant writes the hidden tenant's display name (its user and tenant
// rows) when it differs; a no-op on every unchanged sync. offerName empty:
// the supply group's name.
func (s *Service) nameTenant(ctx context.Context, tenant tenantRef, poolID uuid.UUID, g grant.Grant, offerName string) error {
	label := offerName
	if strings.TrimSpace(label) == "" {
		if err := s.pool.QueryRow(ctx, `SELECT name FROM node_line_groups WHERE id=$1`, poolID).Scan(&label); err != nil {
			return err
		}
	}
	name := tenantDisplayName(label, g)
	now := s.now().UTC()
	if _, err := s.pool.Exec(ctx, `UPDATE users SET display_name=$2, revision=revision+1, updated_at=$3
		WHERE id=$1 AND display_name<>$2`, tenant.userID, name, now); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE tenants SET display_name=$2, revision=revision+1, updated_at=$3
		WHERE id=(SELECT tenant_id FROM access_scopes WHERE id=$1) AND display_name<>$2`, tenant.scopeID, name, now)
	return err
}
