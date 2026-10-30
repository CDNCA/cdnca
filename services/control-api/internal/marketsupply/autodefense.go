package marketsupply

import (
	"context"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/google/uuid"
)

// AutoDefenseStore is the automatic defence store a leaf writes a market
// site's auto_defense block into. The community edition has no automatic
// defense module, so nothing implements it and the block is refused as
// unavailable.
type AutoDefenseStore interface {
	autoDefenseStore()
}

// autoDefenseBlockers checks c's auto_defense block: a malformed block is a
// hard blocker; a well-formed one only tells the subscriber automatic
// defense does not take effect on this supply.
func (s *Service) autoDefenseBlockers(c siteconf.Config, _ TenantPlugins) (*siteconf.AutoDefense, []siteconf.Blocker, []siteconf.Blocker) {
	ad, err := c.DecodeAutoDefense()
	if err != nil {
		return nil, []siteconf.Blocker{{Code: "autodefense_invalid"}}, nil
	}
	if ad == nil {
		return nil, nil, nil
	}
	return nil, nil, []siteconf.Blocker{{Code: siteconf.BlockerAutoDefenseUnavailable, Detail: PluginAutoDefense}}
}

// applyAutoDefense: autoDefenseBlockers never returns a block to apply.
func (s *Service) applyAutoDefense(context.Context, tenantRef, uuid.UUID, *siteconf.AutoDefense) error {
	return nil
}
