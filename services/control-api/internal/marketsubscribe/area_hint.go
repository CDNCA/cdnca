package marketsubscribe

import (
	"strings"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
)

// BlockerSellerAreaUnsupported (buyer side): the seller refused a
// config with area origin rules as invalid and gave no reason. Sellers on a
// controller from before area geographies do exactly that;
// the market carries no seller controller version, so the buyer cannot tell
// in advance. Detail: the rule IDs that name an area.
const BlockerSellerAreaUnsupported = "seller_area_unsupported"

// areaRefusalHint is the hint for a prepare refusal, nil when it does not fit.
func areaRefusalHint(cfg siteconf.Config, reply siteconf.Reply) []siteconf.Blocker {
	if reply.Error != siteconf.ErrInvalid.Error() || len(reply.Blockers) > 0 || cfg.OriginRoutes == nil {
		return nil
	}
	var ids []string
	for _, route := range cfg.OriginRoutes.Routes {
		for _, geo := range route.NodeGeos {
			if geo.Area != "" {
				ids = append(ids, route.ID)
				break
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return []siteconf.Blocker{{Code: BlockerSellerAreaUnsupported, Detail: strings.Join(ids, ",")}}
}
