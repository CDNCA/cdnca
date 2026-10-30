package marketsubscribe

import (
	"context"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/google/uuid"
)

// AutoDefenseReader reads a local site's automatic defence settings. The
// community edition has no automatic defense module: nothing implements it
// and rollouts carry no auto_defense block.
type AutoDefenseReader interface {
	autoDefenseReader()
}

// withAutoDefense leaves cfg.AutoDefense as the caller sent it.
func (s *Service) withAutoDefense(context.Context, uuid.UUID, *siteconf.Config) error { return nil }

// RepushAutoDefense has nothing to roll out in the community edition.
func (s *Service) RepushAutoDefense(context.Context) (int, error) { return 0, nil }
