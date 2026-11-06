package securityban

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/libs/marketproto/bansync"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Where an active ban is enforced. A site served only by
// market subscription nodes has no node of this controller: its bans reach
// the leaves through the market (marketsubscribe ban sync), and the list
// shows per ban whether every leaf took it and its nodes run it. A site with
// no node at all says so instead of "active".

// LeafBanDelivery is what one market leaf behind a site last answered
// (marketsubscribe site_supply_ban_deliveries).
type LeafBanDelivery struct {
	// State: "" (nothing sent yet), sent, accepted, rejected, unsupported.
	State string
	// Reason: why rejected or still sent (a bansync or subscriber code).
	Reason string
	// Accepted: the subscriber entries the leaf took in its last answer;
	// Refused: those it refused, with the code.
	Accepted map[uuid.UUID]bool
	Refused  map[uuid.UUID]string
	Nodes    bansync.Nodes
}

// MarketDeliveries lists the market leaves behind sites (nil map entry: the
// site has none) — marketsubscribe.Service.SiteBanDeliveries.
type MarketDeliveries interface {
	SiteBanDeliveries(ctx context.Context, sites []uuid.UUID) (map[uuid.UUID][]LeafBanDelivery, error)
}

// Delivery of an active ban (Entry.Delivery): nil for a site served only by
// this controller's own nodes (the list's "active" stands).
type Delivery struct {
	// State: the worst over the site's market leaves (DeliveryEffective ...),
	// or DeliveryNoNodes for a site with neither own nodes nor leaves.
	State  string `json:"state"`
	Reason string `json:"reason"`
	// Leaves: market leaves behind the site; Effective: those whose every
	// node runs the ban. OwnNodes: this controller's nodes serving the site.
	Leaves    int `json:"leaves"`
	Effective int `json:"effective"`
	OwnNodes  int `json:"own_nodes"`
}

const (
	DeliveryEffective   = "effective"
	DeliveryDelivering  = "delivering"
	DeliveryPending     = "pending"
	DeliveryNoNodes     = "no_nodes"
	DeliveryUnsupported = "unsupported"
	DeliveryFailed      = "failed"
	DeliveryRefused     = "refused"
)

// deliveryRank orders states best to worst; a ban shows its worst leaf.
var deliveryRank = map[string]int{DeliveryEffective: 0, DeliveryDelivering: 1, DeliveryPending: 2, DeliveryNoNodes: 3,
	DeliveryUnsupported: 4, DeliveryFailed: 5, DeliveryRefused: 6}

// WithMarketDeliveries lets List say how a ban of a market site is enforced.
func (s *Store) WithMarketDeliveries(source MarketDeliveries) *Store {
	s.market = source
	return s
}

// annotate sets Delivery on the active entries of sites served by no own
// node or by market leaves.
func (s *Store) annotate(ctx context.Context, items []Entry) error {
	seen := map[uuid.UUID]bool{}
	sites := []uuid.UUID{}
	for _, item := range items {
		if item.State == StateActive && !seen[item.SiteID] {
			seen[item.SiteID] = true
			sites = append(sites, item.SiteID)
		}
	}
	if len(sites) == 0 {
		return nil
	}
	own := map[uuid.UUID]int{}
	if err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		serving, err := servingNodes(ctx, tx, sites)
		for _, nodeSites := range serving {
			for _, site := range nodeSites {
				own[site]++
			}
		}
		return err
	}); err != nil {
		return fmt.Errorf("read serving nodes: %w", err)
	}
	leaves := map[uuid.UUID][]LeafBanDelivery{}
	if s.market != nil {
		var err error
		if leaves, err = s.market.SiteBanDeliveries(ctx, sites); err != nil {
			return fmt.Errorf("read market ban deliveries: %w", err)
		}
	}
	for i := range items {
		if items[i].State == StateActive {
			items[i].Delivery = deliveryOf(items[i].ID, own[items[i].SiteID], leaves[items[i].SiteID])
		}
	}
	return nil
}

func deliveryOf(entry uuid.UUID, ownNodes int, leaves []LeafBanDelivery) *Delivery {
	if len(leaves) == 0 {
		if ownNodes > 0 {
			return nil
		}
		return &Delivery{State: DeliveryNoNodes}
	}
	out := &Delivery{State: DeliveryEffective, Leaves: len(leaves), OwnNodes: ownNodes}
	for _, leaf := range leaves {
		state, reason := leafEntryState(entry, leaf)
		if state == DeliveryEffective {
			out.Effective++
		}
		if deliveryRank[state] > deliveryRank[out.State] {
			out.State, out.Reason = state, reason
		}
	}
	return out
}

// leafEntryState is one leaf's state of one entry.
func leafEntryState(entry uuid.UUID, leaf LeafBanDelivery) (string, string) {
	if code, refused := leaf.Refused[entry]; refused {
		if code == bansync.RefuseRateLimited {
			return DeliveryPending, code
		}
		return DeliveryRefused, code
	}
	switch leaf.State {
	case "":
		return DeliveryPending, ""
	case "unsupported":
		return DeliveryUnsupported, leaf.Reason
	case "rejected":
		if leaf.Reason != bansync.ErrCodeRateLimited {
			return DeliveryRefused, leaf.Reason
		}
	}
	if !leaf.Accepted[entry] {
		return DeliveryPending, leaf.Reason
	}
	switch leaf.Nodes.State {
	case bansync.NodesApplied:
		return DeliveryEffective, ""
	case bansync.NodesFailed:
		return DeliveryFailed, leaf.Nodes.Reason
	case bansync.NodesNone:
		return DeliveryNoNodes, ""
	case bansync.NodesOff:
		return DeliveryNoNodes, bansync.NodesOff
	}
	return DeliveryDelivering, ""
}
