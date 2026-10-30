package marketsupply

// Seller supply composition (ADR 0012 ML-09 §3.3): the seller picks one or
// more platform nodes; this controller keeps them as a hidden line group
// (purpose='market_supply', migration 422) whose id is the offer
// component's node_pool_ref. Publication, probing and the pool inventory
// (marketprobe) then work as for any line group.
//
// SupplyPlugins answers ML-02 "节点插件只能选节点实际具备的":
// the node plugins this installation's lease grants AND every
// selected node has installed (capability or applied artifact), i.e. the
// intersection over the supply's nodes.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxSupplyNodes   = 256
	supplyGroupPort  = 443
	supplyGroupLabel = "市场供给 "
)

var (
	ErrSupplyInvalid  = errors.New("market supply group: invalid")
	ErrSupplyNotFound = errors.New("market supply group: not found")
	// ErrSupplyNodeUnusable: a selected node is not an active platform node
	// with an address.
	ErrSupplyNodeUnusable = errors.New("market supply group: node unusable")
	ErrSupplyForbidden    = errors.New("market supply group: forbidden")
	// ErrSupplyConflict: stale revision, idempotency key reuse, or (delete)
	// a market product still uses the group.
	ErrSupplyConflict = errors.New("market supply group: conflict")
)

// FeatureReader is the valid lease's feature codes
// (entitlementguard.Guard.ReadValidFeatures).
type FeatureReader interface {
	ReadValidFeatures(ctx context.Context, tx pgx.Tx) (map[string]bool, error)
}

// SupplyGroups writes and reads hidden supply groups for console callers.
type SupplyGroups struct {
	pool      *pgxpool.Pool
	scheduler *nodescheduler.Service
	features  FeatureReader
}

func NewSupplyGroups(pool *pgxpool.Pool, scheduler *nodescheduler.Service, features FeatureReader) *SupplyGroups {
	return &SupplyGroups{pool: pool, scheduler: scheduler, features: features}
}

// SupplyActor is the console caller (a platform member).
type SupplyActor struct {
	UserID, ScopeID uuid.UUID
}

func (a SupplyActor) scheduler() nodescheduler.Actor {
	return nodescheduler.Actor{UserID: a.UserID, ScopeID: a.ScopeID, ScopeKind: "platform"}
}

type SupplyGroupNode struct {
	NodeID  uuid.UUID `json:"node_id"`
	Name    string    `json:"name"`
	Address string    `json:"address"`
	Region  string    `json:"region"`
	Carrier string    `json:"carrier"`
}

type SupplyGroup struct {
	ID       uuid.UUID         `json:"id"`
	Revision int64             `json:"revision"`
	Name     string            `json:"name"`
	Nodes    []SupplyGroupNode `json:"nodes"`
}

type SupplyGroupWrite struct {
	GroupID          uuid.UUID   `json:"-"`
	ExpectedRevision int64       `json:"expected_revision"`
	Name             string      `json:"name"`
	NodeIDs          []uuid.UUID `json:"node_ids"`
	IdempotencyKey   string      `json:"-"`
	RequestID        string      `json:"-"`
}

// Put creates (GroupID nil) or replaces a supply group from a node set.
func (s *SupplyGroups) Put(ctx context.Context, actor SupplyActor, w SupplyGroupWrite) (SupplyGroup, error) {
	ids := slices.Clone(w.NodeIDs)
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	ids = slices.Compact(ids)
	name := strings.TrimSpace(w.Name)
	if len(ids) == 0 && w.GroupID != uuid.Nil {
		// ADR 0012 §18.4 / U3: emptying a supply with a normal subscriber is
		// "stopping supply" (409); otherwise an empty selection stays invalid.
		if err := s.scheduler.CheckMarketSupplyGroupEmptying(ctx, w.GroupID); err != nil {
			return SupplyGroup{}, mapSchedulerError(err)
		}
	}
	if len(ids) == 0 || len(ids) != len(w.NodeIDs) || len(ids) > maxSupplyNodes || slices.Contains(ids, uuid.Nil) ||
		name == "" || len([]rune(name)) > 100 {
		return SupplyGroup{}, ErrSupplyInvalid
	}
	nodes, err := s.loadNodes(ctx, actor.ScopeID, ids)
	if err != nil {
		return SupplyGroup{}, err
	}
	if w.GroupID == uuid.Nil {
		// A retried create (same actor and key) must send the same request:
		// derive the new group's id, and from it the endpoint ids.
		w.GroupID = CreatedGroupID(actor.UserID, w.IdempotencyKey)
	}
	endpoints := make([]nodescheduler.Endpoint, 0, len(nodes))
	for _, node := range nodes {
		endpoints = append(endpoints, nodescheduler.Endpoint{ID: endpointID(w.GroupID, node.NodeID), NodeID: node.NodeID,
			Address: node.Address, Port: supplyGroupPort, Region: node.Region, Carrier: node.Carrier, Weight: 100, Enabled: true})
	}
	result, err := s.scheduler.PutMarketSupplyGroup(ctx, actor.scheduler(), nodescheduler.PutGroupRequest{
		GroupID: w.GroupID, ExpectedRevision: w.ExpectedRevision, Name: supplyGroupLabel + name,
		Note: "节点市场供给（自动生成，不在线路组列表显示）", Endpoints: endpoints,
		IdempotencyKey: w.IdempotencyKey, RequestID: w.RequestID,
	})
	if err != nil {
		return SupplyGroup{}, mapSchedulerError(err)
	}
	return toSupplyGroup(result.Group, nodes), nil
}

// supplyGroupNamespace derives new supply group ids (uuid v5).
var supplyGroupNamespace = uuid.MustParse("6f1d3a52-6c1e-5d0b-9a39-0c8a2f6b7e10")

// CreatedGroupID is the id Put gives a group created by user under key.
func CreatedGroupID(user uuid.UUID, key string) uuid.UUID {
	return uuid.NewSHA1(supplyGroupNamespace, []byte(user.String()+"/"+key))
}

// endpointID keeps a node's endpoint id stable across revisions of a group.
func endpointID(group, node uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(group, node[:])
}

func (s *SupplyGroups) Delete(ctx context.Context, actor SupplyActor, id uuid.UUID, revision int64, key, requestID string) error {
	_, err := s.scheduler.DeleteMarketSupplyGroup(ctx, actor.scheduler(), id, revision, key, requestID)
	return mapSchedulerError(err)
}

func (s *SupplyGroups) Get(ctx context.Context, actor SupplyActor, id uuid.UUID) (SupplyGroup, error) {
	group, err := s.scheduler.GetMarketSupplyGroup(ctx, actor.scheduler(), id)
	if err != nil {
		return SupplyGroup{}, mapSchedulerError(err)
	}
	return toSupplyGroup(group, nil), nil
}

func toSupplyGroup(group nodescheduler.LineGroupRevision, names []SupplyGroupNode) SupplyGroup {
	out := SupplyGroup{ID: group.GroupID, Revision: group.Revision,
		Name: strings.TrimPrefix(group.Name, supplyGroupLabel), Nodes: []SupplyGroupNode{}}
	for _, e := range group.Endpoints {
		node := SupplyGroupNode{NodeID: e.NodeID, Address: e.Address, Region: e.Region, Carrier: e.Carrier}
		if i := slices.IndexFunc(names, func(n SupplyGroupNode) bool { return n.NodeID == e.NodeID }); i >= 0 {
			node.Name = names[i].Name
		}
		out.Nodes = append(out.Nodes, node)
	}
	return out
}

func mapSchedulerError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, nodescheduler.ErrNotFound):
		return ErrSupplyNotFound
	case errors.Is(err, nodescheduler.ErrPermissionDenied), errors.Is(err, nodescheduler.ErrPlatformWriteDenied),
		errors.Is(err, nodescheduler.ErrCredentialInvalid):
		return ErrSupplyForbidden
	case errors.Is(err, nodescheduler.ErrRevisionConflict), errors.Is(err, nodescheduler.ErrIdempotencyConflict),
		errors.Is(err, nodescheduler.ErrReferenceConflict), errors.Is(err, nodescheduler.ErrNameConflict):
		return fmt.Errorf("%w: %w", ErrSupplyConflict, err)
	case errors.Is(err, nodescheduler.ErrInvalidInput), errors.Is(err, nodescheduler.ErrEndpointAddressNotOnNode):
		return fmt.Errorf("%w: %w", ErrSupplyInvalid, err)
	}
	return err
}

// loadNodes reads the selected platform nodes with their primary address
// (IPv4 first) and IP location; every one must be active and public.
func (s *SupplyGroups) loadNodes(ctx context.Context, platform uuid.UUID, ids []uuid.UUID) ([]SupplyGroupNode, error) {
	rows, err := s.pool.Query(ctx, `SELECT node.id, node.name, COALESCE(host(node.ipv4), host(node.ipv6), ''),
			COALESCE(NULLIF(node.management_settings#>>'{ip_location,country_code}',''), node.region),
			COALESCE(node.management_settings#>>'{ip_location,isp}','')
		FROM nodes node JOIN access_scopes scope ON scope.id=node.scope_id AND scope.kind='platform'
		WHERE node.scope_id=$1 AND node.id=ANY($2::uuid[]) AND node.admin_state='active'
		ORDER BY node.id`, platform, ids)
	if err != nil {
		return nil, err
	}
	nodes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SupplyGroupNode, error) {
		var n SupplyGroupNode
		return n, row.Scan(&n.NodeID, &n.Name, &n.Address, &n.Region, &n.Carrier)
	})
	if err != nil {
		return nil, err
	}
	if len(nodes) != len(ids) {
		return nil, ErrSupplyNodeUnusable
	}
	for i := range nodes {
		if nodes[i].Address == "" {
			return nil, ErrSupplyNodeUnusable
		}
		nodes[i].Region = strings.TrimSpace(nodes[i].Region)
		nodes[i].Carrier = strings.TrimSpace(nodes[i].Carrier)
	}
	return nodes, nil
}
