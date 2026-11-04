package marketprobe

import (
	"context"
	"slices"

	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool report: what the seller's 我的上架 page shows for one
// own pool: whether node reports run, how many nodes would be reported, and
// for every other node why not. It is computed here with the inventory's own
// rules (loadCandidates + classify), so the page cannot disagree with what
// the market receives.

// Further per-node reasons of the report (beyond the classify reasons).
const (
	ReasonNotServing   = "not_serving"   // no serving endpoint on the current revision
	ReasonNodeInactive = "node_inactive" // the node is disabled or retired
)

// PoolReport is one pool's report.
type PoolReport struct {
	// Probe is "running" or why node reports are off (OffDisabled,
	// OffNoEdgeNATS, "market_off").
	Probe      string           `json:"probe"`
	Total      int              `json:"total"`
	Reportable int              `json:"reportable"`
	Nodes      []PoolReportNode `json:"nodes"`
}

// PoolReportNode is one node of the pool. Reason is "" for a reportable
// node. Role and RoleSource are the node's market role (its last answer to
// an assignment, else its heartbeat) and why; RoleCapable says whether the
// Agent takes assignments (MARKET_ROLE).
type PoolReportNode struct {
	NodeID      uuid.UUID `json:"node_id"`
	Name        string    `json:"name"`
	Address     string    `json:"address"`
	Region      string    `json:"region"`
	Carrier     string    `json:"carrier"`
	Reason      string    `json:"reason"`
	Value       string    `json:"value,omitempty"`
	Role        string    `json:"role"`
	RoleSource  string    `json:"role_source,omitempty"`
	RoleCapable bool      `json:"role_capable"`
}

// Reporter answers pool reports. service is the running inventory service
// (nil when node reports are off; off says why).
type Reporter struct {
	pool    *pgxpool.Pool
	service *Service
	off     string
}

func NewReporter(pool *pgxpool.Pool, service *Service, off string) *Reporter {
	if service != nil {
		off = ""
	} else if off == "" {
		off = OffDisabled
	}
	return &Reporter{pool: pool, service: service, off: off}
}

// poolNode is one node of a pool's current revision (any endpoint state).
type poolNode struct {
	NodeID   uuid.UUID
	Name     string
	Active   bool
	Address  string
	Region   string
	Carrier  string
	Role     *string
	Snapshot []byte
}

func loadPoolNodes(ctx context.Context, pool *pgxpool.Pool, groupID uuid.UUID) ([]poolNode, error) {
	rows, err := pool.Query(ctx, `SELECT DISTINCT ON (endpoint.node_id) endpoint.node_id, node.name, node.admin_state='active',
			host(endpoint.address), endpoint.region, endpoint.carrier,
			(SELECT presence.market_probe_role FROM node_presence presence WHERE presence.node_id=endpoint.node_id),
			(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts WHERE facts.node_id=endpoint.node_id
			 ORDER BY facts.session_epoch DESC LIMIT 1)
		FROM node_line_groups line_group
		JOIN access_scopes scope ON scope.id=line_group.tenant_scope_id AND scope.kind='platform'
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
		  AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
		JOIN nodes node ON node.id=endpoint.node_id
		WHERE line_group.id=$1 AND line_group.deleted_at IS NULL
		ORDER BY endpoint.node_id, endpoint.address_family, endpoint.address`, groupID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (poolNode, error) {
		var n poolNode
		return n, row.Scan(&n.NodeID, &n.Name, &n.Active, &n.Address, &n.Region, &n.Carrier, &n.Role, &n.Snapshot)
	})
}

// Report reports one pool (a supply group the caller already may read).
func (r *Reporter) Report(ctx context.Context, groupID uuid.UUID) (PoolReport, error) {
	nodes, err := loadPoolNodes(ctx, r.pool, groupID)
	if err != nil {
		return PoolReport{}, err
	}
	candidates, err := loadGroupCandidates(ctx, r.pool, groupID)
	if err != nil {
		return PoolReport{}, err
	}
	var answers map[string]roleAnswer
	if r.service != nil {
		r.service.mu.Lock()
		answers = r.service.roles
		r.service.mu.Unlock()
	}
	return buildReport(r.off, nodes, candidates, answers), nil
}

// buildReport classifies the serving candidates as the inventory does and
// gives every pool node its reason.
func buildReport(off string, nodes []poolNode, candidates []candidate, answers map[string]roleAnswer) PoolReport {
	report := PoolReport{Probe: "running", Nodes: []PoolReportNode{}}
	if off != "" {
		report.Probe = off
	}
	reported, excluded := classify(withAnswers(candidates, answers))
	reasons := map[uuid.UUID]Excluded{}
	for _, e := range excluded {
		reasons[e.NodeID] = e
	}
	serving := map[uuid.UUID]bool{}
	for _, c := range candidates {
		serving[c.NodeID] = true
	}
	for _, n := range nodes {
		node := PoolReportNode{NodeID: n.NodeID, Name: n.Name, Address: n.Address, Region: n.Region, Carrier: n.Carrier,
			RoleCapable: marketRoleCapable(n.Snapshot)}
		if n.Role != nil {
			node.Role = *n.Role
		}
		if answer, ok := answers[n.NodeID.String()]; ok {
			node.Role, node.RoleSource = roleName(answer.Role), answer.Source
		}
		switch e, excludedNode := reasons[n.NodeID]; {
		case !n.Active:
			node.Reason = ReasonNodeInactive
		case !serving[n.NodeID]:
			node.Reason = ReasonNotServing
		case excludedNode:
			node.Reason, node.Value = e.Reason, e.Value
		case !slices.ContainsFunc(reported, func(p marketclient.PoolNode) bool { return p.NodeID == n.NodeID.String() }):
			node.Reason = ReasonNotServing
		}
		if node.Reason == "" {
			report.Reportable++
		}
		report.Nodes = append(report.Nodes, node)
	}
	report.Total = len(report.Nodes)
	if report.Probe != "running" {
		report.Reportable = 0 // nothing reaches the market while reports are off
	}
	return report
}
