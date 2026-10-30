package securitypolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Auto switch layers: a site whose auto
// switch follows the system runs, on a platform node, that node's override
// (防火墙配置 → 区域及节点配置, scope node) else its region's (scope region)
// else the platform's global auto switch; a tenant's own node only ever runs
// the global one. The platform global value is the platform scope's global
// document; while it sets no auto_switch, the license's cc_protection
// (materialized into the tenant scope's global document) is the default.

const (
	AutoSwitchSourceGlobal = "global"
	AutoSwitchSourceRegion = "region"
	AutoSwitchSourceNode   = "node"
)

// PlatformNode is a live node of the platform scope and its region name
// (nodes.region, as region overrides name it).
type PlatformNode struct {
	ID     uuid.UUID
	Region string
}

// NodeAutoSwitch is the auto switch a platform node runs and the layer it
// comes from.
type NodeAutoSwitch struct {
	NodeID uuid.UUID          `json:"node_id"`
	Source string             `json:"source"`
	Value  CCSystemAutoSwitch `json:"value"`
}

// ResolveAutoSwitchLayers is each platform node's auto switch, in node ID
// order: its node override, else its region's, else global. Overrides of
// nodes that are not platform nodes are ignored.
func ResolveAutoSwitchLayers(global CCSystemAutoSwitch, regions map[string]CCSystemAutoSwitch,
	nodes map[uuid.UUID]CCSystemAutoSwitch, platformNodes []PlatformNode) []NodeAutoSwitch {
	result := make([]NodeAutoSwitch, 0, len(platformNodes))
	for _, node := range platformNodes {
		item := NodeAutoSwitch{NodeID: node.ID, Source: AutoSwitchSourceGlobal, Value: global}
		if value, ok := regions[strings.TrimSpace(node.Region)]; ok && strings.TrimSpace(node.Region) != "" {
			item.Source, item.Value = AutoSwitchSourceRegion, value
		}
		if value, ok := nodes[node.ID]; ok {
			item.Source, item.Value = AutoSwitchSourceNode, value
		}
		result = append(result, item)
	}
	slices.SortFunc(result, func(left, right NodeAutoSwitch) int { return bytes.Compare(left.NodeID[:], right.NodeID[:]) })
	return result
}

// NodeAutoSwitchOverrides is the nodes whose auto switch differs from
// global: only they need an override on the node.
func NodeAutoSwitchOverrides(global CCSystemAutoSwitch, resolved []NodeAutoSwitch) []NodeAutoSwitch {
	result := make([]NodeAutoSwitch, 0)
	for _, item := range resolved {
		if !sameAutoSwitch(item.Value, global) {
			result = append(result, item)
		}
	}
	return result
}

// sameAutoSwitch compares what the node runs: two switches that are both
// unusable are both off.
func sameAutoSwitch(left, right CCSystemAutoSwitch) bool {
	if !autoSwitchUsable(left) || !autoSwitchUsable(right) {
		return autoSwitchUsable(left) == autoSwitchUsable(right)
	}
	return left.QPSTotal == right.QPSTotal && left.QPS5xx == right.QPS5xx &&
		strings.TrimSpace(left.Rule) == strings.TrimSpace(right.Rule) && recoverSeconds(left) == recoverSeconds(right)
}

func autoSwitchUsable(value CCSystemAutoSwitch) bool {
	return value.Enable && (value.QPSTotal > 0 || value.QPS5xx > 0) && strings.TrimSpace(value.Rule) != ""
}

func recoverSeconds(value CCSystemAutoSwitch) int {
	if value.Seconds == 0 {
		return CCAutoSwitchDefaultRecoverSeconds
	}
	return clampInt(value.Seconds, ccAutoSwitchMinRecoverSeconds, ccAutoSwitchMaxRecoverSeconds)
}

// autoSwitchGlobal is the platform global document's auto_switch, else the
// tenant global document's (the license default), else off.
func autoSwitchGlobal(platformGlobal, tenantGlobal []byte) (CCSystemAutoSwitch, error) {
	for _, raw := range [][]byte{platformGlobal, tenantGlobal} {
		value, set, err := autoSwitchOverride(raw)
		if err != nil {
			return CCSystemAutoSwitch{}, err
		}
		if set {
			return value, nil
		}
	}
	return CCSystemAutoSwitch{}, nil
}

// autoSwitchOverride is a document's auto_switch and whether it sets one.
func autoSwitchOverride(raw []byte) (CCSystemAutoSwitch, bool, error) {
	if len(raw) == 0 {
		return CCSystemAutoSwitch{}, false, nil
	}
	var document struct {
		AutoSwitch *CCSystemAutoSwitch `json:"auto_switch"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return CCSystemAutoSwitch{}, false, err
	}
	if document.AutoSwitch == nil {
		return CCSystemAutoSwitch{}, false, nil
	}
	return *document.AutoSwitch, true, nil
}

// AutoSwitchLayers is the platform's auto switch layers as a tenant's sites
// follow them.
type AutoSwitchLayers struct {
	Global CCSystemAutoSwitch
	// Nodes is every platform node's resolved auto switch (node ID order).
	Nodes []NodeAutoSwitch
}

// LoadAutoSwitchLayers reads the platform global, region and node documents
// (openresty_security_configs of the platform scope) and the platform's live
// nodes; tenantGlobal is the tenant's global document (nil: none).
func LoadAutoSwitchLayers(ctx context.Context, db interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}, tenantGlobal []byte) (AutoSwitchLayers, error) {
	var platformScope uuid.UUID
	err := db.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL ORDER BY id LIMIT 1`).
		Scan(&platformScope)
	if errors.Is(err, pgx.ErrNoRows) {
		global, decodeErr := autoSwitchGlobal(nil, tenantGlobal)
		return AutoSwitchLayers{Global: global, Nodes: []NodeAutoSwitch{}}, decodeErr
	}
	if err != nil {
		return AutoSwitchLayers{}, err
	}
	rows, err := db.Query(ctx, `SELECT scope_type,scope_id,document FROM openresty_security_configs
		WHERE tenant_scope_id=$1 AND deleted_at IS NULL ORDER BY scope_type,scope_id`, platformScope)
	if err != nil {
		return AutoSwitchLayers{}, err
	}
	var platformGlobal []byte
	regions := map[string]CCSystemAutoSwitch{}
	nodes := map[uuid.UUID]CCSystemAutoSwitch{}
	for rows.Next() {
		var scopeType, scopeID string
		var raw []byte
		if err := rows.Scan(&scopeType, &scopeID, &raw); err != nil {
			rows.Close()
			return AutoSwitchLayers{}, err
		}
		if scopeType == "global" {
			platformGlobal = raw
			continue
		}
		value, set, err := autoSwitchOverride(raw)
		if err != nil {
			rows.Close()
			return AutoSwitchLayers{}, err
		}
		if !set {
			continue
		}
		switch scopeType {
		case "region":
			regions[scopeID] = value
		case "node":
			if id, err := uuid.Parse(scopeID); err == nil {
				nodes[id] = value
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return AutoSwitchLayers{}, err
	}
	global, err := autoSwitchGlobal(platformGlobal, tenantGlobal)
	if err != nil {
		return AutoSwitchLayers{}, err
	}
	nodeRows, err := db.Query(ctx, `SELECT id,btrim(region) FROM nodes WHERE scope_id=$1 AND admin_state<>'retired' ORDER BY id`, platformScope)
	if err != nil {
		return AutoSwitchLayers{}, err
	}
	platformNodes, err := pgx.CollectRows(nodeRows, func(row pgx.CollectableRow) (PlatformNode, error) {
		var node PlatformNode
		return node, row.Scan(&node.ID, &node.Region)
	})
	if err != nil {
		return AutoSwitchLayers{}, err
	}
	return AutoSwitchLayers{Global: global, Nodes: ResolveAutoSwitchLayers(global, regions, nodes, platformNodes)}, nil
}
