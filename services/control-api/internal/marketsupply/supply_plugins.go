package marketsupply

import (
	"context"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// NodePlugin is one node-side plugin a seller may include in a supply
// (自动防御、高级 CC、CRS 档位、付费规则包、IP 情报、JA4).
// Feature: the lease feature code the installation must hold ("" = free);
// the node must advertise Capability at MinVersion and, when MediaType is
// set, have an item of that media type in its applied artifact set
// (node_artifact_applied_items, from the node's own receipt).
type NodePlugin struct {
	Code       string
	NameZH     string
	NameEN     string
	Feature    string
	Capability agentv1.CapabilityName
	MinVersion uint32
	MediaType  string
}

// NodePlugins is the fixed catalogue, in display order.
var NodePlugins = []NodePlugin{
	{Code: "module.autodefense", NameZH: "智能自动防御（学习、观察、告警）", NameEN: "Automatic defense (learn, observe, alert)",
		Feature: "module.autodefense", Capability: agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE, MinVersion: 1},
	{Code: "module.autodefense.auto", NameZH: "智能自动防御（自动处置）", NameEN: "Automatic defense (automatic mitigation)",
		Feature: "module.autodefense.auto", Capability: agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE, MinVersion: 1},
	{Code: "pack.cc.advanced", NameZH: "高级 CC 规则组", NameEN: "Advanced CC rule groups",
		Feature: "pack.cc.advanced", Capability: agentv1.CapabilityName_CAPABILITY_NAME_CC, MinVersion: 1},
	{Code: "pack.crs", NameZH: "OWASP CRS 档位", NameEN: "OWASP CRS levels",
		Feature: "pack.crs", Capability: agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE, MinVersion: 1,
		MediaType: artifactset.MediaTypeEngineModule},
	{Code: "pack.selfwaf", NameZH: "自研检测规则集", NameEN: "In-house detection rules",
		Feature: "pack.selfwaf", Capability: agentv1.CapabilityName_CAPABILITY_NAME_WAF, MinVersion: 1},
	{Code: "ipintel", NameZH: "IP 情报库", NameEN: "IP intelligence library",
		Capability: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, MinVersion: 2, MediaType: artifactset.MediaTypeIPIntel},
	{Code: "module.ipintel.dnspup", NameZH: "IP 库实时更新（dnspup）", NameEN: "IP intelligence live updates (dnspup)",
		Feature: "module.ipintel.dnspup", Capability: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, MinVersion: 2,
		MediaType: artifactset.MediaTypeIPIntel},
	{Code: "ja4", NameZH: "JA4 指纹", NameEN: "JA4 fingerprints",
		Capability: agentv1.CapabilityName_CAPABILITY_NAME_JA4, MinVersion: 1},
}

type SupplyPlugin struct {
	Code   string `json:"code"`
	NameZH string `json:"name_zh"`
	NameEN string `json:"name_en"`
}

// SupplyPlugins returns the plugins of NodePlugins the lease grants and
// every one of nodeIDs has (an empty list for no nodes or no lease).
// Market rule packs bought on the plugin market are listed too
// ("rule_pack:<pack id>"): the installation holds the pack and every node
// has one of its versions in its applied artifact set.
func (s *SupplyGroups) SupplyPlugins(ctx context.Context, platform uuid.UUID, nodeIDs []uuid.UUID) ([]SupplyPlugin, error) {
	out := []SupplyPlugin{}
	if len(nodeIDs) == 0 || len(nodeIDs) > maxSupplyNodes {
		return out, nil
	}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		perNode, err := s.nodePlugins(ctx, tx, platform, nodeIDs)
		if err != nil || len(perNode) != len(nodeIDs) {
			return err // a node not of this platform: nothing is common
		}
		for _, plugin := range NodePlugins {
			if !slices.ContainsFunc(nodeIDs, func(id uuid.UUID) bool { return !slices.Contains(perNode[id], plugin.Code) }) {
				out = append(out, SupplyPlugin{Code: plugin.Code, NameZH: plugin.NameZH, NameEN: plugin.NameEN})
			}
		}
		packs, err := commonRulePacks(ctx, tx, nodeIDs)
		if err != nil {
			return err
		}
		out = append(out, packs...)
		return nil
	})
	if err != nil || len(out) == 0 {
		return []SupplyPlugin{}, err
	}
	return out, nil
}

// GroupPlugins is SupplyPlugins over a supply group's current nodes.
func (s *SupplyGroups) GroupPlugins(ctx context.Context, actor SupplyActor, id uuid.UUID) ([]SupplyPlugin, error) {
	group, err := s.Get(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(group.Nodes))
	for _, n := range group.Nodes {
		if !slices.Contains(ids, n.NodeID) {
			ids = append(ids, n.NodeID)
		}
	}
	return s.SupplyPlugins(ctx, actor.ScopeID, ids)
}

// NodePluginCodes returns, per active platform node of nodeIDs, the licensed
// plugins of NodePlugins it has that the node market knows (a feature code,
// module.* / pack.*) plus the rule packs it has applied (rule_pack:<pack id>):
// the per-node plugins the leaf reports with its
// pool inventory (PUT /v1/pools/{pool}/nodes). Free plugins (no feature code)
// are not market plugin codes and are left out. Same facts as SupplyPlugins,
// so the market's intersection matches the console's.
func (s *SupplyGroups) NodePluginCodes(ctx context.Context, nodeIDs []uuid.UUID) (map[uuid.UUID][]string, error) {
	out := map[uuid.UUID][]string{}
	if len(nodeIDs) == 0 {
		return out, nil
	}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var platform uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); err != nil {
			return err
		}
		perNode, err := s.nodePlugins(ctx, tx, platform, nodeIDs)
		if err != nil {
			return err
		}
		packs, err := nodeRulePacks(ctx, tx, nodeIDs)
		if err != nil {
			return err
		}
		for id, codes := range perNode {
			codes = append(codes, packs[id]...)
			out[id] = slices.DeleteFunc(codes, func(code string) bool { return !spec.ValidPlugin(code) })
		}
		return nil
	})
	return out, err
}

// nodePlugins returns the codes of NodePlugins each active platform node of
// nodeIDs has and the lease grants (nodes not found are absent).
func (s *SupplyGroups) nodePlugins(ctx context.Context, tx pgx.Tx, platform uuid.UUID, nodeIDs []uuid.UUID) (map[uuid.UUID][]string, error) {
	features := map[string]bool{}
	if s.features != nil {
		var err error
		if features, err = s.features.ReadValidFeatures(ctx, tx); err != nil {
			return nil, err
		}
	}
	facts, err := loadNodeFacts(ctx, tx, platform, nodeIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID][]string, len(facts))
	for _, f := range facts {
		codes := []string{}
		for _, plugin := range NodePlugins {
			if (plugin.Feature == "" || features[plugin.Feature]) && f.has(plugin) {
				codes = append(codes, plugin.Code)
			}
		}
		out[f.id] = codes
	}
	return out, nil
}

type nodeFacts struct {
	id           uuid.UUID
	capabilities []byte
	media        []string
}

func (f nodeFacts) has(plugin NodePlugin) bool {
	return marketprobe.HasCapability(f.capabilities, plugin.Capability, plugin.MinVersion) &&
		(plugin.MediaType == "" || slices.Contains(f.media, plugin.MediaType))
}

// loadNodeFacts reads each active platform node's latest session
// capabilities and applied artifact media types.
func loadNodeFacts(ctx context.Context, tx pgx.Tx, platform uuid.UUID, nodeIDs []uuid.UUID) ([]nodeFacts, error) {
	rows, err := tx.Query(ctx, `SELECT node.id,
			(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts WHERE facts.node_id=node.id
			 ORDER BY facts.session_epoch DESC LIMIT 1),
			COALESCE((SELECT array_agg(DISTINCT item.media_type) FROM node_artifact_applied_items item
			 WHERE item.node_id=node.id), '{}')
		FROM nodes node WHERE node.scope_id=$1 AND node.id=ANY($2::uuid[]) AND node.admin_state='active'`, platform, nodeIDs)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (nodeFacts, error) {
		var f nodeFacts
		return f, row.Scan(&f.id, &f.capabilities, &f.media)
	})
}

// nodeRulePacks lists, per node, the rule_pack:<pack id> codes of the rule
// packs (source catalog or market) one of whose versions the node applied:
// the per-node form of commonRulePacks.
func nodeRulePacks(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) (map[uuid.UUID][]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT item.node_id, artifact.pack_id
		FROM rule_pack_artifacts artifact
		JOIN node_artifact_applied_items item ON item.sha256=artifact.sha256 AND item.media_type=$2
		WHERE artifact.source IN ('catalog','market') AND item.node_id=ANY($1::uuid[])
		ORDER BY item.node_id, artifact.pack_id`, nodeIDs, artifactset.MediaTypeRulePack)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID][]string{}
	var node uuid.UUID
	var pack string
	_, err = pgx.ForEachRow(rows, []any{&node, &pack}, func() error {
		out[node] = append(out[node], "rule_pack:"+pack)
		return nil
	})
	return out, err
}

// commonRulePacks lists the rule packs this installation got from the
// license (source catalog: official) or the plugin market (source market:
// bought) one of whose versions is applied on every node.
func commonRulePacks(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) ([]SupplyPlugin, error) {
	rows, err := tx.Query(ctx, `SELECT artifact.pack_id, min(artifact.name)
		FROM rule_pack_artifacts artifact
		JOIN node_artifact_applied_items item ON item.sha256=artifact.sha256 AND item.media_type=$2
		WHERE artifact.source IN ('catalog','market') AND item.node_id=ANY($1::uuid[])
		GROUP BY artifact.pack_id HAVING count(DISTINCT item.node_id)=$3
		ORDER BY artifact.pack_id`, nodeIDs, artifactset.MediaTypeRulePack, len(nodeIDs))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (SupplyPlugin, error) {
		var pack, name string
		err := row.Scan(&pack, &name)
		return SupplyPlugin{Code: "rule_pack:" + pack, NameZH: name, NameEN: name}, err
	})
}

// maxPluginNames bounds one PluginNames lookup (an offer's tags.plugins).
const maxPluginNames = 64

// PluginNames resolves plugin codes to display names from this
// installation's catalogue (u4g: a resale shows the upstream snapshot's
// codes by name): NodePlugins, then rule_pack:<pack id> by the name of a
// catalog/market rule pack artifact held here. Unknown codes are left out
// (the caller shows the code). Order follows codes, duplicates once.
func (s *SupplyGroups) PluginNames(ctx context.Context, codes []string) ([]SupplyPlugin, error) {
	out := []SupplyPlugin{}
	if len(codes) == 0 || len(codes) > maxPluginNames {
		return out, nil
	}
	packs := []string{}
	for _, code := range codes {
		if pack, ok := strings.CutPrefix(code, "rule_pack:"); ok && pack != "" && !slices.Contains(packs, pack) {
			packs = append(packs, pack)
		}
	}
	names := map[string]string{}
	if len(packs) > 0 {
		rows, err := s.pool.Query(ctx, `SELECT pack_id, min(name) FROM rule_pack_artifacts
			WHERE source IN ('catalog','market') AND pack_id=ANY($1::text[]) GROUP BY pack_id`, packs)
		if err != nil {
			return nil, err
		}
		var pack, name string
		if _, err := pgx.ForEachRow(rows, []any{&pack, &name}, func() error { names[pack] = name; return nil }); err != nil {
			return nil, err
		}
	}
	return pluginNamesOf(codes, names), nil
}

// pluginNamesOf is PluginNames over the fixed catalogue and the rule pack
// names read (pack id → name).
func pluginNamesOf(codes []string, packNames map[string]string) []SupplyPlugin {
	out := []SupplyPlugin{}
	seen := map[string]bool{}
	for _, code := range codes {
		if seen[code] {
			continue
		}
		seen[code] = true
		if i := slices.IndexFunc(NodePlugins, func(p NodePlugin) bool { return p.Code == code }); i >= 0 {
			out = append(out, SupplyPlugin{Code: code, NameZH: NodePlugins[i].NameZH, NameEN: NodePlugins[i].NameEN})
		} else if pack, ok := strings.CutPrefix(code, "rule_pack:"); ok && packNames[pack] != "" {
			out = append(out, SupplyPlugin{Code: code, NameZH: packNames[pack], NameEN: packNames[pack]})
		}
	}
	return out
}
