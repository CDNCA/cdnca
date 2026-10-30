package analyticslog

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/cdnca/cdnca/libs/rulepack"
)

// fix-wafname: rule pack rule names. The node runs a pack rule under
// rulepack.NodeRuleID(pack_id, rule_id) in the segment of policy
// NodeRuleID(pack_id, "@pack"); the names are in the stored artifacts
// (rule_pack_artifacts.content: official system packs, developer / market
// packs, a tenant's own packs, WAF subscription and auto defense solidified
// packs). A sealed pack names only its exported rules (manifest).

// packNames is one artifact's pack name and pack-local rule names.
type packNames struct {
	packID, name string
	rules        map[string]string
}

// packNamesOf reads the names of a stored artifact (plaintext pack or sealed
// manifest); packID "" when it is neither.
func packNamesOf(content []byte) packNames {
	var document struct {
		Schema string `json:"schema"`
		PackID string `json:"pack_id"`
		Name   string `json:"name"`
		Rules  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"rules"`
		Manifest struct {
			PackID      string            `json:"pack_id"`
			Name        string            `json:"name"`
			ExportNames map[string]string `json:"export_names"`
		} `json:"manifest"`
	}
	if json.Unmarshal(content, &document) != nil {
		return packNames{}
	}
	if document.Schema == rulepack.SealedSchema {
		return packNames{packID: document.Manifest.PackID, name: document.Manifest.Name, rules: document.Manifest.ExportNames}
	}
	names := packNames{packID: document.PackID, name: document.Name, rules: make(map[string]string, len(document.Rules))}
	for _, rule := range document.Rules {
		names.rules[rule.ID] = rule.Name
	}
	return names
}

// packIndex is packNames keyed the way events name them.
type packIndex struct {
	segment, name string
	nodes         map[string]string // node rule ID -> "<pack> · <rule>"
}

func indexPack(pack packNames) packIndex {
	index := packIndex{segment: rulepack.NodeRuleID(pack.packID, "@pack"), name: boundName(pack.name),
		nodes: make(map[string]string, len(pack.rules))}
	for id, name := range pack.rules {
		if name != "" {
			index.nodes[rulepack.NodeRuleID(pack.packID, id)] = joinName(pack.name, name)
		}
	}
	return index
}

// addPack adds every name of pack; a name already known (a newer version
// added first) is kept.
func (names *EventNames) addPack(pack packNames) {
	if pack.packID != "" {
		names.addIndex(indexPack(pack), nil)
	}
}

// addIndex adds the names of index the refs use (nil: all of them).
func (names *EventNames) addIndex(index packIndex, refs []EventNameRef) {
	if names.Rules == nil {
		names.Rules = map[string]map[string]string{}
	}
	if names.Policies == nil {
		names.Policies = map[string]string{}
	}
	rules := names.Rules[index.segment]
	add := func(ruleID string) {
		name := index.nodes[ruleID]
		if name == "" {
			return
		}
		if rules == nil {
			rules = map[string]string{}
			names.Rules[index.segment] = rules
		}
		if _, known := rules[ruleID]; !known {
			rules[ruleID] = name
		}
	}
	used := refs == nil
	for _, ref := range refs {
		if strings.ToLower(ref.PolicyID) == index.segment {
			used = true
		}
		add(strings.ToLower(ref.RuleID))
	}
	if refs == nil {
		for ruleID := range index.nodes {
			add(ruleID)
		}
	}
	if _, known := names.Policies[index.segment]; (used || rules != nil) && !known && index.name != "" {
		names.Policies[index.segment] = index.name
	}
}

// maxCachedPacks bounds the per-process cache of artifact names (artifacts
// are immutable: keyed by sha256); a full cache starts over.
const maxCachedPacks = 4096

type packNameCache struct {
	mu      sync.Mutex
	entries map[string]packIndex
}

func (cache *packNameCache) get(sha string) (packIndex, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry, ok := cache.entries[sha]
	return entry, ok
}

func (cache *packNameCache) put(sha string, entry packIndex) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.entries == nil || len(cache.entries) >= maxCachedPacks {
		cache.entries = map[string]packIndex{}
	}
	cache.entries[sha] = entry
}

// eventPackArtifactsSQL: the downloaded artifacts the tenant's sites can
// mount (platform system / developer packs and the tenant's own user
// packs; every pack in the platform view), current version first.
const eventPackArtifactsSQL = `SELECT artifact.sha256
	FROM rule_pack_artifacts artifact
	JOIN rule_packs pack ON pack.pack_id=artifact.pack_id
	LEFT JOIN access_scopes scope ON scope.id=pack.owner_scope_id
	WHERE artifact.state='downloaded' AND ($1::uuid IS NULL OR pack.owner_scope_id IS NULL OR scope.tenant_id=$1::uuid)
	ORDER BY artifact.pack_id, artifact.version IS NOT DISTINCT FROM pack.current_version DESC, artifact.created_at DESC`

const eventPackContentSQL = `SELECT sha256, content FROM rule_pack_artifacts WHERE sha256=ANY($1::text[]) AND content IS NOT NULL`

// lookupPacks adds the pack names refs use.
func (lookup *PostgresEventNameLookup) lookupPacks(ctx context.Context, tenant any, refs []EventNameRef, names *EventNames) {
	rows, err := lookup.pool.Query(ctx, eventPackArtifactsSQL, tenant)
	if err != nil {
		lookup.logger.WarnContext(ctx, "security event pack names failed", "error", err)
		return
	}
	var shas, missing []string
	for rows.Next() {
		var sha string
		if rows.Scan(&sha) == nil {
			shas = append(shas, sha)
			if _, ok := lookup.packs.get(sha); !ok {
				missing = append(missing, sha)
			}
		}
	}
	rows.Close()
	if len(missing) > 0 {
		contents, err := lookup.pool.Query(ctx, eventPackContentSQL, missing)
		if err != nil {
			lookup.logger.WarnContext(ctx, "security event pack contents failed", "error", err)
			return
		}
		for contents.Next() {
			var sha string
			var content []byte
			if contents.Scan(&sha, &content) == nil {
				if pack := packNamesOf(content); pack.packID != "" {
					lookup.packs.put(sha, indexPack(pack))
				} else {
					lookup.packs.put(sha, packIndex{})
				}
			}
		}
		contents.Close()
	}
	for _, sha := range shas {
		if index, ok := lookup.packs.get(sha); ok && index.segment != "" {
			names.addIndex(index, refs)
		}
	}
}
