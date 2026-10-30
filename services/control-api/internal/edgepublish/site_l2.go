package edgepublish

import (
	"regexp"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/google/uuid"
)

// Site L2 (网站 L2 配置; competitor doc
// ruhepeizhiL2jiedian.md "网站级 L2 配置，仅管理员可设"). The publication
// target's topology (the line group's L2 endpoints) is the package default:
//   - package: the line group's L2 configuration (A19, migration 504), or
//     every topology endpoint when the line group names none;
//   - off: no L2, the site goes straight to its origins;
//   - custom: the site's own L2 configuration.
// An L2 configuration keeps the topology endpoints on its enabled member
// nodes, in member sort order, weighted by the member's weight, balanced by
// its load method (轮询 rr = round_robin, URL哈希 = url_hash). One none of
// whose members is an L2 endpoint of the target is refused (the site would
// silently lose its L2): the operator picks another configuration or turns
// it off. An L2 node the line group does not route to cannot be added: L1
// nodes only trust (mTLS) the L2 endpoints of their target snapshot.

func siteL2Topology(topology *L2TopologySnapshot, fact siteFact) (*L2TopologySnapshot, error) {
	if topology == nil {
		return nil, nil
	}
	if topology.Sites != nil {
		// a node-list publication: resolved per site (siteL2PublicationTopology)
		return topology.Sites[fact.id], nil
	}
	config := topology.Config
	if fact.forwarding != nil {
		switch fact.forwarding.l2Mode {
		case "", "package":
		case "off":
			return nil, nil
		case "custom":
			if fact.forwarding.l2Config == nil {
				// the site's configuration was deleted (497 refuses that
				// while a site uses it) or belongs to another scope
				return nil, ErrSiteL2Unavailable
			}
			config = fact.forwarding.l2Config
		default:
			return nil, ErrInvalidInput
		}
	}
	if config == nil {
		return topology, nil
	}
	selected := *topology
	selected.Config = config
	selected.Endpoints = nil
	selected.Conditions = nil
	conditions := map[uuid.UUID]*L2TopologyCondition{}
	for _, member := range config.Members {
		var condition *L2TopologyCondition
		if member.ConditionID != nil {
			condition = conditions[*member.ConditionID]
			if condition == nil {
				rules, ok := config.Conditions[*member.ConditionID]
				if !ok {
					return nil, ErrTargetSnapshotConflict
				}
				condition = l2TopologyCondition(*member.ConditionID, rules, topology.TargetIdentities)
				conditions[*member.ConditionID] = condition
			}
			if condition.NodeIDs != nil && len(condition.NodeIDs) == 0 {
				// no L1 target matches the condition's node rules: its
				// members serve none of this publication's requests
				continue
			}
		}
		for _, endpoint := range topology.Endpoints {
			if endpoint.NodeID == member.NodeID {
				endpoint.Weight = member.Weight
				selected.Endpoints = append(selected.Endpoints, endpoint)
				if condition != nil {
					condition.EndpointIDs = append(condition.EndpointIDs, endpoint.EndpointID)
				}
			}
		}
	}
	if len(selected.Endpoints) == 0 {
		return nil, ErrSiteL2Unavailable
	}
	for _, condition := range conditions {
		if len(condition.EndpointIDs) != 0 {
			slices.SortFunc(condition.EndpointIDs, compareUUIDText)
			selected.Conditions = append(selected.Conditions, *condition)
		}
	}
	slices.SortFunc(selected.Conditions, func(left, right L2TopologyCondition) int { return compareUUIDText(left.ID, right.ID) })
	return &selected, nil
}

func compareUUIDText(left, right uuid.UUID) int {
	return strings.Compare(left.String(), right.String())
}

// l2TopologyCondition splits an L2 condition's rules (A19-b): the L1 node
// rules are decided here for each target (NodeIDs: the matching targets in
// order; nil without node rules = every target), the request rules go to the
// node (cdnca_origin); neither left = every request. Rules combine with AND (L2条件 "多个匹配条件的关系为且").
func l2TopologyCondition(id uuid.UUID, rules []edgesite.L2Rule, targets []L2TopologyIdentity) *L2TopologyCondition {
	condition := &L2TopologyCondition{ID: id}
	var nodeRules []edgesite.L2Rule
	for _, rule := range rules {
		if strings.HasPrefix(rule.Field, "node_") {
			nodeRules = append(nodeRules, rule)
		} else {
			condition.Rules = append(condition.Rules, rule)
		}
	}
	if len(nodeRules) == 0 {
		return condition
	}
	condition.NodeIDs = []uuid.UUID{}
	for _, target := range targets {
		matched := true
		for _, rule := range nodeRules {
			if !l2NodeRuleMatches(rule, target) {
				matched = false
				break
			}
		}
		if matched {
			condition.NodeIDs = append(condition.NodeIDs, target.NodeID)
		}
	}
	slices.SortFunc(condition.NodeIDs, compareUUIDText)
	if len(condition.NodeIDs) == len(targets) {
		condition.NodeIDs = nil // every target: the request rules decide (none: always)
	}
	return condition
}

// l2NodeRuleMatches: an L1 node rule on the target. 节点ID matches the
// node's display id (节点管理 ID column) or its id; the country code is
// compared upper-case. neq / not_contains / not_regex are the negation of
// eq / contains / regex over every value.
func l2NodeRuleMatches(rule edgesite.L2Rule, target L2TopologyIdentity) bool {
	location := target.Location
	var values []string
	pattern := rule.Value
	switch rule.Field {
	case "node_id":
		values = []string{location.DisplayID, target.NodeID.String()}
		if rule.Operator != "regex" && rule.Operator != "not_regex" {
			pattern = strings.ToLower(pattern)
		}
	case "node_country":
		values = []string{strings.ToUpper(location.CountryCode)}
		if rule.Operator != "regex" && rule.Operator != "not_regex" {
			pattern = strings.ToUpper(pattern)
		}
	case "node_isp":
		values = []string{location.ISP}
	case "node_province":
		values = []string{location.Province}
	case "node_city":
		values = []string{location.City}
	default:
		return false
	}
	operator, negated := rule.Operator, false
	switch operator {
	case "neq":
		operator, negated = "eq", true
	case "not_contains":
		operator, negated = "contains", true
	case "not_regex":
		operator, negated = "regex", true
	}
	var compiled *regexp.Regexp
	if operator == "regex" {
		var err error
		if compiled, err = regexp.Compile(pattern); err != nil {
			return false // refused when written (L2-REGEX-01)
		}
	}
	matched := false
	for _, value := range values {
		if value == "" {
			continue // an unknown location matches no positive rule
		}
		switch operator {
		case "eq":
			matched = value == pattern
		case "contains":
			matched = strings.Contains(value, pattern)
		case "prefix":
			matched = strings.HasPrefix(value, pattern)
		case "suffix":
			matched = strings.HasSuffix(value, pattern)
		case "regex":
			matched = compiled.MatchString(value)
		}
		if matched {
			break
		}
	}
	return matched != negated
}

// l2PoolAlgorithm: the L2 pool's algorithm for the configuration's load
// method; without a configuration the line group's endpoints round robin.
func l2PoolAlgorithm(config *L2TopologyConfig) string {
	if config != nil && config.LoadMethod == "url_hash" {
		return "url_hash"
	}
	return "round_robin"
}
