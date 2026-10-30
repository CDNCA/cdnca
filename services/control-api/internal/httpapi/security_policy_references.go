package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/ccreference"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

const (
	ccReferenceMatcher = "matcher"
	ccReferenceFilter  = "filter"
)

type ccReference struct {
	ID            uuid.UUID                      `json:"id"`
	ScopeID       uuid.UUID                      `json:"scope_id"`
	Owner         *securitypolicy.OwnerReference `json:"owner,omitempty"`
	Name          string                         `json:"name"`
	SystemRule    bool                           `json:"system_rule"`
	SystemRuleID  string                         `json:"system_rule_id,omitempty"`
	SystemRuleKey string                         `json:"system_rule_key,omitempty"`
	Status        string                         `json:"status"`
	Type          string                         `json:"type,omitempty"`
	Sort          int                            `json:"sort,omitempty"`
	CreatedAt     time.Time                      `json:"created_at"`
	PolicyID      uuid.UUID                      `json:"policy_id,omitempty"`
	RuleID        uuid.UUID                      `json:"rule_id,omitempty"`
	Field         string                         `json:"field,omitempty"`
	Operator      string                         `json:"operator,omitempty"`
	Values        []string                       `json:"values,omitempty"`
	Key           string                         `json:"key,omitempty"`
	Description   string                         `json:"description,omitempty"`
	Version       int64                          `json:"version"`
	UpdatedAt     time.Time                      `json:"updated_at,omitempty"`
	Parameters    json.RawMessage                `json:"parameters,omitempty"`
}

type ccReferenceList struct {
	Items []ccReference `json:"items"`
	Total int           `json:"total"`
	Page  int           `json:"page"`
	Limit int           `json:"limit"`
}

func (s *Server) handleListCCMatchers(w http.ResponseWriter, r *http.Request) {
	s.handleListCCReferences(w, r, ccReferenceMatcher)
}

func (s *Server) handleListCCFilters(w http.ResponseWriter, r *http.Request) {
	s.handleListCCReferences(w, r, ccReferenceFilter)
}

func (s *Server) handleListCCReferences(w http.ResponseWriter, r *http.Request, kind string) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.read")
	if !ok {
		return
	}
	page, err := positiveQueryInt(r, "page", 1)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "page must be a positive integer")
		return
	}
	limit, err := positiveQueryInt(r, "limit", 10)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && status != "enabled" && status != "disabled" {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "status must be enabled or disabled")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if len([]rune(name)) > 128 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "name is too long")
		return
	}
	var id uuid.UUID
	if raw := r.URL.Query().Get("id"); raw != "" {
		id, err = uuid.Parse(raw)
		if err != nil || id == uuid.Nil || id.String() != raw {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "id must be a canonical UUID")
			return
		}
	}
	owner := strings.TrimSpace(r.URL.Query().Get("owner"))
	if len([]rune(owner)) > 128 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "owner is too long")
		return
	}
	if kind != ccReferenceMatcher && kind != ccReferenceFilter {
		s.writeAPIError(w, r, http.StatusNotFound, "not_found", "security policy reference not found")
		return
	}

	requestedType := strings.TrimSpace(r.URL.Query().Get("type"))
	if requestedType != "" && len([]rune(requestedType)) > 64 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "type is too long")
		return
	}
	referenceKind := ccreference.KindMatcher
	if kind == ccReferenceFilter {
		referenceKind = ccreference.KindFilter
	}
	result, err := s.ccReferences.List(r.Context(), securityPolicyCCReferenceActor(principal), referenceKind, ccreference.ListFilter{
		Page: page, Limit: limit, Status: status, Name: name, ID: id, Owner: owner, Type: requestedType,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	items := make([]ccReference, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, mapCCReferenceForScope(item, principal.ScopeKind))
	}
	writeJSON(w, http.StatusOK, ccReferenceList{Items: items, Total: int(result.Total), Page: result.Page, Limit: result.Limit})
}

func securityPolicyCCReferenceActor(principal identity.Principal) ccreference.Actor {
	return ccreference.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}

func mapCCReference(item ccreference.Item) ccReference {
	owner := (*securitypolicy.OwnerReference)(nil)
	if item.Owner != nil {
		owner = &securitypolicy.OwnerReference{ID: item.Owner.ID, DisplayName: item.Owner.DisplayName}
	}
	return ccReference{
		ID: item.ID, ScopeID: item.ScopeID, Owner: owner, Name: item.Name, SystemRule: item.SystemRule,
		SystemRuleID: item.SystemRuleID, SystemRuleKey: item.SystemRuleKey,
		Status: referenceStatus(item.Enabled), Type: item.Type, Sort: item.Sort, CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt, PolicyID: item.PolicyID, RuleID: item.RuleID, Field: item.Field,
		Operator: item.Operator, Key: item.Key, Values: item.Values, Description: item.Description,
		Version: item.Revision, Parameters: item.Parameters,
	}
}

func mapCCReferenceForScope(item ccreference.Item, scopeKind string) ccReference {
	result := mapCCReference(item)
	if scopeKind == "tenant" {
		result.Owner = nil
		if item.SystemRule {
			result.Description = ""
			result.PolicyID = uuid.Nil
			result.RuleID = uuid.Nil
			result.Field = ""
			result.Operator = ""
			result.Key = ""
			result.Values = nil
			result.Parameters = nil
			result.UpdatedAt = time.Time{}
		}
	}
	return result
}

func (s *Server) listAllCCReferencePolicies(r *http.Request, principal identity.Principal, status, owner string) ([]securitypolicy.Policy, error) {
	actor := securityPolicyActor(principal)
	const batchSize = 100
	policies := make([]securitypolicy.Policy, 0)
	for page := 1; ; page++ {
		result, err := s.securityPolicies.List(r.Context(), actor, securitypolicy.ListFilter{
			Page: page, Limit: batchSize, Kind: securitypolicy.KindCC, Status: status, Owner: owner,
		})
		if err != nil {
			return nil, err
		}
		policies = append(policies, result.Items...)
		if len(policies) >= int(result.Total) || len(result.Items) == 0 {
			return policies, nil
		}
	}
}

func projectCCReferences(policies []securitypolicy.Policy, kind string) []ccReference {
	items := make([]ccReference, 0)
	for _, policy := range policies {
		for ruleIndex, rule := range policy.Rules {
			if kind == ccReferenceMatcher {
				conditions := rule.Conditions
				if len(conditions) == 0 {
					conditions = []securitypolicy.Condition{{Field: "all", Operator: "equals", Values: []string{"*"}}}
				}
				for conditionIndex, condition := range conditions {
					id := referenceID(policy.ID, rule.ID, kind, conditionIndex)
					name := strings.TrimSpace(rule.Name)
					if name == "" {
						name = strings.TrimSpace(policy.Name)
					}
					if len(conditions) > 1 {
						name = fmt.Sprintf("%s · %s", name, condition.Field)
					}
					items = append(items, ccReference{
						ID: id, ScopeID: policy.ScopeID, Owner: policy.Owner, Name: name,
						SystemRule: false, Status: referenceStatus(policy.Enabled && rule.Enabled),
						Sort: rule.Priority, CreatedAt: policy.CreatedAt, PolicyID: policy.ID, RuleID: rule.ID,
						Field: condition.Field, Operator: condition.Operator, Values: append([]string(nil), condition.Values...),
					})
				}
				continue
			}
			filterType := projectedFilterType(rule)
			if filterType == "" {
				continue
			}
			name := strings.TrimSpace(rule.Name)
			if name == "" {
				name = strings.TrimSpace(policy.Name)
			}
			items = append(items, ccReference{
				ID: referenceID(policy.ID, rule.ID, kind, ruleIndex), ScopeID: policy.ScopeID, Owner: policy.Owner,
				Name: name, SystemRule: false, Status: referenceStatus(policy.Enabled && rule.Enabled), Type: filterType,
				Sort: rule.Priority, CreatedAt: policy.CreatedAt, PolicyID: policy.ID, RuleID: rule.ID,
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if !items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].ID.String() > items[j].ID.String()
	})
	return items
}

func projectedFilterType(rule securitypolicy.Rule) string {
	if rule.ActionConfig.RateLimit != nil {
		return "req_rate"
	}
	if rule.ActionConfig.Challenge != nil && strings.TrimSpace(rule.ActionConfig.Challenge.Type) != "" {
		return strings.TrimSpace(rule.ActionConfig.Challenge.Type)
	}
	switch rule.Action {
	case securitypolicy.ActionRateLimit:
		return "req_rate"
	case securitypolicy.ActionChallenge:
		return "challenge"
	default:
		return ""
	}
}

func referenceStatus(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func referenceID(policyID, ruleID uuid.UUID, kind string, index int) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("cdnca/security-policy-reference/%s/%s/%s/%d", policyID, ruleID, kind, index)))
}

func filterCCReferences(items []ccReference, keep func(ccReference) bool) []ccReference {
	filtered := make([]ccReference, 0, len(items))
	for _, item := range items {
		if keep(item) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}
