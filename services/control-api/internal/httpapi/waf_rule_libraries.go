package httpapi

import (
	"net/http"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/platformpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

type wafRuleLibraryResponse struct {
	ID           string                `json:"id"`
	Name         string                `json:"name"`
	Description  string                `json:"description"`
	Origin       string                `json:"origin"`
	Scope        string                `json:"scope"`
	Owner        string                `json:"owner,omitempty"`
	Enabled      bool                  `json:"enabled"`
	Subscription string                `json:"subscription"`
	Protected    bool                  `json:"protected"`
	Revision     int64                 `json:"revision"`
	UpdatedAt    string                `json:"updated_at"`
	Rules        []securitypolicy.Rule `json:"rules,omitempty"`
}

type wafRuleLibraryListResponse struct {
	Items []wafRuleLibraryResponse `json:"items"`
	Total int                      `json:"total"`
	Page  int                      `json:"page"`
	Limit int                      `json:"limit"`
}

func (s *Server) handleListWAFRuleLibraries(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.read")
	if !ok {
		return
	}
	page, err := positiveQueryInt(r, "page", 1)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "page must be a positive integer")
		return
	}
	limit, err := positiveQueryInt(r, "limit", 20)
	if err != nil || limit > 100 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit must be between 1 and 100")
		return
	}
	items, err := s.wafRuleLibraryItems(r, principal)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	filtered := items[:0]
	for _, item := range items {
		if name != "" && !strings.Contains(strings.ToLower(item.Name), strings.ToLower(name)) {
			continue
		}
		if scope != "" && item.Scope != scope {
			continue
		}
		if status == "enabled" && !item.Enabled || status == "disabled" && item.Enabled {
			continue
		}
		filtered = append(filtered, item)
	}
	if status != "" && status != "enabled" && status != "disabled" || scope != "" && scope != "global" && scope != "user" {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "scope or status is invalid")
		return
	}
	start := (page - 1) * limit
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	writeJSON(w, http.StatusOK, wafRuleLibraryListResponse{Items: filtered[start:end], Total: len(filtered), Page: page, Limit: limit})
}

func (s *Server) handleSubscribeWAFRuleLibrary(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.wafRuleLibraryResource(w, r, "security_policies.manage")
	if !ok {
		return
	}
	library, ok := s.platformWAFRuleLibrary(id)
	if !ok {
		s.writeAPIError(w, r, http.StatusNotFound, "not_found", "WAF rule library was not found")
		return
	}
	if _, err := s.securityPolicies.UpsertLicensedWAF(r.Context(), securityPolicyActor(principal), licensedWAFDefinition(library), wafOperationKey(r, "subscribe"), requestID(r.Context())); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUnsubscribeWAFRuleLibrary(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.wafRuleLibraryResource(w, r, "security_policies.manage")
	if !ok {
		return
	}
	if _, ok := s.platformWAFRuleLibrary(id); !ok {
		s.writeAPIError(w, r, http.StatusNotFound, "not_found", "WAF rule library was not found")
		return
	}
	if err := s.securityPolicies.RemoveLicensedWAF(r.Context(), securityPolicyActor(principal), id.String(), wafOperationKey(r, "unsubscribe"), requestID(r.Context())); err != nil {
		if err == securitypolicy.ErrNotFound {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRefreshWAFRuleLibraries(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.manage")
	if !ok {
		return
	}
	subscriptions, err := s.securityPolicies.ListLicensedWAFSubscriptions(r.Context(), securityPolicyActor(principal))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	for _, subscription := range subscriptions {
		libraryID, parseErr := uuid.Parse(subscription.Metadata.LibraryID)
		if parseErr != nil {
			continue
		}
		library, exists := s.platformWAFRuleLibrary(libraryID)
		if !exists {
			continue
		}
		if _, err := s.securityPolicies.UpsertLicensedWAF(r.Context(), securityPolicyActor(principal), licensedWAFDefinition(library), wafOperationKey(r, "refresh"), requestID(r.Context())); err != nil {
			s.writeError(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) wafRuleLibraryItems(r *http.Request, principal identity.Principal) ([]wafRuleLibraryResponse, error) {
	actor := securityPolicyActor(principal)
	custom, err := s.securityPolicies.ListRawWAF(r.Context(), actor)
	if err != nil {
		return nil, err
	}
	subscribed, err := s.securityPolicies.ListLicensedWAFSubscriptions(r.Context(), actor)
	if err != nil {
		return nil, err
	}
	subscriptions := make(map[string]securitypolicy.LicensedWAFSubscription, len(subscribed))
	for _, item := range subscribed {
		subscriptions[item.Metadata.LibraryID] = item
	}
	items := make([]wafRuleLibraryResponse, 0, len(custom)+8)
	for _, library := range s.platformWAFRuleLibraries() {
		subscription, exists := subscriptions[library.ID.String()]
		status := "not_subscribed"
		if exists && subscription.Metadata.Revision == int64(library.Revision) {
			status = "subscribed"
		} else if exists {
			status = "update_available"
		}
		updatedAt := ""
		if s.now != nil {
			updatedAt = s.now().UTC().Format("2006-01-02T15:04:05Z")
		}
		items = append(items, wafRuleLibraryResponse{ID: library.ID.String(), Name: library.Name, Description: library.Description,
			Origin: "system", Scope: "global", Owner: "平台授权中心", Enabled: library.Enabled, Subscription: status,
			Protected: true, Revision: int64(library.Revision), UpdatedAt: updatedAt})
	}
	for _, policy := range custom {
		if policy.Protected {
			continue
		}
		owner := ""
		if policy.Owner != nil {
			owner = policy.Owner.DisplayName
		}
		items = append(items, wafRuleLibraryResponse{ID: policy.ID.String(), Name: policy.Name, Description: policy.Description,
			Origin: "custom", Scope: "user", Owner: owner, Enabled: policy.Enabled, Subscription: "not_applicable",
			Protected: false, Revision: policy.Revision, UpdatedAt: policy.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"), Rules: policy.Rules})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}

func (s *Server) platformWAFRuleLibraries() []platformpolicy.WAFRuleLibrary {
	if s.platformPolicyState == nil {
		return nil
	}
	snapshot, stale := s.platformPolicyState.Snapshot()
	if stale || snapshot.Defaulted {
		return nil
	}
	return snapshot.Policy.WAFRuleLibraries
}

func (s *Server) platformWAFRuleLibrary(id uuid.UUID) (platformpolicy.WAFRuleLibrary, bool) {
	for _, library := range s.platformWAFRuleLibraries() {
		if library.ID == id {
			return library, true
		}
	}
	return platformpolicy.WAFRuleLibrary{}, false
}

func licensedWAFDefinition(library platformpolicy.WAFRuleLibrary) securitypolicy.LicensedWAFDefinition {
	rules := make([]securitypolicy.Rule, len(library.Rules))
	for i, rule := range library.Rules {
		conditions := make([]securitypolicy.Condition, len(rule.Conditions))
		for j, condition := range rule.Conditions {
			conditions[j] = securitypolicy.Condition{Field: condition.Field, Operator: condition.Operator, Key: condition.Key, Values: append([]string(nil), condition.Values...)}
		}
		rules[i] = securitypolicy.Rule{ID: rule.ID, Name: rule.Name, Priority: rule.Priority, Enabled: rule.Enabled,
			Conditions: conditions, Action: rule.Action, Flow: rule.Flow}
	}
	return securitypolicy.LicensedWAFDefinition{LibraryID: library.ID.String(), Revision: int64(library.Revision), Name: library.Name,
		Description: library.Description, Enabled: library.Enabled, DefaultAction: securitypolicy.ActionAllow, Rules: rules}
}

func (s *Server) wafRuleLibraryResource(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, uuid.UUID, bool) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, permission)
	if !ok {
		return identity.Principal{}, uuid.Nil, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil || id.String() != r.PathValue("id") {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "WAF rule library ID must be a canonical UUID")
		return identity.Principal{}, uuid.Nil, false
	}
	return principal, id, true
}

func wafOperationKey(r *http.Request, operation string) string {
	if value := strings.TrimSpace(r.Header.Get("Idempotency-Key")); value != "" {
		return value
	}
	return "waf-library-" + operation + "-" + uuid.NewString()
}
