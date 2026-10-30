package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

type createSecurityPolicyRequest struct {
	TargetScopeID string `json:"target_scope_id"`
	OwnerID       string `json:"owner_id"`
	securitypolicy.PolicyFields
}

type securityPolicyImportErrorEnvelope struct {
	Error securityPolicyImportAPIError `json:"error"`
}

type securityPolicyImportAPIError struct {
	Code       string                              `json:"code"`
	Message    string                              `json:"message"`
	RequestID  string                              `json:"request_id"`
	LineErrors []securitypolicy.ACLImportLineError `json:"line_errors"`
}

func (s *Server) handleCreateSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createSecurityPolicyRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	targetScopeID, err := optionalUUID(body.TargetScopeID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "target_scope_id must be a UUID")
		return
	}
	ownerID, err := optionalUUID(body.OwnerID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "owner_id must be a UUID")
		return
	}
	result, err := s.securityPolicies.Create(r.Context(), securityPolicyActor(principal), securitypolicy.CreateRequest{
		TargetScopeID: targetScopeID, OwnerUserID: ownerID, Fields: body.PolicyFields,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		if writeSecurityPolicyImportError(w, r, err) {
			return
		}
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Policy.Revision))
	writeJSONStatus(w, http.StatusCreated, result.Policy)
}

func (s *Server) handleListSecurityPolicies(w http.ResponseWriter, r *http.Request) {
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
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
		return
	}
	var policyID uuid.UUID
	if raw := r.URL.Query().Get("id"); raw != "" {
		policyID, err = uuid.Parse(raw)
		if err != nil || policyID == uuid.Nil || policyID.String() != raw {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "id must be a canonical UUID")
			return
		}
	}
	result, err := s.securityPolicies.List(r.Context(), securityPolicyActor(principal), securitypolicy.ListFilter{
		Page: page, Limit: limit, Kind: r.URL.Query().Get("kind"), Status: r.URL.Query().Get("status"),
		Name: r.URL.Query().Get("name"), ID: policyID, Owner: r.URL.Query().Get("owner"),
		Scope: r.URL.Query().Get("scope"),
	})
	if err != nil {
		if writeSecurityPolicyImportError(w, r, err) {
			return
		}
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleSecurityPolicyCatalogRules returns rules built from the synced system
// rule catalog (GET /v1/security-policies/catalog-rules?kind=waf&keys=a,b or
// kind=cc&keys=cc_rule:N[,cc_rule:M...], up to 8 groups merged in order) so
// the editor pre-fills catalog values.
func (s *Server) handleSecurityPolicyCatalogRules(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.read")
	if !ok {
		return
	}
	keys := strings.Split(r.URL.Query().Get("keys"), ",")
	if len(keys) == 1 && keys[0] == "" {
		keys = nil
	}
	// CC challenges carry proof of work only when every node serving the
	// policy's scope runs it (scope_id: the policy's target scope; default
	// the caller's own).
	scopeID := principal.ScopeID
	if raw := r.URL.Query().Get("scope_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil || parsed.String() != raw {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "scope_id must be a UUID")
			return
		}
		scopeID = parsed
	}
	result, err := s.securityPolicies.CatalogRulesForScope(r.Context(), securityPolicyActor(principal), scopeID,
		r.URL.Query().Get("kind"), keys)
	if err != nil {
		if errors.Is(err, securitypolicy.ErrInvalidInput) {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "unknown or unpublishable system catalog rules")
			return
		}
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.securityPolicyResource(w, r, "security_policies.read")
	if !ok {
		return
	}
	item, err := s.securityPolicies.Get(r.Context(), securityPolicyActor(principal), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(item.Revision))
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleUpdateSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.securityPolicyResource(w, r, "security_policies.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	revision, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	var fields securitypolicy.PolicyFields
	if err := decodeJSON(w, r, &fields); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.securityPolicies.Update(r.Context(), securityPolicyActor(principal), securitypolicy.UpdateRequest{
		ID: id, ExpectedRevision: revision, Fields: fields,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		if writeQuickBlockError(s, w, r, err) {
			return
		}
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Policy.Revision))
	writeJSON(w, http.StatusOK, result.Policy)
}

// handleSetSecurityPolicyQuickBlock replaces a WAF policy's quick block
// switches (PUT /v1/security-policies/{id}/quick-block, If-Match version):
// block CN / global IDC and chosen carriers, with allowed crawlers; the
// policy's system-managed quick block rules follow them.
func (s *Server) handleSetSecurityPolicyQuickBlock(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.securityPolicyResource(w, r, "security_policies.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	revision, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	var block securitypolicy.QuickBlock
	if err := decodeJSON(w, r, &block); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.securityPolicies.SetQuickBlock(r.Context(), securityPolicyActor(principal), securitypolicy.QuickBlockRequest{
		ID: id, ExpectedRevision: revision, QuickBlock: block, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		if writeQuickBlockError(s, w, r, err) {
			return
		}
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Policy.Revision))
	writeJSON(w, http.StatusOK, result.Policy)
}

// handleIPIntelReadiness tells the quick block card whether the control
// plane holds a verified IP intelligence library (GET
// /v1/security-policies/ip-intel-status).
func (s *Server) handleIPIntelReadiness(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.read")
	if !ok {
		return
	}
	revision, err := s.securityPolicies.QuickBlockLibraryStatus(r.Context(), securityPolicyActor(principal))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Ready    bool   `json:"ready"`
		Revision uint64 `json:"revision"`
	}{revision > 0, revision})
}

// handleCRSProfiles lists the downloaded CRS profile packs a managed WAF may
// select (GET /v1/security-policies/crs-profiles, security_policies.read).
func (s *Server) handleCRSProfiles(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.read"); !ok {
		return
	}
	profiles, err := s.securityPolicies.CRSProfiles(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Items []securitypolicy.CRSProfileSummary `json:"items"`
	}{profiles})
}

func writeQuickBlockError(s *Server, w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case errors.Is(err, securitypolicy.ErrQuickBlockIPIntelUnavailable):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "quick_block_ip_intel_unavailable",
			"the IP intelligence library has not been synced to the control plane yet")
	case errors.Is(err, securitypolicy.ErrQuickBlockUnsupported):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "quick_block_unsupported_policy",
			"quick block needs a custom WAF policy whose default action is allow")
	case errors.Is(err, securitypolicy.ErrQuickBlockLastRules):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "quick_block_last_rules",
			"turning quick block off would leave the policy without rules")
	case errors.Is(err, securitypolicy.ErrQuickBlockSiteOverrides):
		// Names the sites whose own quick block the change would break.
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "quick_block_site_override_conflict", err.Error())
	case errors.Is(err, securitypolicy.ErrQuickBlockRuleBudget):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "quick_block_rule_budget",
			"quick block rules and the policy's rules exceed 100 rules")
	default:
		return false
	}
	return true
}

func (s *Server) handleDeleteSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.securityPolicyResource(w, r, "security_policies.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	revision, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	if _, err := s.securityPolicies.Delete(r.Context(), securityPolicyActor(principal), securitypolicy.DeleteRequest{
		ID: id, ExpectedRevision: revision, IdempotencyKey: key, RequestID: requestID(r.Context()),
	}); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleBatchSecurityPolicies (SEC-ACCOUNT-04) enables, disables or deletes
// selected WAF rule libraries (POST /v1/security-policies/batch,
// security_policies.manage, Idempotency-Key). Every item names its version;
// the response carries one result per item in request order, conflicts and
// refusals included, so a partial batch is visible item by item.
func (s *Server) handleBatchSecurityPolicies(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body struct {
		Action string                     `json:"action"`
		Items  []securitypolicy.BatchItem `json:"items"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	results, err := s.securityPolicies.Batch(r.Context(), securityPolicyActor(principal), securitypolicy.BatchRequest{
		Action: body.Action, Items: body.Items, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Items []securitypolicy.BatchItemResult `json:"items"`
	}{results})
}

func (s *Server) handleEvaluateSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.securityPolicyResource(w, r, "security_policies.read")
	if !ok {
		return
	}
	revision, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	var facts securitypolicy.RequestFacts
	if err := decodeJSON(w, r, &facts); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.securityPolicies.Evaluate(r.Context(), securityPolicyActor(principal), id, revision, facts)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) securityPolicyResource(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, uuid.UUID, bool) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, permission)
	if !ok {
		return identity.Principal{}, uuid.Nil, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "security policy ID must be a UUID")
		return identity.Principal{}, uuid.Nil, false
	}
	return principal, id, true
}

func (s *Server) requireSecurityPolicyPermission(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, bool) {
	principal, err := s.authenticatedPrincipal(r)
	if err == nil {
		err = identity.Authorize(principal, permission)
	}
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	return principal, true
}

func securityPolicyActor(principal identity.Principal) securitypolicy.Actor {
	return securitypolicy.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}

func writeSecurityPolicyImportError(w http.ResponseWriter, r *http.Request, err error) bool {
	var failure *securitypolicy.ACLImportError
	if !errors.As(err, &failure) {
		return false
	}
	writeJSONStatus(w, http.StatusUnprocessableEntity, securityPolicyImportErrorEnvelope{Error: securityPolicyImportAPIError{
		Code:       "acl_import_invalid",
		Message:    "ACL import contains invalid lines",
		RequestID:  requestID(r.Context()),
		LineErrors: failure.Lines,
	}})
	return true
}
