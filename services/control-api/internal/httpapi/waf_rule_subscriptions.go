package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/wafsubscription"
	"github.com/google/uuid"
)

// The HTTP server's write timeout is 30 s; a manual sync gives the fetch
// less than that and the fetch records its outcome either way.
const wafSubscriptionSyncTimeout = 25 * time.Second

type wafRuleSubscriptionListResponse struct {
	Items []wafsubscription.Subscription `json:"items"`
}

// WAFSubscriptions is the service the server runs; main starts its poll loop.
func (s *Server) WAFSubscriptions() *wafsubscription.Service { return s.wafSubscriptions }

func (s *Server) handleListWAFRuleSubscriptions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireWAFSubscriptionOperator(w, r, "security_policies.read"); !ok {
		return
	}
	items, err := s.wafSubscriptions.List(r.Context(), false)
	if err != nil {
		s.writeWAFSubscriptionError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wafRuleSubscriptionListResponse{Items: items})
}

func (s *Server) handleCreateWAFRuleSubscription(w http.ResponseWriter, r *http.Request) {
	operator, ok := s.requireWAFSubscriptionOperator(w, r, "security_policies.manage")
	if !ok {
		return
	}
	var input wafsubscription.Input
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	item, err := s.wafSubscriptions.Create(r.Context(), operator, input)
	if err != nil {
		s.writeWAFSubscriptionError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) handleUpdateWAFRuleSubscription(w http.ResponseWriter, r *http.Request) {
	operator, id, ok := s.wafSubscriptionResource(w, r, "security_policies.manage")
	if !ok {
		return
	}
	var input wafsubscription.Input
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	item, err := s.wafSubscriptions.Update(r.Context(), operator, id, input)
	if err != nil {
		s.writeWAFSubscriptionError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleDeleteWAFRuleSubscription(w http.ResponseWriter, r *http.Request) {
	operator, id, ok := s.wafSubscriptionResource(w, r, "security_policies.manage")
	if !ok {
		return
	}
	if err := s.wafSubscriptions.Delete(r.Context(), operator, id); err != nil {
		s.writeWAFSubscriptionError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSyncWAFRuleSubscription is "立即更新订阅": it fetches now and
// returns the library with the outcome (last_error empty on success).
func (s *Server) handleSyncWAFRuleSubscription(w http.ResponseWriter, r *http.Request) {
	operator, id, ok := s.wafSubscriptionResource(w, r, "security_policies.manage")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), wafSubscriptionSyncTimeout)
	defer cancel()
	item, err := s.wafSubscriptions.Sync(ctx, operator, id)
	if err != nil {
		s.writeWAFSubscriptionError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) requireWAFSubscriptionOperator(w http.ResponseWriter, r *http.Request, permission string) (wafsubscription.Operator, bool) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, permission)
	if !ok {
		return wafsubscription.Operator{}, false
	}
	if principal.ScopeKind != "platform" || s.wafSubscriptions == nil {
		s.writeAPIError(w, r, http.StatusForbidden, "forbidden", "WAF rule subscriptions are managed by platform operators")
		return wafsubscription.Operator{}, false
	}
	return s.wafSubscriptionActor(r, principal), true
}

func (s *Server) wafSubscriptionResource(w http.ResponseWriter, r *http.Request, permission string) (wafsubscription.Operator, uuid.UUID, bool) {
	operator, ok := s.requireWAFSubscriptionOperator(w, r, permission)
	if !ok {
		return wafsubscription.Operator{}, uuid.Nil, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil || id.String() != r.PathValue("id") {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "WAF rule subscription ID must be a canonical UUID")
		return wafsubscription.Operator{}, uuid.Nil, false
	}
	return operator, id, true
}

func (s *Server) wafSubscriptionActor(r *http.Request, principal identity.Principal) wafsubscription.Actor {
	return wafsubscription.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
		RequestID: requestID(r.Context()), SourceIP: s.requestInfo(r).SourceIP}
}

func (s *Server) writeWAFSubscriptionError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, wafsubscription.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", err.Error())
	case errors.Is(err, wafsubscription.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "not_found", "WAF rule subscription was not found")
	case errors.Is(err, wafsubscription.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "forbidden", "WAF rule subscriptions are managed by platform operators")
	case errors.Is(err, wafsubscription.ErrNotReady):
		s.writeAPIError(w, r, http.StatusConflict, "waf_subscription_not_ready", "the subscription has not been fetched yet")
	default:
		s.writeError(w, r, err)
	}
}

type wafSubscriptionPackListResponse struct {
	Items []wafsubscription.SubscriberPack `json:"items"`
}

type tenantWAFRuleSubscriptionListResponse struct {
	Items []wafsubscription.TenantSubscription `json:"items"`
}

// handleListWAFSubscriptionPacks lists subscriber packs (every tenant's for
// a platform operator, optionally ?subscription_id=; the own tenant's
// otherwise) with the published sites still on an older version ("待发布").
func (s *Server) handleListWAFSubscriptionPacks(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.read")
	if !ok {
		return
	}
	var only *uuid.UUID
	if raw := r.URL.Query().Get("subscription_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil || id.String() != raw {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "subscription_id must be a canonical UUID")
			return
		}
		only = &id
	}
	if s.wafSubscriptions == nil {
		writeJSON(w, http.StatusOK, wafSubscriptionPackListResponse{Items: []wafsubscription.SubscriberPack{}})
		return
	}
	items, err := s.wafSubscriptions.SubscriberPacks(r.Context(), s.wafSubscriptionActor(r, principal), only)
	if err != nil {
		s.writeWAFSubscriptionError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wafSubscriptionPackListResponse{Items: items})
}

// handleListTenantWAFRuleSubscriptions is the tenant's list: subscriptions
// it can subscribe to and the ones it keeps a pack of.
func (s *Server) handleListTenantWAFRuleSubscriptions(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.tenantWAFSubscriptionActor(w, r, "security_policies.read")
	if !ok {
		return
	}
	items, err := s.wafSubscriptions.TenantList(r.Context(), actor, nil)
	if err != nil {
		s.writeWAFSubscriptionError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, tenantWAFRuleSubscriptionListResponse{Items: items})
}

// handleSubscribeWAFRuleSubscription gives the caller's tenant its user
// layer rule pack of the subscription (downloaded, not enabled).
func (s *Server) handleSubscribeWAFRuleSubscription(w http.ResponseWriter, r *http.Request) {
	actor, id, ok := s.tenantWAFSubscriptionResource(w, r)
	if !ok {
		return
	}
	item, err := s.wafSubscriptions.Subscribe(r.Context(), actor, id)
	if err != nil {
		s.writeWAFSubscriptionError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// handleUnsubscribeWAFRuleSubscription stops updating the tenant's pack;
// the pack stays until it is deleted on the rule pack page.
func (s *Server) handleUnsubscribeWAFRuleSubscription(w http.ResponseWriter, r *http.Request) {
	actor, id, ok := s.tenantWAFSubscriptionResource(w, r)
	if !ok {
		return
	}
	if err := s.wafSubscriptions.Unsubscribe(r.Context(), actor, id); err != nil {
		s.writeWAFSubscriptionError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) tenantWAFSubscriptionActor(w http.ResponseWriter, r *http.Request, permission string) (wafsubscription.Actor, bool) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, permission)
	if !ok {
		return wafsubscription.Actor{}, false
	}
	if principal.ScopeKind != "tenant" || s.wafSubscriptions == nil {
		s.writeAPIError(w, r, http.StatusForbidden, "forbidden", "WAF rule subscriptions are subscribed by tenants")
		return wafsubscription.Actor{}, false
	}
	return s.wafSubscriptionActor(r, principal), true
}

func (s *Server) tenantWAFSubscriptionResource(w http.ResponseWriter, r *http.Request) (wafsubscription.Actor, uuid.UUID, bool) {
	actor, ok := s.tenantWAFSubscriptionActor(w, r, "security_policies.manage")
	if !ok {
		return wafsubscription.Actor{}, uuid.Nil, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil || id.String() != r.PathValue("id") {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "WAF rule subscription ID must be a canonical UUID")
		return wafsubscription.Actor{}, uuid.Nil, false
	}
	return actor, id, true
}

type wafPendingPublicationListResponse struct {
	Items []wafsubscription.PendingPublication `json:"items"`
}

// handleListWAFPendingPublications lists the caller's sites whose bound
// platform library copy has a newer version than the published one.
// Publishing them stays a confirmed activation. (Subscription packs list
// their pending sites at /v1/waf-rule-subscriptions/packs.)
func (s *Server) handleListWAFPendingPublications(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.read")
	if !ok {
		return
	}
	if s.wafSubscriptions == nil {
		writeJSON(w, http.StatusOK, wafPendingPublicationListResponse{Items: []wafsubscription.PendingPublication{}})
		return
	}
	items, err := s.wafSubscriptions.PendingPublications(r.Context(), securityPolicyActor(principal))
	if err != nil {
		s.writeWAFSubscriptionError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wafPendingPublicationListResponse{Items: items})
}
