package httpapi

import (
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnssettings"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type updateDNSSettingsRequest struct {
	TTL int `json:"ttl"`
}

type dnsOperationResponse struct {
	Operation dnssettings.Operation `json:"operation"`
	Replayed  bool                  `json:"replayed"`
}

func (s *Server) handleGetDNSSettings(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.read")
	if !ok {
		return
	}
	if s.dnsSettings == nil {
		s.writeError(w, r, dnssettings.ErrUnavailable)
		return
	}
	result, err := s.dnsSettings.Get(r.Context(), dnsSettingsActor(principal))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleUpdateDNSSettings(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	version, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	var body updateDNSSettingsRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if s.dnsSettings == nil || principal.TenantID == nil {
		s.writeError(w, r, dnssettings.ErrUnavailable)
		return
	}
	result, err := s.dnsSettings.Update(r.Context(), dnsSettingsActor(principal), dnssettings.UpdateRequest{
		TTL: body.TTL, ExpectedRevision: version, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleStartDNSOperation(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body struct{}
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body must be an empty JSON object")
		return
	}
	kind := strings.TrimSpace(r.PathValue("kind"))
	if kind != dnssettings.OperationRepair && kind != dnssettings.OperationCleanup {
		s.writeAPIError(w, r, http.StatusNotFound, "dns_operation_not_found", "DNS operation was not found")
		return
	}
	if s.dnsSettings == nil || principal.TenantID == nil {
		s.writeError(w, r, dnssettings.ErrUnavailable)
		return
	}
	result, replayed, err := s.dnsSettings.StartOperation(r.Context(), dnsSettingsActor(principal), dnssettings.OperationRequest{
		Kind: kind, IdempotencyKey: key, RequestID: requestID(r.Context()),
		TraceID: strings.TrimSpace(r.Header.Get("Traceparent")),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, dnsOperationResponse{Operation: result, Replayed: replayed})
}

func (s *Server) handleGetDNSOperation(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("operation_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "operation_id must be a UUID")
		return
	}
	if s.dnsSettings == nil || principal.TenantID == nil {
		s.writeError(w, r, dnssettings.ErrUnavailable)
		return
	}
	result, err := s.dnsSettings.GetOperation(r.Context(), dnsSettingsActor(principal), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func dnsSettingsActor(principal identity.Principal) dnssettings.Actor {
	actor := dnssettings.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
	if principal.TenantID != nil {
		actor.TenantID = *principal.TenantID
	}
	return actor
}
