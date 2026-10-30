package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsmaintenance"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnssettings"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// 节点管理 > DNS配置 (platform administrator): one installation-wide DNS
// configuration and its CNAME domains, synchronised into every tenant scope.

type savePlatformDNSConfigRequest struct {
	ProviderType string            `json:"provider_type"`
	Credentials  map[string]string `json:"credentials,omitempty"`
	TTL          int               `json:"ttl"`
	IPWeight     bool              `json:"ip_weight"`
}

type platformDNSZoneRequest struct {
	Name   string `json:"name"`
	Remark string `json:"remark"`
	// RandomAllocation 参与随机分配 (fix-cnamerand); omitted keeps it.
	RandomAllocation *bool `json:"random_allocation"`
}

type platformDNSOperationResponse struct {
	Operations []dnssettings.Operation `json:"operations"`
	Replayed   bool                    `json:"replayed"`
}

func (s *Server) handleGetPlatformDNSConfig(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.read")
	if !ok {
		return
	}
	result, err := s.dnsacme.PlatformConfig(r.Context(), dnsActor(principal))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSavePlatformDNSConfig(w http.ResponseWriter, r *http.Request) {
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
	var body savePlatformDNSConfigRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.dnsacme.SavePlatformConfig(r.Context(), dnsActor(principal), dnsacme.SavePlatformConfigRequest{
		ProviderType: body.ProviderType, Credentials: body.Credentials, TTL: body.TTL, IPWeight: body.IPWeight,
		ExpectedRevision: version, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	clear(body.Credentials)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

// handleTestPlatformDNSConnection is 连接测试: it verifies the entered (or,
// without credentials, the saved) credentials and reports which CNAME domains
// the account hosts. Read-only: nothing is saved and no record is written.
func (s *Server) handleTestPlatformDNSConnection(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.manage")
	if !ok {
		return
	}
	var body struct {
		ProviderType string            `json:"provider_type"`
		Credentials  map[string]string `json:"credentials,omitempty"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.dnsacme.TestPlatformConnection(r.Context(), dnsActor(principal), body.ProviderType, body.Credentials)
	clear(body.Credentials)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleStartPlatformDNSOperation starts 记录修复 (repair) or 清除CDN无关解析
// (cleanup) for every tenant scope holding the platform DNS configuration.
func (s *Server) handleStartPlatformDNSOperation(w http.ResponseWriter, r *http.Request) {
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
	actor := dnsActor(principal)
	config, err := s.dnsacme.PlatformConfig(r.Context(), actor)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if config.ProviderType == "" {
		s.writeError(w, r, dnsacme.ErrPlatformNotConfigured)
		return
	}
	// A repair also brings tenants that appeared since the last save in sync.
	_, _ = s.dnsacme.SyncPlatformTenants(r.Context())
	if s.dnsSettings == nil {
		s.writeError(w, r, dnssettings.ErrUnavailable)
		return
	}
	jobs, err := s.planPlatformDNSOperation(r, kind)
	switch {
	case errors.Is(err, dnsmaintenance.ErrNoTenant):
		s.writeAPIError(w, r, http.StatusConflict, "dns_no_tenant", "no user holds the DNS configuration yet")
		return
	case errors.Is(err, dnsmaintenance.ErrProviderListed) || errors.Is(err, dnsmaintenance.ErrNotConfigured):
		s.writeAPIError(w, r, http.StatusBadGateway, "dns_provider_unavailable", "the DNS provider records could not be listed")
		return
	case err != nil:
		s.writeError(w, r, err)
		return
	}
	targets := make([]dnssettings.PlatformTarget, len(jobs))
	for index, job := range jobs {
		targets[index] = dnssettings.PlatformTarget{TenantID: job.TenantID, ScopeID: job.ScopeID, Items: job.Items}
	}
	operations, replayed, err := s.dnsSettings.StartPlatformOperation(r.Context(), principal.UserID, principal.ScopeID,
		targets, dnssettings.OperationRequest{
			Kind: kind, IdempotencyKey: key, RequestID: requestID(r.Context()),
			TraceID: strings.TrimSpace(r.Header.Get("Traceparent")),
		})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, platformDNSOperationResponse{Operations: operations, Replayed: replayed})
}

func (s *Server) handleListPlatformDNSZones(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.read")
	if !ok {
		return
	}
	query := r.URL.Query()
	page, pageErr := strconv.Atoi(defaultQuery(query.Get("page"), "1"))
	limit, limitErr := strconv.Atoi(defaultQuery(query.Get("limit"), "10"))
	if pageErr != nil || limitErr != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "page and limit must be integers")
		return
	}
	result, err := s.dnsacme.ListPlatformZones(r.Context(), dnsActor(principal), dnsacme.PlatformZoneQuery{
		Search: query.Get("search"), Page: page, Limit: limit,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreatePlatformDNSZone(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body platformDNSZoneRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.dnsacme.CreatePlatformZone(r.Context(), dnsActor(principal), dnsacme.PlatformZoneRequest{
		Name: body.Name, Remark: body.Remark, RandomAllocation: body.RandomAllocation,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, result)
}

func (s *Server) handleUpdatePlatformDNSZone(w http.ResponseWriter, r *http.Request) {
	principal, request, ok := s.platformDNSZoneTarget(w, r)
	if !ok {
		return
	}
	var body platformDNSZoneRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	request.Name, request.Remark, request.RandomAllocation = body.Name, body.Remark, body.RandomAllocation
	result, err := s.dnsacme.UpdatePlatformZone(r.Context(), dnsActor(principal), request)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeletePlatformDNSZone(w http.ResponseWriter, r *http.Request) {
	principal, request, ok := s.platformDNSZoneTarget(w, r)
	if !ok {
		return
	}
	if err := s.dnsacme.DeletePlatformZone(r.Context(), dnsActor(principal), request); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) platformDNSZoneTarget(w http.ResponseWriter, r *http.Request) (identity.Principal, dnsacme.PlatformZoneRequest, bool) {
	principal, ok := s.requirePermission(w, r, "dns.manage")
	if !ok {
		return identity.Principal{}, dnsacme.PlatformZoneRequest{}, false
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return identity.Principal{}, dnsacme.PlatformZoneRequest{}, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "zone ID must be a UUID")
		return identity.Principal{}, dnsacme.PlatformZoneRequest{}, false
	}
	version, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return identity.Principal{}, dnsacme.PlatformZoneRequest{}, false
	}
	return principal, dnsacme.PlatformZoneRequest{ID: id, ExpectedRevision: version, IdempotencyKey: key,
		RequestID: requestID(r.Context())}, true
}

func defaultQuery(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// planPlatformDNSOperation lists the 记录修复 owners or the 清除CDN无关解析
// records; each becomes one result line of the background job.
func (s *Server) planPlatformDNSOperation(r *http.Request, kind string) ([]dnsmaintenance.Job, error) {
	store, err := dnsmaintenance.NewStore(s.pool)
	if err != nil {
		return nil, err
	}
	lister := s.dnsRecordLister
	if lister == nil {
		lister = dnsproviderremote.NewZoneRecordLister()
	}
	planner, err := dnsmaintenance.NewPlanner(store, s.dnsacme, lister)
	if err != nil {
		return nil, err
	}
	if kind == dnssettings.OperationCleanup {
		return planner.PlanCleanup(r.Context())
	}
	return planner.PlanRepair(r.Context())
}
