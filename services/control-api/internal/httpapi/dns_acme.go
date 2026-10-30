package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/acmecacredentials"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type createDNSProviderRequest struct {
	TargetScopeID string            `json:"target_scope_id"`
	Name          string            `json:"name"`
	Remark        string            `json:"remark,omitempty"`
	ProviderType  string            `json:"provider_type"`
	Credentials   map[string]string `json:"credentials"`
}

type updateDNSProviderRequest struct {
	ExpectedVersion int64             `json:"expected_version"`
	Name            string            `json:"name"`
	Remark          *string           `json:"remark,omitempty"`
	Status          string            `json:"status"`
	Credentials     map[string]string `json:"credentials,omitempty"`
}

type createDNSZoneRequest struct {
	TargetScopeID string `json:"target_scope_id"`
	ProviderID    string `json:"provider_id"`
	Name          string `json:"name"`
}

type createDNSRecordRequest struct {
	TargetScopeID string `json:"target_scope_id"`
	ZoneID        string `json:"zone_id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	Content       string `json:"content"`
	TTL           int    `json:"ttl"`
}

type updateDNSRecordRequest struct {
	ExpectedVersion int64  `json:"expected_version"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	Content         string `json:"content"`
	TTL             int    `json:"ttl"`
}

type createCertificateOrderRequest struct {
	TargetScopeID string   `json:"target_scope_id"`
	DNSProviderID string   `json:"dns_provider_id"`
	Domains       []string `json:"domains"`
	ChallengeType string   `json:"challenge_type"`
	AutoRenew     bool     `json:"auto_renew"`
	Issuer        string   `json:"issuer"`
	Name          string   `json:"name"`
	Remark        string   `json:"remark"`
}

func (s *Server) handleCreateDNSProvider(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createDNSProviderRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	target, err := optionalUUID(body.TargetScopeID)
	if err != nil {
		s.writeFieldError(w, r, "target_scope_id", fielderr.InvalidFormat)
		return
	}
	result, err := s.dnsacme.CreateProvider(r.Context(), dnsActor(principal), dnsacme.CreateProviderRequest{
		TargetScopeID: target, Name: body.Name, Remark: body.Remark, ProviderType: body.ProviderType,
		Credentials: body.Credentials, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, result)
}

func (s *Server) handleListDNSProviders(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.read")
	if !ok {
		return
	}
	request, err := parseDNSProviderPageRequest(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "pagination query is invalid")
		return
	}
	page, err := s.dnsacme.ListProviderPage(r.Context(), dnsActor(principal), request)
	if err != nil {
		if errors.Is(err, dnsacme.ErrInvalidInput) {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "pagination query is invalid")
			return
		}
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func parseDNSProviderPageRequest(r *http.Request) (dnsacme.ProviderPageRequest, error) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return dnsacme.ProviderPageRequest{}, err
	}
	for key, value := range values {
		if (key != "limit" && key != "cursor") || len(value) != 1 {
			return dnsacme.ProviderPageRequest{}, dnsacme.ErrInvalidInput
		}
	}
	result := dnsacme.ProviderPageRequest{Limit: dnsacme.DefaultProviderPageLimit}
	if raw, found := values["limit"]; found {
		limit, parseErr := strconv.Atoi(raw[0])
		if parseErr != nil || strconv.Itoa(limit) != raw[0] || limit < 1 || limit > dnsacme.MaxProviderPageLimit {
			return dnsacme.ProviderPageRequest{}, dnsacme.ErrInvalidInput
		}
		result.Limit = limit
	}
	if raw, found := values["cursor"]; found {
		if raw[0] == "" || len(raw[0]) > dnsacme.MaxProviderCursorLength || strings.ContainsAny(raw[0], "\x00\r\n") {
			return dnsacme.ProviderPageRequest{}, dnsacme.ErrInvalidInput
		}
		result.Cursor = raw[0]
	}
	return result, nil
}

func (s *Server) handleUpdateDNSProvider(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, ok := s.pathUUID(w, r, "provider ID")
	if !ok {
		return
	}
	var body updateDNSProviderRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.dnsacme.UpdateProvider(r.Context(), dnsActor(principal), dnsacme.UpdateProviderRequest{
		ID: id, ExpectedRevision: body.ExpectedVersion, Name: body.Name, Remark: body.Remark, Status: body.Status,
		Credentials: body.Credentials, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeleteDNSProvider(w http.ResponseWriter, r *http.Request) {
	s.handleDNSDelete(w, r, "dns.manage", s.dnsacme.DeleteProvider)
}

func (s *Server) handleVerifyDNSProvider(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, ok := s.pathUUID(w, r, "provider ID")
	if !ok {
		return
	}
	version, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	var extra [1]byte
	if count, readErr := r.Body.Read(extra[:]); count != 0 || !errors.Is(readErr, io.EOF) {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body must be empty")
		return
	}
	result, err := s.dnsacme.VerifyProvider(r.Context(), dnsActor(principal), dnsacme.VerifyProviderRequest{
		ID: id, ExpectedRevision: version, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateDNSZone(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createDNSZoneRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	target, targetErr := optionalUUID(body.TargetScopeID)
	providerID, providerErr := uuid.Parse(body.ProviderID)
	if targetErr != nil {
		s.writeFieldError(w, r, "target_scope_id", fielderr.InvalidFormat)
		return
	}
	if providerErr != nil {
		s.writeFieldError(w, r, "provider_id", uuidReason(body.ProviderID))
		return
	}
	result, err := s.dnsacme.CreateZone(r.Context(), dnsActor(principal), dnsacme.CreateZoneRequest{
		TargetScopeID: target, ProviderID: providerID, Name: body.Name,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, result)
}

func (s *Server) handleListDNSZones(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.read")
	if !ok {
		return
	}
	items, err := s.dnsacme.ListZones(r.Context(), dnsActor(principal))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleDeleteDNSZone(w http.ResponseWriter, r *http.Request) {
	s.handleDNSDelete(w, r, "dns.manage", s.dnsacme.DeleteZone)
}

func (s *Server) handleCreateDNSRecord(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createDNSRecordRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	target, targetErr := optionalUUID(body.TargetScopeID)
	zoneID, zoneErr := uuid.Parse(body.ZoneID)
	if targetErr != nil {
		s.writeFieldError(w, r, "target_scope_id", fielderr.InvalidFormat)
		return
	}
	if zoneErr != nil {
		s.writeFieldError(w, r, "zone_id", uuidReason(body.ZoneID))
		return
	}
	result, err := s.dnsacme.CreateRecord(r.Context(), dnsActor(principal), dnsacme.CreateRecordRequest{
		TargetScopeID: target, ZoneID: zoneID, Name: body.Name, Type: body.Type,
		Content: body.Content, TTL: body.TTL, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, result)
}

func (s *Server) handleListDNSRecords(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.read")
	if !ok {
		return
	}
	zoneID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("zone_id")))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "zone_id must be a UUID")
		return
	}
	items, err := s.dnsacme.ListRecords(r.Context(), dnsActor(principal), zoneID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleUpdateDNSRecord(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "dns.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, ok := s.pathUUID(w, r, "record ID")
	if !ok {
		return
	}
	var body updateDNSRecordRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.dnsacme.UpdateRecord(r.Context(), dnsActor(principal), dnsacme.UpdateRecordRequest{
		ID: id, ExpectedRevision: body.ExpectedVersion, Name: body.Name, Type: body.Type,
		Content: body.Content, TTL: body.TTL, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	s.handleDNSDelete(w, r, "dns.manage", s.dnsacme.DeleteRecord)
}

func (s *Server) handleCreateCertificateOrder(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "certificates.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createCertificateOrderRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	target, err := optionalUUID(body.TargetScopeID)
	if err != nil {
		s.writeFieldError(w, r, "target_scope_id", fielderr.InvalidFormat)
		return
	}
	var providerID *uuid.UUID
	if strings.TrimSpace(body.DNSProviderID) != "" {
		parsed, parseErr := uuid.Parse(body.DNSProviderID)
		if parseErr != nil {
			s.writeFieldError(w, r, "dns_provider_id", fielderr.InvalidFormat)
			return
		}
		providerID = &parsed
	}
	result, err := s.dnsacme.CreateOrder(r.Context(), dnsActor(principal), dnsacme.CreateOrderRequest{
		TargetScopeID: target, DNSProviderID: providerID, Domains: body.Domains,
		ChallengeType: body.ChallengeType, AutoRenew: body.AutoRenew,
		Issuer: body.Issuer, Name: body.Name, Remark: body.Remark,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, result)
}

func (s *Server) handleListCertificateOrders(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "certificates.read")
	if !ok {
		return
	}
	items, err := s.dnsacme.ListOrders(r.Context(), dnsActor(principal))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleDNSDelete(
	w http.ResponseWriter,
	r *http.Request,
	permission string,
	deleteFunc func(context.Context, dnsacme.Actor, dnsacme.DeleteRequest) error,
) {
	principal, ok := s.requirePermission(w, r, permission)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, ok := s.pathUUID(w, r, "resource ID")
	if !ok {
		return
	}
	version, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	if err := deleteFunc(r.Context(), dnsActor(principal), dnsacme.DeleteRequest{
		ID: id, ExpectedRevision: version, IdempotencyKey: key, RequestID: requestID(r.Context()),
	}); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requirePermission(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, bool) {
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

func (s *Server) pathUUID(w http.ResponseWriter, r *http.Request, label string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", label+" must be a UUID")
		return uuid.Nil, false
	}
	return id, true
}

func dnsActor(principal identity.Principal) dnsacme.Actor {
	return dnsacme.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}

// handleListCertificateIssuers is the CAs a new certificate request may
// name (CERT-04): Let's Encrypt and every EAB CA the platform configured,
// with the platform default. The request form shows only these.
func (s *Server) handleListCertificateIssuers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePermission(w, r, "certificates.read"); !ok {
		return
	}
	var result struct {
		Items   []string `json:"items"`
		Default string   `json:"default"`
	}
	// Read-write: the platform default is read under FOR SHARE (the same lock
	// tenant writes take), which PostgreSQL refuses in a read-only transaction.
	err := pgx.BeginTxFunc(r.Context(), s.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		for _, issuer := range dnsacme.CertificateIssuers {
			configured, err := acmecacredentials.Configured(r.Context(), tx, issuer)
			if err != nil {
				return err
			}
			if configured {
				result.Items = append(result.Items, issuer)
			}
		}
		var err error
		result.Default, err = systemconfig.LoadDefaultCertificateIssuer(r.Context(), tx)
		return err
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// uuidReason: an empty required ID is "required", anything else malformed.
func uuidReason(value string) string {
	if strings.TrimSpace(value) == "" {
		return fielderr.Required
	}
	return fielderr.InvalidFormat
}
