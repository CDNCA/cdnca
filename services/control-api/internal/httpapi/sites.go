package httpapi

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/marketmanaged"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

type siteBasicPayload struct {
	PackageID             *string             `json:"package_id"`
	PackageSubscriptionID *string             `json:"package_subscription_id"`
	CNAMEMode             string              `json:"cname_mode"`
	CNAMEDomain           string              `json:"cname_domain"`
	CNAMEHostname         string              `json:"cname_hostname"`
	CNAMERegenerate       bool                `json:"cname_regenerate,omitempty"`
	PackageName           *string             `json:"package_name"`
	GroupID               *string             `json:"group_id"`
	GroupName             *string             `json:"group_name"`
	Domains               []string            `json:"domains"`
	HTTPEnabled           bool                `json:"http_enabled"`
	HTTPListenPorts       []string            `json:"http_listen_ports"`
	HTTPSListenPorts      []string            `json:"https_listen_ports"`
	IPv6Enabled           bool                `json:"ipv6_enabled"`
	Origins               []string            `json:"origins"`
	CNAME                 string              `json:"cname"`
	TLSProtocols          tlsProtocolsPayload `json:"tls_protocols,omitempty"`
	CNAMEState            *string             `json:"cname_state"`
	CNAMEFailureCode      *string             `json:"cname_failure_code,omitempty"`
	CNAMETaskID           *string             `json:"cname_task_id"`
	CNAMECurrentRevision  *int64              `json:"cname_current_revision"`
	CNAMELKGRevision      *int64              `json:"cname_lkg_revision"`
	HTTPSEnabled          bool                `json:"https_enabled"`
	ForceHTTPS            *bool               `json:"force_https,omitempty"`
	HTTPSRedirectPort     *int                `json:"https_redirect_port,omitempty"`
	// CacheSharedAcrossDomains (所有域名共用缓存): omitted keeps the stored value.
	CacheSharedAcrossDomains *bool `json:"cache_shared_across_domains,omitempty"`
	// CacheStatusHeader (响应头显示缓存状态): omitted keeps the stored value;
	// on create, on.
	CacheStatusHeader *bool `json:"cache_status_header,omitempty"`
	// TLS profile: omitted keeps the stored value; on create,
	// the system default. tls_client_ca_pem goes with tls_client_auth.
	TLSCipherPreset *string `json:"tls_cipher_preset,omitempty"`
	// TLSCipherSuites goes with tls_cipher_preset custom:
	// whitelisted TLS 1.2 suite names, in order.
	TLSCipherSuites []string `json:"tls_cipher_suites,omitempty"`
	TLSOCSPStapling *bool    `json:"tls_ocsp_stapling,omitempty"`
	TLSClientAuth   *string  `json:"tls_client_auth,omitempty"`
	TLSClientCAPEM  *string  `json:"tls_client_ca_pem,omitempty"`
	Enabled         bool     `json:"enabled"`
	Status          string   `json:"status"`
	// SyncStatus is response only: derived by the server from the site's
	// latest automatic publication (497, PJ-C02); a write carrying it is
	// refused.
	SyncStatus *string `json:"sync_status,omitempty"`
	IsDefault  bool    `json:"is_default"`

	// HTTPS protocols: omitted keeps the stored value; on
	// create, the owner's 默认设置, else on. tls_prefer_server_ciphers null
	// is "by the cipher preset" (a response always carries the key; a write
	// with null stores it again, omitted keeps the stored value).
	HTTP2Enabled           *bool `json:"http2_enabled,omitempty"`
	HTTP3Enabled           *bool `json:"http3_enabled,omitempty"`
	TLSPreferServerCiphers *bool `json:"tls_prefer_server_ciphers"`

	decoded       bool
	ipv6Present   bool
	preferPresent bool
}

func (payload *siteBasicPayload) UnmarshalJSON(data []byte) error {
	type siteBasicPayloadWire siteBasicPayload
	var wire siteBasicPayloadWire
	if err := decodeSiteJSON(data, &wire); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["sync_status"]; ok {
		return errors.New("sync_status is derived by the server and cannot be written")
	}
	*payload = siteBasicPayload(wire)
	payload.decoded = true
	_, payload.ipv6Present = fields["ipv6_enabled"]
	_, payload.preferPresent = fields["tls_prefer_server_ciphers"]
	return nil
}

type tlsProtocolsPayload []string

func (protocols *tlsProtocolsPayload) UnmarshalJSON(encoded []byte) error {
	if bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
		return site.ErrTLSProtocolsInvalid
	}
	var decoded []string
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return err
	}
	*protocols = decoded
	return nil
}

type createSiteRequest struct {
	TargetScopeID string           `json:"target_scope_id"`
	OwnerID       string           `json:"owner_id"`
	Basic         siteBasicPayload `json:"basic"`
	OriginPool    *site.OriginPool `json:"origin_pool,omitempty"`
	// DNSProviderID: 建站「DNS API（自动添加记录）」, the owner's DNS account.
	DNSProviderID string `json:"dns_provider_id,omitempty"`
}

type updateSiteRequest struct {
	ExpectedVersion int64            `json:"expected_version"`
	Section         string           `json:"section"`
	Changes         siteBasicPayload `json:"-"`
	OriginChanges   *site.OriginPool `json:"-"`
}

func (request *updateSiteRequest) UnmarshalJSON(data []byte) error {
	var wire struct {
		ExpectedVersion int64           `json:"expected_version"`
		Section         string          `json:"section"`
		Changes         json.RawMessage `json:"changes"`
	}
	if err := decodeSiteJSON(data, &wire); err != nil {
		return err
	}
	request.ExpectedVersion = wire.ExpectedVersion
	request.Section = wire.Section
	switch wire.Section {
	case "origin":
		var pool site.OriginPool
		if err := decodeSiteJSON(wire.Changes, &pool); err != nil {
			return err
		}
		request.OriginChanges = &pool
	default:
		if err := decodeSiteJSON(wire.Changes, &request.Changes); err != nil {
			return err
		}
	}
	return nil
}

func (request updateSiteRequest) MarshalJSON() ([]byte, error) {
	changes := any(request.Changes)
	if request.Section == "origin" && request.OriginChanges != nil {
		changes = request.OriginChanges
	}
	return json.Marshal(struct {
		ExpectedVersion int64  `json:"expected_version"`
		Section         string `json:"section"`
		Changes         any    `json:"changes"`
	}{request.ExpectedVersion, request.Section, changes})
}

type lockSiteRequest struct {
	ExpectedVersion int64  `json:"expected_version"`
	Reason          string `json:"reason"`
}

type unlockSiteRequest struct {
	ExpectedVersion int64 `json:"expected_version"`
}

type batchSiteActionRequest struct {
	Action    string                 `json:"action"`
	Items     []site.BatchActionItem `json:"items"`
	Protocols *batchSiteProtocols    `json:"protocols,omitempty"`
}

// batchSiteProtocols (action set_protocols): an omitted key keeps each
// site's value; tls_prefer_server_ciphers null is "by the cipher preset"
// again, as in a single-site basic update.
type batchSiteProtocols struct {
	HTTP2Enabled           *bool `json:"http2_enabled"`
	HTTP3Enabled           *bool `json:"http3_enabled"`
	TLSPreferServerCiphers *bool `json:"tls_prefer_server_ciphers"`

	preferPresent bool
}

func (payload *batchSiteProtocols) UnmarshalJSON(data []byte) error {
	type wire batchSiteProtocols
	var decoded wire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*payload = batchSiteProtocols(decoded)
	_, payload.preferPresent = fields["tls_prefer_server_ciphers"]
	return nil
}

func (payload *batchSiteProtocols) fields() *site.BatchProtocols {
	if payload == nil {
		return nil
	}
	return &site.BatchProtocols{
		HTTP2Enabled: payload.HTTP2Enabled, HTTP3Enabled: payload.HTTP3Enabled,
		TLSPreferServerCiphers:      payload.TLSPreferServerCiphers,
		TLSPreferServerCiphersReset: payload.preferPresent && payload.TLSPreferServerCiphers == nil,
	}
}

type batchSiteActionItemResponse struct {
	ID     uuid.UUID            `json:"id"`
	Status string               `json:"status"`
	Site   *siteDetailResponse  `json:"site,omitempty"`
	Error  *site.BatchItemError `json:"error,omitempty"`
}

type batchSiteActionResponse struct {
	Items []batchSiteActionItemResponse `json:"items"`
}

func authorizeBatchSiteAction(principal identity.Principal, action string) error {
	if action == site.BatchActionRegenerateCNAME {
		return identity.Authorize(principal, "dns.manage")
	}
	return nil
}

type siteDetailResponse struct {
	ID             uuid.UUID              `json:"id"`
	ScopeID        uuid.UUID              `json:"scope_id"`
	DisplayID      string                 `json:"display_id"`
	Version        int64                  `json:"version"`
	Owner          *site.OwnerReference   `json:"owner"`
	CreatedAt      string                 `json:"created_at"`
	UpdatedAt      string                 `json:"updated_at"`
	Lock           site.LockState         `json:"lock"`
	StatusState    site.OperationalStatus `json:"status_state"`
	StatusCode     int                    `json:"status_code"`
	StatusRecovery *site.StatusRecovery   `json:"status_recovery"`
	ListenerState  site.ListenerState     `json:"listener_state"`
	// HTTPSCertificateBound (be-gap-2): the site has a bound certificate; HTTPS
	// and forced HTTPS can only be turned on with one.
	HTTPSCertificateBound bool             `json:"https_certificate_bound"`
	Basic                 siteBasicPayload `json:"basic"`
	OriginPool            site.OriginPool  `json:"origin_pool"`

	TrafficEnforcement *site.TrafficEnforcement `json:"traffic_enforcement"`

	// PackageExpiresAt / PackageExpiredDays / PackageRemainingDays: the
	// package subscription's period end, the whole days since it passed (0
	// while valid) and the days left (rounded up, 0 once passed; tp-b3a-be);
	// all null without a subscription (site-backend6).
	PackageExpiresAt     *string `json:"package_expires_at"`
	PackageExpiredDays   *int    `json:"package_expired_days"`
	PackageRemainingDays *int    `json:"package_remaining_days"`

	// AccessReadiness: 接入状态 (fix-readiness); null only when unreadable.
	AccessReadiness *site.AccessReadiness `json:"access_readiness"`
	// PackageUnavailableReason: no_package / package_disabled /
	// package_deleted while the site is not served for lack of a valid
	// package (fix-nopkgpub2); null while it is valid.
	PackageUnavailableReason *string `json:"package_unavailable_reason"`
}

type siteListItemResponse struct {
	site.ListItem
	StatusCode int `json:"status_code"`
}

type siteListResponse struct {
	Items []siteListItemResponse `json:"items"`
	Total int64                  `json:"total"`
	Page  int                    `json:"page"`
	Limit int                    `json:"limit"`
}

func (s *Server) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createSiteRequest
	if err := decodeJSON(w, r, &body); err != nil {
		if errors.Is(err, site.ErrTLSProtocolsInvalid) {
			s.writeSiteError(w, r, err)
		} else {
			s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		}
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
	dnsProviderID, err := optionalUUIDPointer(&body.DNSProviderID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "dns_provider_id must be a UUID")
		return
	}
	if dnsProviderID != nil {
		// Writing records through the account is a DNS change.
		if err := identity.Authorize(principal, "dns.manage"); err != nil {
			s.writeError(w, r, err)
			return
		}
	}
	// A create may leave ipv6_enabled out (basic updates may not): the
	// owner's 默认设置 > IPv6 decides, else off.
	ipv6Omitted := body.Basic.decoded && !body.Basic.ipv6Present
	body.Basic.ipv6Present = true
	fields, err := fieldsFromBasic(body.Basic)
	fields.IPv6Omitted = ipv6Omitted
	if err != nil {
		s.writeSiteError(w, r, err)
		return
	}
	actor, err := s.siteWriteActor(r, principal)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.sites.Create(r.Context(), actor, site.CreateRequest{
		TargetScopeID: targetScopeID,
		OwnerUserID:   ownerID,
		Fields:        fields,
		OriginPool:    body.OriginPool,
		DNSProviderID: dnsProviderID,
		// 默认设置 > DNS API 只替有权写解析的创建者自动添加记录。
		DefaultDNSAllowed: identity.Authorize(principal, "dns.manage") == nil,
		// 默认设置 > 源站请求头 / 上传限制 写站点 HTTP 策略，需要该权限（fp-site5b）。
		DefaultHTTPPolicyAllowed: identity.Authorize(principal, "http_policies.manage") == nil,
		IdempotencyKey:           key,
		RequestID:                requestID(r.Context()),
	})
	if err != nil {
		s.writeSiteError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Site.Revision))
	writeJSONStatus(w, http.StatusCreated, siteDetail(result.Site))
}

func (s *Server) handleListSites(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.read")
	if !ok {
		return
	}
	filter, err := parseSiteListFilter(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return
	}
	result, err := s.sites.List(r.Context(), siteActor(principal), filter)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	response := siteListResponse{Items: make([]siteListItemResponse, len(result.Items)), Total: result.Total, Page: result.Page, Limit: result.Limit}
	for index, item := range result.Items {
		code, ok := compatibilityCodeFromStatusState(item.OperationalStatus)
		if !ok {
			s.writeAPIError(w, r, http.StatusInternalServerError, "site_status_invalid", "site status is invalid")
			return
		}
		response.Items[index] = siteListItemResponse{ListItem: item, StatusCode: code}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleGetSite(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	item, err := s.sites.Get(r.Context(), siteActor(principal), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(item.Revision))
	writeJSON(w, http.StatusOK, siteDetail(item))
}

func (s *Server) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	var body updateSiteRequest
	if err := decodeJSON(w, r, &body); err != nil {
		if errors.Is(err, site.ErrTLSProtocolsInvalid) {
			s.writeSiteError(w, r, err)
		} else {
			s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		}
		return
	}
	var result site.WriteResult
	switch body.Section {
	case "basic":
		var fields site.SiteFields
		fields, err = fieldsFromBasic(body.Changes)
		if err != nil {
			s.writeSiteError(w, r, err)
			return
		}
		actor, actorErr := s.siteWriteActor(r, principal)
		if actorErr != nil {
			s.writeError(w, r, actorErr)
			return
		}
		result, err = s.sites.Update(r.Context(), actor, site.UpdateRequest{
			ID:               id,
			ExpectedRevision: body.ExpectedVersion,
			Fields:           fields,
			IdempotencyKey:   key,
			RequestID:        requestID(r.Context()),
			SourceIP:         s.requestInfo(r).SourceIP,
		})
	case "origin":
		if body.OriginChanges == nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "origin changes are invalid")
			return
		}
		result, err = s.sites.UpdateOrigin(r.Context(), siteActor(principal), site.UpdateOriginRequest{
			ID:               id,
			ExpectedRevision: body.ExpectedVersion,
			Pool:             *body.OriginChanges,
			IdempotencyKey:   key,
			RequestID:        requestID(r.Context()),
		})
	default:
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "section must be basic or origin")
		return
	}
	if err != nil {
		s.writeSiteError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Site.Revision))
	writeJSON(w, http.StatusOK, siteDetail(result.Site))
}

func (s *Server) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	version, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	_, err = s.sites.Delete(r.Context(), siteActor(principal), site.DeleteRequest{
		ID:               id,
		ExpectedRevision: version,
		IdempotencyKey:   key,
		RequestID:        requestID(r.Context()),
	})
	if err != nil {
		s.writeSiteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleBatchSiteAction(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body batchSiteActionRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if err := authorizeBatchSiteAction(principal, body.Action); err != nil {
		s.writeError(w, r, err)
		return
	}
	actor, err := s.siteWriteActor(r, principal)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.sites.BatchAction(r.Context(), actor, site.BatchActionRequest{
		Action:         body.Action,
		Items:          body.Items,
		Protocols:      body.Protocols.fields(),
		IdempotencyKey: key,
		RequestID:      requestID(r.Context()),
	})
	if err != nil {
		s.writeSiteError(w, r, err)
		return
	}
	response := batchSiteActionResponse{Items: make([]batchSiteActionItemResponse, len(result.Items))}
	for index, item := range result.Items {
		response.Items[index] = batchSiteActionItemResponse{
			ID: item.ID, Status: item.Status, Error: item.Error,
		}
		if item.Site != nil {
			detail := siteDetail(*item.Site)
			response.Items[index].Site = &detail
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleLockSite(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePlatformSiteManage(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	var body lockSiteRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.sites.Lock(r.Context(), siteActor(principal), site.LockRequest{
		ID:               id,
		ExpectedRevision: body.ExpectedVersion,
		Reason:           body.Reason,
		IdempotencyKey:   key,
		RequestID:        requestID(r.Context()),
	})
	if err != nil {
		s.writeSiteError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Site.Revision))
	writeJSON(w, http.StatusOK, siteDetail(result.Site))
}

func (s *Server) handleUnlockSite(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePlatformSiteManage(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	var body unlockSiteRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.sites.Unlock(r.Context(), siteActor(principal), site.UnlockRequest{
		ID:               id,
		ExpectedRevision: body.ExpectedVersion,
		IdempotencyKey:   key,
		RequestID:        requestID(r.Context()),
	})
	if err != nil {
		s.writeSiteError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Site.Revision))
	writeJSON(w, http.StatusOK, siteDetail(result.Site))
}

func (s *Server) requireSitePermission(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, bool) {
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

func (s *Server) requirePlatformSiteManage(w http.ResponseWriter, r *http.Request) (identity.Principal, bool) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
	if !ok {
		return identity.Principal{}, false
	}
	if principal.ScopeKind != "platform" {
		s.writeError(w, r, identity.ErrPermissionDenied)
		return identity.Principal{}, false
	}
	return principal, true
}

// siteFieldErrorDetails names the refused field of a site write
// (validation_error); omitted when the store cannot locate one.
type siteFieldErrorDetails struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

func (s *Server) writeSiteError(w http.ResponseWriter, r *http.Request, err error) {
	var fieldErr *site.FieldError
	switch {
	case errors.As(err, &fieldErr):
		writeJSONStatus(w, http.StatusBadRequest, errorEnvelope{Error: apiError{
			Code: "validation_error", Message: "site field " + fieldErr.Field + " is invalid: " + fieldErr.Reason,
			RequestID: requestID(r.Context()), Details: siteFieldErrorDetails{Field: fieldErr.Field, Reason: fieldErr.Reason},
		}})
	case errors.Is(err, marketmanaged.ErrManaged):
		s.writeAPIError(w, r, http.StatusConflict, "market_managed",
			"this site serves a node-market subscriber; the supplier cannot disable or delete it (ADR 0012 §18.4)")
	case errors.Is(err, site.ErrAutoDNSProvider):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "dns_provider_unusable",
			"choose a verified DNS API account of the site owner")
	case errors.Is(err, site.ErrTransferApexInUse):
		s.writeDomainTrustError(w, r, err, http.StatusConflict, "site_transfer_domain_in_use",
			"another site of the current owner still uses the verified domain")
	case errors.Is(err, site.ErrTransferTarget):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "site_transfer_target_invalid",
			"choose another active user (not the current owner)")
	case errors.Is(err, site.ErrLocked):
		s.writeAPIError(w, r, http.StatusConflict, "site_locked", "site is locked by a platform administrator")
	case errors.Is(err, site.ErrDNSMutationInProgress):
		s.writeAPIError(w, r, http.StatusConflict, "site_dns_mutation_in_progress",
			"a DNS reconcile task is changing this site's records; retry when it finishes")
	case errors.Is(err, site.ErrLockStateConflict):
		s.writeAPIError(w, r, http.StatusConflict, "site_lock_state_conflict", "site lock state already matches the request")
	case errors.Is(err, site.ErrOriginAuthRequiresHTTPS):
		s.writeAPIError(w, r, http.StatusConflict, "origin_auth_requires_https",
			"an enabled origin authentication rule needs this origin on HTTPS port 443")
	case errors.Is(err, site.ErrOriginSectionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "origin_section_conflict", "origin settings must be updated through the origin section")
	case errors.Is(err, site.ErrTLSLegacyProtocolBlocked):
		s.writeAPIError(w, r, http.StatusBadRequest, "site_tls_legacy_protocol_blocked", "legacy TLS protocols are blocked")
	case errors.Is(err, site.ErrTLSProtocolsInvalid):
		s.writeAPIError(w, r, http.StatusBadRequest, "site_tls_protocols_invalid",
			"TLS protocols must be an ascending contiguous range of TLSv1..TLSv1.3")
	case errors.Is(err, site.ErrTLSProfileInvalid):
		s.writeAPIError(w, r, http.StatusBadRequest, "site_tls_profile_invalid",
			"TLS profile is invalid: TLSv1/TLSv1.1 need the legacy cipher preset; client verification needs a PEM CA bundle")
	case errors.Is(err, domaintrust.ErrDomainBlocked):
		// The administrator's reason is never revealed.
		s.writeDomainTrustError(w, r, err, http.StatusUnprocessableEntity, "domain_blocked", "site domain is not allowed")
	case errors.Is(err, domaintrust.ErrDomainVerifiedByOther):
		s.writeDomainTrustError(w, r, err, http.StatusConflict, "domain_verified_by_other",
			"the domain ownership has been verified by another account")
	case errors.Is(err, domaintrust.ErrOwnershipRequired):
		s.writeDomainTrustError(w, r, err, http.StatusConflict, "domain_ownership_required",
			"verify ownership of the domain before adding it")
	case errors.Is(err, domaintrust.ErrClaimSuspended):
		s.writeAPIError(w, r, http.StatusConflict, "site_domain_claim_suspended",
			"remove the domain claimed by its verified owner before enabling this site")
	default:
		s.writeError(w, r, err)
	}
}

func (s *Server) idempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if !requestIDPattern.MatchString(key) {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "Idempotency-Key is required")
		return "", false
	}
	return key, true
}

func siteActor(principal identity.Principal) site.Actor {
	return site.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}

func (s *Server) siteWriteActor(r *http.Request, principal identity.Principal) (site.Actor, error) {
	actor := siteActor(principal)
	scheme, rawToken, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if principal.ScopeKind != "platform" || !found || !strings.EqualFold(scheme, "Bearer") {
		return actor, nil
	}
	if s.identity == nil {
		return site.Actor{}, identity.ErrInvalidSession
	}
	session, err := s.identity.AuthenticateSession(r.Context(), strings.TrimSpace(rawToken))
	if err != nil {
		return site.Actor{}, err
	}
	if session.Principal.UserID != principal.UserID || session.Principal.ScopeID != principal.ScopeID ||
		session.Principal.ScopeKind != principal.ScopeKind || session.SessionID == uuid.Nil {
		return site.Actor{}, identity.ErrInvalidSession
	}
	actor.SessionID = session.SessionID
	return actor, nil
}

func fieldsFromBasic(basic siteBasicPayload) (site.SiteFields, error) {
	if !basic.HTTPEnabled || len(basic.Domains) < 1 || len(basic.Domains) > 100 ||
		(basic.decoded && !basic.ipv6Present) {
		return site.SiteFields{}, site.ErrInvalidInput
	}
	packageID, err := optionalUUIDPointer(basic.PackageID)
	if err != nil {
		return site.SiteFields{}, site.ErrInvalidInput
	}
	packageSubscriptionID, err := optionalUUIDPointer(basic.PackageSubscriptionID)
	if err != nil {
		return site.SiteFields{}, site.ErrInvalidInput
	}
	groupID, err := optionalUUIDPointer(basic.GroupID)
	if err != nil {
		return site.SiteFields{}, site.ErrInvalidInput
	}
	fields := site.SiteFields{
		Domain:                   basic.Domains[0],
		Domains:                  basic.Domains,
		HTTPPorts:                basic.HTTPListenPorts,
		HTTPSPorts:               basic.HTTPSListenPorts,
		IPv6Enabled:              basic.IPv6Enabled,
		Origins:                  basic.Origins,
		CNAME:                    basic.CNAME,
		TLSProtocols:             basic.TLSProtocols,
		HTTPSEnabled:             basic.HTTPSEnabled,
		ForceHTTPS:               basic.ForceHTTPS,
		HTTPSRedirectPort:        basic.HTTPSRedirectPort,
		CacheSharedAcrossDomains: basic.CacheSharedAcrossDomains,
		CacheStatusHeader:        basic.CacheStatusHeader,
		TLSCipherPreset:          basic.TLSCipherPreset,
		TLSCipherSuites:          basic.TLSCipherSuites,
		TLSOCSPStapling:          basic.TLSOCSPStapling,
		TLSClientAuth:            basic.TLSClientAuth,
		TLSClientCAPEM:           basic.TLSClientCAPEM,
		Enabled:                  basic.Enabled,
		Status:                   basic.Status,
		IsDefault:                basic.IsDefault,
		PackageID:                packageID,
		PackageSubscriptionID:    packageSubscriptionID,
		CNAMEMode:                basic.CNAMEMode,
		CNAMEDomain:              basic.CNAMEDomain,
		CNAMEHostname:            basic.CNAMEHostname,
		CNAMERegenerate:          basic.CNAMERegenerate,
		PackageName:              stringPointerValue(basic.PackageName),
		GroupID:                  groupID,
		GroupName:                stringPointerValue(basic.GroupName),
	}
	fields.HTTP2Enabled, fields.HTTP3Enabled = basic.HTTP2Enabled, basic.HTTP3Enabled
	fields.TLSPreferServerCiphers = basic.TLSPreferServerCiphers
	// an explicit null: by the cipher preset again
	fields.TLSPreferServerCiphersReset = basic.preferPresent && basic.TLSPreferServerCiphers == nil
	return fields, nil
}

func siteDetail(item site.Site) siteDetailResponse {
	return siteDetailAt(item, time.Now())
}

func siteDetailAt(item site.Site, now time.Time) siteDetailResponse {
	var expiresAt *string
	var expiredDays, remainingDays *int
	if item.PackageExpiresAt != nil {
		text := item.PackageExpiresAt.UTC().Format(time.RFC3339)
		days := site.PackageExpiredDays(*item.PackageExpiresAt, now)
		remaining := site.PackageRemainingDays(*item.PackageExpiresAt, now)
		expiresAt, expiredDays, remainingDays = &text, &days, &remaining
	}
	forceHTTPS, redirectPort, cacheShared := item.ForceHTTPS, item.HTTPSRedirectPort, item.CacheSharedAcrossDomains
	cacheStatusHeader := item.CacheStatusHeader
	syncStatus := item.SyncStatus
	var packageName, groupName *string
	if item.Package != nil {
		name := item.Package.Name
		packageName = &name
	}
	if item.GroupName != nil {
		name := *item.GroupName
		groupName = &name
	}
	tlsCipherPreset, tlsOCSPStapling, tlsClientAuth, tlsClientCAPEM := item.TLSCipherPreset, item.TLSOCSPStapling,
		item.TLSClientAuth, item.TLSClientCAPEM
	http2Enabled, http3Enabled := item.HTTP2Enabled, item.HTTP3Enabled
	var tlsPreferServerCiphers *bool
	if item.TLSPreferServerCiphers != nil {
		value := *item.TLSPreferServerCiphers
		tlsPreferServerCiphers = &value
	}
	statusState := item.OperationalStatus
	if statusState == "" {
		statusState = site.OperationalStatusOf(item.Status, item.Lock.Locked)
	}
	statusCode, _ := compatibilityCodeFromStatusState(statusState)
	return siteDetailResponse{
		ID:             item.ID,
		ScopeID:        item.ScopeID,
		DisplayID:      item.DisplayID,
		Version:        item.Revision,
		Owner:          item.Owner,
		CreatedAt:      item.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999Z07:00"),
		UpdatedAt:      item.UpdatedAt.UTC().Format("2006-01-02T15:04:05.999999Z07:00"),
		Lock:           item.Lock,
		StatusState:    statusState,
		StatusCode:     statusCode,
		StatusRecovery: item.StatusRecovery,
		ListenerState:  item.ListenerState,
		OriginPool:     item.OriginPool,

		HTTPSCertificateBound: item.HTTPSCertificateBound,
		Basic: siteBasicPayload{
			PackageID:                uuidPointerString(item.PackageID),
			PackageSubscriptionID:    uuidPointerString(item.PackageSubscriptionID),
			CNAMEMode:                stringPointerValue(item.CNAMEMode),
			CNAMEDomain:              stringPointerValue(item.CNAMEDomain),
			CNAMEHostname:            stringPointerValue(item.CNAMEHostname),
			PackageName:              packageName,
			GroupID:                  uuidPointerString(item.GroupID),
			GroupName:                groupName,
			Domains:                  item.Domains,
			HTTPEnabled:              true,
			HTTPListenPorts:          item.HTTPPorts,
			HTTPSListenPorts:         item.HTTPSPorts,
			IPv6Enabled:              item.ListenerState.IPv6DesiredEnabled,
			Origins:                  item.Origins,
			CNAME:                    item.CNAME,
			TLSProtocols:             tlsProtocolsPayload(append([]string(nil), item.TLSProtocols...)),
			CNAMEState:               item.CNAMEState,
			CNAMEFailureCode:         item.CNAMEFailureCode,
			CNAMETaskID:              uuidPointerString(item.CNAMETaskID),
			CNAMECurrentRevision:     item.CNAMECurrentRevision,
			CNAMELKGRevision:         item.CNAMELKGRevision,
			HTTPSEnabled:             item.HTTPSEnabled,
			ForceHTTPS:               &forceHTTPS,
			HTTPSRedirectPort:        &redirectPort,
			CacheSharedAcrossDomains: &cacheShared,
			CacheStatusHeader:        &cacheStatusHeader,
			TLSCipherPreset:          &tlsCipherPreset,
			TLSCipherSuites:          append([]string(nil), item.TLSCipherSuites...),
			TLSOCSPStapling:          &tlsOCSPStapling,
			TLSClientAuth:            &tlsClientAuth,
			TLSClientCAPEM:           &tlsClientCAPEM,
			Enabled:                  item.Enabled,
			Status:                   item.Status,
			SyncStatus:               &syncStatus,
			IsDefault:                item.IsDefault,
			HTTP2Enabled:             &http2Enabled,
			HTTP3Enabled:             &http3Enabled,
			TLSPreferServerCiphers:   tlsPreferServerCiphers,
		},
		TrafficEnforcement: item.TrafficEnforcement,
		PackageExpiresAt:   expiresAt,
		PackageExpiredDays: expiredDays,

		PackageRemainingDays: remainingDays,
		AccessReadiness:      item.AccessReadiness,

		PackageUnavailableReason: item.PackageUnavailableReason,
	}
}

// handleCheckSiteAccess: 详情 > 接入状态 > 立即检查 (fix-readiness). It
// resolves the site's domains through the control plane's resolver now and
// returns the readiness; once a minute per site (429 + Retry-After).
func (s *Server) handleCheckSiteAccess(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	readiness, err := s.sites.CheckAccessNow(r.Context(), siteActor(principal), id)
	var throttled *site.AccessCheckThrottledError
	if errors.As(err, &throttled) {
		w.Header().Set("Retry-After", strconv.FormatInt(int64(throttled.Wait/time.Second), 10))
		s.writeAPIError(w, r, http.StatusTooManyRequests, "access_check_throttled", "the site was checked less than a minute ago")
		return
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, readiness)
}

const siteDomainCSVContentType = "text/csv; charset=utf-8"

type SiteDomainExportSnapshot struct {
	ID            uuid.UUID
	ActorUserID   uuid.UUID
	ActorScopeID  uuid.UUID
	TargetScopeID uuid.UUID
	FilterSHA256  [32]byte
}

type SiteDomainExportCursor struct {
	SnapshotID    uuid.UUID
	ActorUserID   uuid.UUID
	ActorScopeID  uuid.UUID
	TargetScopeID uuid.UUID
	FilterSHA256  [32]byte
	RowSequence   int
}

type siteDomainExportRow struct {
	SiteID   uuid.UUID
	Domain   string
	Revision int64
	Enabled  bool
}

func writeSiteDomainExportCSV(writer io.Writer, rows []siteDomainExportRow) error {
	encoder := csv.NewWriter(writer)
	if err := encoder.Write(strings.Split(siteDomainExportCSVHeader(), ",")); err != nil {
		return err
	}
	for _, row := range rows {
		if err := encoder.Write([]string{
			row.SiteID.String(),
			sanitizeSiteDomainCSVCell(row.Domain),
			strconv.FormatInt(row.Revision, 10),
			strconv.FormatBool(row.Enabled),
		}); err != nil {
			return err
		}
	}
	encoder.Flush()
	return encoder.Error()
}

func sanitizeSiteDomainCSVCell(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	default:
		return value
	}
}

func siteDomainExportCSVHeader() string {
	return "site_id,domain,revision,enabled"
}

func siteDomainExportContractSource() string {
	return strings.Join([]string{
		"sites.export", siteDomainCSVContentType,
		"SiteDomainExportSnapshot", "SiteDomainExportCursor",
		"actor_user_id", "actor_scope_id", "target_scope_id", "filter_sha256",
	}, "\n")
}

func decodeSiteJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("changes must contain one JSON object")
	}
	return nil
}

func parseSiteListFilter(r *http.Request) (site.ListFilter, error) {
	allowed := map[string]bool{
		"page": true, "limit": true, "domain": true, "domains": true, "origin_ip": true,
		"site_ids": true, "owner": true, "package_id": true, "package": true, "site": true, "group_id": true,
		"region_id": true, "node_group_id": true, "cname_domain": true,
		"cname_hostname": true, "http_port": true, "https_port": true,
		"https_enabled": true, "enabled": true, "status": true, "is_default": true,
		"sync_status": true,
	}
	query := r.URL.Query()
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return site.ListFilter{}, site.ErrInvalidInput
		}
	}
	page, err := positiveIntOr(query.Get("page"), 1)
	if err != nil {
		return site.ListFilter{}, err
	}
	limit, err := positiveIntOr(query.Get("limit"), 20)
	if err != nil {
		return site.ListFilter{}, err
	}
	filter := site.ListFilter{
		Page: page, Limit: limit, Domain: query.Get("domain"), Owner: query.Get("owner"),
		Package: query.Get("package"), Site: query.Get("site"),
		OriginIP: query.Get("origin_ip"), CNAMEDomain: query.Get("cname_domain"),
		CNAMEHostname: query.Get("cname_hostname"), HTTPPort: query.Get("http_port"),
		HTTPSPort: query.Get("https_port"), Status: query.Get("status"), SyncStatus: query.Get("sync_status"),
	}
	if rawStatus := strings.TrimSpace(query.Get("status")); rawStatus != "" {
		if code, parseErr := strconv.Atoi(rawStatus); parseErr == nil {
			state, ok := statusStateFromCompatibilityCode(code)
			if !ok {
				return site.ListFilter{}, site.ErrInvalidInput
			}
			filter.Status = storedStatusFromOperationalState(state)
		} else {
			state := site.OperationalStatus(rawStatus)
			if stored := storedStatusFromOperationalState(state); stored != "" {
				filter.Status = stored
			}
		}
	}
	filter.Domains = splitFilter(query.Get("domains"))
	for _, raw := range splitFilter(query.Get("site_ids")) {
		id, err := uuid.Parse(raw)
		if err != nil {
			return site.ListFilter{}, err
		}
		filter.SiteIDs = append(filter.SiteIDs, id)
	}
	for _, target := range []struct {
		raw         string
		destination **uuid.UUID
	}{
		{query.Get("package_id"), &filter.PackageID},
		{query.Get("group_id"), &filter.GroupID},
		{query.Get("region_id"), &filter.RegionID},
		{query.Get("node_group_id"), &filter.NodeGroupID},
	} {
		raw, destination := target.raw, target.destination
		if raw == "" {
			continue
		}
		id, err := uuid.Parse(raw)
		if err != nil {
			return site.ListFilter{}, err
		}
		*destination = &id
	}
	for _, target := range []struct {
		raw         string
		destination **bool
	}{
		{query.Get("https_enabled"), &filter.HTTPSEnabled},
		{query.Get("enabled"), &filter.Enabled},
		{query.Get("is_default"), &filter.IsDefault},
	} {
		raw, destination := target.raw, target.destination
		if raw == "" {
			continue
		}
		value, err := strictBool(raw)
		if err != nil {
			return site.ListFilter{}, err
		}
		*destination = &value
	}
	return filter, nil
}

func optionalUUID(raw string) (uuid.UUID, error) {
	if strings.TrimSpace(raw) == "" {
		return uuid.Nil, nil
	}
	return uuid.Parse(raw)
}

func optionalUUIDPointer(raw *string) (*uuid.UUID, error) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil, nil
	}
	id, err := uuid.Parse(*raw)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func uuidPointerString(value *uuid.UUID) *string {
	if value == nil {
		return nil
	}
	raw := value.String()
	return &raw
}

func stringPointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func splitFilter(raw string) []string {
	return strings.FieldsFunc(raw, func(character rune) bool {
		return character == ',' || character == ' ' || character == '\n' || character == '\t'
	})
}

func positiveIntOr(raw string, fallback int) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, site.ErrInvalidInput
	}
	return value, nil
}

func strictBool(raw string) (bool, error) {
	switch raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, site.ErrInvalidInput
	}
}

func quoteVersion(version int64) string {
	return `"` + strconv.FormatInt(version, 10) + `"`
}

func parseIfMatch(raw string) (int64, error) {
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, site.ErrInvalidInput
	}
	version, err := strconv.ParseInt(raw[1:len(raw)-1], 10, 64)
	if err != nil || version < 1 {
		return 0, site.ErrInvalidInput
	}
	return version, nil
}

// writeDomainTrustError adds the refused domain and its apex so the site
// form can open the ownership verification step.
func (s *Server) writeDomainTrustError(w http.ResponseWriter, r *http.Request, err error, status int, code, message string) {
	var detail *domaintrust.DomainError
	if !errors.As(err, &detail) {
		s.writeAPIError(w, r, status, code, message)
		return
	}
	writeJSONStatus(w, status, map[string]any{"error": map[string]any{
		"code": code, "message": message, "request_id": requestID(r.Context()),
		"domain": detail.Domain, "apex": detail.Apex,
	}})
}
