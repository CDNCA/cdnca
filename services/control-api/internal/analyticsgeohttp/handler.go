package analyticsgeohttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
)

const (
	defaultQueryTimeout = 3 * time.Second
	maximumQueryTimeout = 10 * time.Second
	maximumRawQuery     = 4096
)

type Authenticator func(*http.Request) (analyticsgeo.Actor, error)

type lookupService interface {
	Lookup(context.Context, analyticsgeo.Actor, analyticsgeo.QueryRequest) (analyticsgeo.Item, error)
}

type Config struct{ QueryTimeout time.Duration }

type Handler struct {
	service      lookupService
	authenticate Authenticator
	queryTimeout time.Duration
}

type responseEnvelope struct {
	Data responseData `json:"data"`
}

type responseData struct {
	EventID             string                      `json:"event_id"`
	OccurredAt          time.Time                   `json:"occurred_at"`
	SiteID              string                      `json:"site_id"`
	NodeID              string                      `json:"node_id"`
	SourceCountryCode   string                      `json:"source_country_code"`
	SourceCarrier       string                      `json:"source_carrier"`
	CountryCode         string                      `json:"country_code"`
	Region              string                      `json:"region"`
	City                string                      `json:"city"`
	Carrier             string                      `json:"carrier"`
	ASN                 uint32                      `json:"asn"`
	AddressFamily       string                      `json:"address_family"`
	LookupReason        analyticsgeo.LookupReason   `json:"lookup_reason"`
	Resolution          analyticsgeo.Resolution     `json:"resolution"`
	Reconciliation      analyticsgeo.Reconciliation `json:"reconciliation"`
	PrefixLength        int                         `json:"prefix_length"`
	DatabaseVersion     string                      `json:"database_version"`
	DatabaseProvider    string                      `json:"database_provider"`
	DatabaseSHA256      string                      `json:"database_sha256"`
	DatabasePublishedAt time.Time                   `json:"database_published_at"`
	DatabaseEffectiveAt time.Time                   `json:"database_effective_at"`
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func NewHandler(service lookupService, authenticate Authenticator, config Config) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, analyticsgeo.ErrInvalidConfiguration
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultQueryTimeout
	}
	if config.QueryTimeout < time.Millisecond || config.QueryTimeout > maximumQueryTimeout {
		return nil, analyticsgeo.ErrInvalidConfiguration
	}
	return &Handler{service: service, authenticate: authenticate, queryTimeout: config.QueryTimeout}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	audience, kind, eventID, ok := resolveRoute(request)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed, "analytics_geo_method_not_allowed", "method not allowed")
		return
	}
	if request.URL == nil || len(request.URL.RawQuery) > maximumRawQuery || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		writeError(writer, http.StatusBadRequest, "analytics_geo_invalid_request", "invalid request")
		return
	}
	actor, err := handler.authenticate(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "analytics_geo_unauthenticated", "authentication required")
		return
	}
	query, err := parseQuery(request, audience, kind, eventID)
	if err != nil {
		if errors.Is(err, analyticsgeo.ErrScopeForbidden) {
			writeError(writer, http.StatusForbidden, "analytics_geo_scope_forbidden", "scope forbidden")
			return
		}
		writeError(writer, http.StatusBadRequest, "analytics_geo_invalid_request", "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	item, err := handler.service.Lookup(ctx, actor, query)
	if err != nil {
		writeServiceError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, responseEnvelope{Data: responseData{
		EventID: item.EventID, OccurredAt: item.OccurredAt, SiteID: item.SiteID, NodeID: item.NodeID,
		SourceCountryCode: item.SourceCountryCode, SourceCarrier: item.SourceCarrier,
		CountryCode: item.CountryCode, Region: item.Region, City: item.City, Carrier: item.Carrier, ASN: item.ASN,
		AddressFamily: item.AddressFamily, LookupReason: item.LookupReason,
		Resolution: item.Resolution, Reconciliation: item.Reconciliation, PrefixLength: item.PrefixLength,
		DatabaseVersion: item.Provenance.Version, DatabaseProvider: item.Provenance.Provider,
		DatabaseSHA256: item.Provenance.SHA256, DatabasePublishedAt: item.Provenance.PublishedAt,
		DatabaseEffectiveAt: item.Provenance.EffectiveAt,
	}})
}

func resolveRoute(request *http.Request) (analyticsgeo.Audience, analyticsgeo.Kind, string, bool) {
	if request == nil || request.URL == nil {
		return 0, "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(parts) == 7 && parts[0] == "v1" && parts[1] == "admin" && parts[2] == "analytics" &&
		parts[3] == "logs" && parts[5] == "geo-evidence" {
		return analyticsgeo.AudiencePlatform, analyticsgeo.Kind(parts[4]), parts[6], true
	}
	if len(parts) == 6 && parts[0] == "v1" && parts[1] == "analytics" && parts[2] == "logs" && parts[4] == "geo-evidence" {
		return analyticsgeo.AudienceTenant, analyticsgeo.Kind(parts[3]), parts[5], true
	}
	return 0, "", "", false
}

func parseQuery(request *http.Request, audience analyticsgeo.Audience, kind analyticsgeo.Kind, eventID string) (analyticsgeo.QueryRequest, error) {
	values := request.URL.Query()
	allowed := map[string]bool{"from": true, "to": true, "tenant_id": true, "site_id": true, "node_id": true,
		"client_ip": true, "database_version": true}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return analyticsgeo.QueryRequest{}, analyticsgeo.ErrInvalidInput
		}
	}
	if audience == analyticsgeo.AudienceTenant {
		if _, present := values["tenant_id"]; present {
			return analyticsgeo.QueryRequest{}, analyticsgeo.ErrScopeForbidden
		}
	}
	from, fromErr := time.Parse(time.RFC3339Nano, values.Get("from"))
	to, toErr := time.Parse(time.RFC3339Nano, values.Get("to"))
	if fromErr != nil || toErr != nil {
		return analyticsgeo.QueryRequest{}, analyticsgeo.ErrInvalidInput
	}
	return analyticsgeo.QueryRequest{
		Audience: audience, TenantID: values.Get("tenant_id"), Kind: kind, EventID: eventID,
		From: from, To: to, SiteID: values.Get("site_id"), NodeID: values.Get("node_id"),
		ClientIP: values.Get("client_ip"), DatabaseVersion: values.Get("database_version"),
	}, nil
}

func writeServiceError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, context.Canceled):
		writeError(writer, http.StatusRequestTimeout, "analytics_geo_request_cancelled", "request cancelled")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(writer, http.StatusGatewayTimeout, "analytics_geo_timeout", "query timed out")
	case errors.Is(err, analyticsgeo.ErrInvalidInput):
		writeError(writer, http.StatusBadRequest, "analytics_geo_invalid_request", "invalid request")
	case errors.Is(err, analyticsgeo.ErrPermissionDenied), errors.Is(err, analyticsgeo.ErrScopeForbidden):
		writeError(writer, http.StatusForbidden, "analytics_geo_permission_denied", "permission denied")
	case errors.Is(err, analyticsgeo.ErrNotFound), errors.Is(err, analyticsgeo.ErrVersionNotFound):
		writeError(writer, http.StatusNotFound, "analytics_geo_evidence_not_found", "evidence not found")
	case errors.Is(err, analyticsgeo.ErrCapacityExceeded):
		writeError(writer, http.StatusConflict, "analytics_geo_ambiguous_event", "event identity is ambiguous")
	case errors.Is(err, analyticsgeo.ErrInvalidResponse):
		writeError(writer, http.StatusBadGateway, "analytics_geo_invalid_response", "evidence invalid")
	default:
		writeError(writer, http.StatusServiceUnavailable, "analytics_geo_unavailable", "evidence unavailable")
	}
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	response := errorEnvelope{}
	response.Error.Code, response.Error.Message = code, message
	writeJSON(writer, status, response)
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
