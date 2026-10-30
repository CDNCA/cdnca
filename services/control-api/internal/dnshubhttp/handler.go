// Package dnshubhttp serves 用户端「域名解析」(ADR 0020 §3.2): the tenant's own
// DNS accounts' domains and their A/AAAA/CNAME/TXT records. Tenant session
// only; dns.read for reads, dns.manage for writes (checked in the database by
// dnsproviderremotesource.Hub). Community edition.
//
//	GET    /v1/dns/hub/domains?provider_id=&q=&cursor=&limit=
//	POST   /v1/dns/hub/domains/refresh                                  {provider_id?}
//	GET    /v1/dns/hub/domains/{provider_id}/{apex}/records?type=&q=
//	POST   /v1/dns/hub/domains/{provider_id}/{apex}/records              (Idempotency-Key)
//	PATCH  /v1/dns/hub/domains/{provider_id}/{apex}/records/{record_ref} (Idempotency-Key)
//	DELETE /v1/dns/hub/domains/{provider_id}/{apex}/records/{record_ref} (Idempotency-Key)
//	POST   /v1/dns/hub/records/batch                                    (Idempotency-Key)
package dnshubhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	maxBodyBytes  = 256 << 10
	maxBatchItems = 50
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Patterns are the routes the control-api server forwards here.
var Patterns = []string{
	"GET /v1/dns/hub/domains",
	"POST /v1/dns/hub/domains/refresh",
	"GET /v1/dns/hub/domains/{provider_id}/{apex}/records",
	"POST /v1/dns/hub/domains/{provider_id}/{apex}/records",
	"PATCH /v1/dns/hub/domains/{provider_id}/{apex}/records/{record_ref}",
	"DELETE /v1/dns/hub/domains/{provider_id}/{apex}/records/{record_ref}",
	"POST /v1/dns/hub/records/batch",
}

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

// Service is the hub (dnsproviderremotesource.Hub).
type Service interface {
	ListDomains(context.Context, dnsproviderremotesource.HubActor, dnsproviderremotesource.HubDomainQuery) (dnsproviderremotesource.HubDomainPage, error)
	RefreshDomains(context.Context, dnsproviderremotesource.HubActor, uuid.UUID) ([]dnsproviderremotesource.HubRefreshResult, error)
	ListRecords(context.Context, dnsproviderremotesource.HubActor, uuid.UUID, string, dnsproviderremotesource.HubRecordQuery) (dnsproviderremotesource.HubRecordList, error)
	Mutate(context.Context, dnsproviderremotesource.HubActor, dnsproviderremotesource.HubMutation) (dnsproviderremotesource.HubMutationResult, error)
}

type Handler struct {
	hub          Service
	authenticate AuthenticateSessionFunc
	mux          *http.ServeMux
}

func NewHandler(hub Service, authenticate AuthenticateSessionFunc) (*Handler, error) {
	if hub == nil || authenticate == nil {
		return nil, errors.New("DNS hub handler dependencies are required")
	}
	handler := &Handler{hub: hub, authenticate: authenticate, mux: http.NewServeMux()}
	routes := map[string]http.HandlerFunc{
		"GET /v1/dns/hub/domains":                                              handler.listDomains,
		"POST /v1/dns/hub/domains/refresh":                                     handler.refresh,
		"GET /v1/dns/hub/domains/{provider_id}/{apex}/records":                 handler.listRecords,
		"POST /v1/dns/hub/domains/{provider_id}/{apex}/records":                handler.mutation("create"),
		"PATCH /v1/dns/hub/domains/{provider_id}/{apex}/records/{record_ref}":  handler.mutation("update"),
		"DELETE /v1/dns/hub/domains/{provider_id}/{apex}/records/{record_ref}": handler.mutation("delete"),
		"POST /v1/dns/hub/records/batch":                                       handler.batch,
	}
	for _, pattern := range Patterns {
		handler.mux.HandleFunc(pattern, routes[pattern])
	}
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	handler.mux.ServeHTTP(response, request)
}

// session authenticates the bearer token of a tenant session; the hub checks
// membership and permission in its own transaction.
func (handler *Handler) session(response http.ResponseWriter, request *http.Request) (dnsproviderremotesource.HubActor, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || values[0][7:] == "" ||
		strings.TrimSpace(values[0][7:]) != values[0][7:] {
		writeError(response, request, http.StatusUnauthorized, "unauthorized", "authentication is required", nil)
		return dnsproviderremotesource.HubActor{}, false
	}
	session, err := handler.authenticate(request.Context(), values[0][7:])
	if err != nil || session.Principal.UserID == uuid.Nil || session.SessionID == uuid.Nil {
		writeError(response, request, http.StatusUnauthorized, "unauthorized", "authentication is required", nil)
		return dnsproviderremotesource.HubActor{}, false
	}
	if session.Principal.ScopeKind != "tenant" {
		writeError(response, request, http.StatusForbidden, "permission_denied", "permission is required", nil)
		return dnsproviderremotesource.HubActor{}, false
	}
	return dnsproviderremotesource.HubActor{UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID,
		ScopeKind: session.Principal.ScopeKind, RequestID: requestID(request)}, true
}

func (handler *Handler) listDomains(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request)
	if !ok {
		return
	}
	values := request.URL.Query()
	for key, value := range values {
		if key != "provider_id" && key != "q" && key != "cursor" && key != "limit" || len(value) != 1 {
			writeFieldError(response, request, key)
			return
		}
	}
	query := dnsproviderremotesource.HubDomainQuery{Query: values.Get("q"), Cursor: values.Get("cursor")}
	if raw := values.Get("provider_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeFieldError(response, request, "provider_id")
			return
		}
		query.ProviderID = id
	}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || strconv.Itoa(limit) != raw || limit < 1 {
			writeFieldError(response, request, "limit")
			return
		}
		query.Limit = limit
	}
	page, err := handler.hub.ListDomains(request.Context(), actor, query)
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, page)
}

func (handler *Handler) refresh(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request)
	if !ok {
		return
	}
	var body struct {
		ProviderID string `json:"provider_id"`
	}
	if request.ContentLength != 0 && !decode(response, request, &body) {
		return
	}
	providerID := uuid.Nil
	if body.ProviderID != "" {
		id, err := uuid.Parse(body.ProviderID)
		if err != nil {
			writeFieldError(response, request, "provider_id")
			return
		}
		providerID = id
	}
	results, err := handler.hub.RefreshDomains(request.Context(), actor, providerID)
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"results": results})
}

func (handler *Handler) listRecords(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request)
	if !ok {
		return
	}
	providerID, err := uuid.Parse(request.PathValue("provider_id"))
	if err != nil {
		writeError(response, request, http.StatusNotFound, "dns_hub_not_found", "DNS account or domain was not found", nil)
		return
	}
	values := request.URL.Query()
	for key, value := range values {
		if key != "type" && key != "q" || len(value) != 1 {
			writeFieldError(response, request, key)
			return
		}
	}
	list, err := handler.hub.ListRecords(request.Context(), actor, providerID, request.PathValue("apex"),
		dnsproviderremotesource.HubRecordQuery{Type: values.Get("type"), Query: values.Get("q")})
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, list)
}

// mutationBody is the single-record request body (§3.2).
type mutationBody struct {
	Name           string                                  `json:"name"`
	Type           string                                  `json:"type"`
	Value          string                                  `json:"value"`
	TTL            uint32                                  `json:"ttl"`
	Line           string                                  `json:"line"`
	Weight         uint32                                  `json:"weight"`
	Expected       *dnsproviderremotesource.HubRecordInput `json:"expected"`
	ConfirmManaged bool                                    `json:"confirm_managed"`
}

func (body mutationBody) mutation(action string, providerID uuid.UUID, apex, ref, key string) dnsproviderremotesource.HubMutation {
	return dnsproviderremotesource.HubMutation{ProviderID: providerID, Apex: apex, Action: action, RecordRef: ref,
		Record: dnsproviderremotesource.HubRecordInput{Name: body.Name, Type: body.Type, Value: body.Value,
			TTL: body.TTL, Line: body.Line, Weight: body.Weight},
		Expected: body.Expected, ConfirmManaged: body.ConfirmManaged, IdempotencyKey: key}
}

func (handler *Handler) mutation(action string) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		actor, ok := handler.session(response, request)
		if !ok {
			return
		}
		key, ok := idempotencyKey(response, request)
		if !ok {
			return
		}
		providerID, err := uuid.Parse(request.PathValue("provider_id"))
		if err != nil {
			writeError(response, request, http.StatusNotFound, "dns_hub_not_found", "DNS account or domain was not found", nil)
			return
		}
		var body mutationBody
		if !decode(response, request, &body) {
			return
		}
		result, err := handler.hub.Mutate(request.Context(), actor,
			body.mutation(action, providerID, request.PathValue("apex"), request.PathValue("record_ref"), key))
		if err != nil {
			writeServiceError(response, request, err)
			return
		}
		writeJSON(response, result.Status, result)
	}
}

type batchItem struct {
	mutationBody
	ProviderID string `json:"provider_id"`
	Apex       string `json:"apex"`
	Action     string `json:"action"`
	RecordRef  string `json:"record_ref"`
}

type batchResult struct {
	Index  int                                `json:"index"`
	Status int                                `json:"status"`
	OpID   *uuid.UUID                         `json:"op_id,omitempty"`
	State  string                             `json:"state,omitempty"`
	Record *dnsproviderremotesource.HubRecord `json:"record,omitempty"`
	Error  map[string]any                     `json:"error"`
}

// batch runs each item on its own (no rollback across items). Item i uses
// the key "<Idempotency-Key>.<i>", so a retried batch replays every item.
func (handler *Handler) batch(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	if len(key) > 120 {
		writeError(response, request, http.StatusBadRequest, "validation_error", "Idempotency-Key is too long for a batch", map[string]any{"field": "Idempotency-Key"})
		return
	}
	var body struct {
		Items []json.RawMessage `json:"items"`
	}
	if !decode(response, request, &body) {
		return
	}
	if len(body.Items) == 0 || len(body.Items) > maxBatchItems {
		writeFieldError(response, request, "items")
		return
	}
	results := make([]batchResult, 0, len(body.Items))
	for index, raw := range body.Items {
		result := batchResult{Index: index}
		var item batchItem
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		providerID, parseErr := uuid.Nil, error(nil)
		if decodeErr := decoder.Decode(&item); decodeErr != nil {
			result.Status, result.Error = http.StatusBadRequest, errorBody(request, "invalid_request", "item is invalid", nil)
		} else if providerID, parseErr = uuid.Parse(item.ProviderID); parseErr != nil {
			result.Status, result.Error = http.StatusNotFound, errorBody(request, "dns_hub_not_found", "DNS account or domain was not found", nil)
		} else if item.Action != "create" && item.Action != "update" && item.Action != "delete" {
			result.Status, result.Error = http.StatusBadRequest, errorBody(request, "validation_error", "request fields are invalid", map[string]any{"field": "action"})
		} else {
			outcome, err := handler.hub.Mutate(request.Context(), actor,
				item.mutation(item.Action, providerID, item.Apex, item.RecordRef, key+"."+strconv.Itoa(index)))
			if err != nil {
				result.Status, result.Error = serviceError(request, err)
			} else {
				result.Status, result.OpID, result.State, result.Record = outcome.Status, &outcome.OpID, outcome.State, outcome.Record
			}
		}
		results = append(results, result)
	}
	writeJSON(response, http.StatusOK, map[string]any{"results": results})
}

func requestID(request *http.Request) string {
	if id := request.Header.Get("X-Request-ID"); requestIDPattern.MatchString(id) {
		return id
	}
	return uuid.NewString()
}

func idempotencyKey(response http.ResponseWriter, request *http.Request) (string, bool) {
	keys := request.Header.Values("Idempotency-Key")
	if len(keys) != 1 || !requestIDPattern.MatchString(keys[0]) {
		writeError(response, request, http.StatusBadRequest, "validation_error", "Idempotency-Key is required",
			map[string]any{"field": "Idempotency-Key"})
		return "", false
	}
	return keys[0], true
}

func decode(response http.ResponseWriter, request *http.Request, destination any) bool {
	if !strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/json") {
		writeError(response, request, http.StatusUnsupportedMediaType, "unsupported_media_type", "JSON body is required", nil)
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxBodyBytes))
	if err != nil {
		writeError(response, request, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large", nil)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeError(response, request, http.StatusBadRequest, "invalid_request", "request body is invalid", nil)
		return false
	}
	return true
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func errorBody(request *http.Request, code, message string, extra map[string]any) map[string]any {
	body := map[string]any{"code": code, "message": message, "request_id": request.Header.Get("X-Request-ID")}
	for key, value := range extra {
		body[key] = value
	}
	return body
}

func writeError(response http.ResponseWriter, request *http.Request, status int, code, message string, extra map[string]any) {
	writeJSON(response, status, map[string]any{"error": errorBody(request, code, message, extra)})
}

func writeFieldError(response http.ResponseWriter, request *http.Request, field string) {
	writeError(response, request, http.StatusBadRequest, "validation_error", "request fields are invalid", map[string]any{"field": field})
}

func writeServiceError(response http.ResponseWriter, request *http.Request, err error) {
	status, body := serviceError(request, err)
	if retry, ok := body["retry_after_seconds"].(int); ok && retry > 0 {
		response.Header().Set("Retry-After", strconv.Itoa(retry))
	}
	writeJSON(response, status, map[string]any{"error": body})
}

// serviceError maps a hub error to the §3.2 contract. Provider failures carry
// only the stable short code (never provider bodies or credentials).
func serviceError(request *http.Request, err error) (int, map[string]any) {
	var field *dnsproviderremotesource.HubFieldError
	var changed *dnsproviderremotesource.HubChangedError
	var managed *dnsproviderremotesource.HubManagedError
	var provider *dnsproviderremote.Error
	switch {
	case errors.As(err, &field):
		return http.StatusBadRequest, errorBody(request, "validation_error", "request fields are invalid", map[string]any{"field": field.Field})
	case errors.Is(err, dnsproviderremotesource.ErrHubInvalid):
		return http.StatusBadRequest, errorBody(request, "validation_error", "request fields are invalid", nil)
	case errors.Is(err, dnsproviderremotesource.ErrHubPermission):
		return http.StatusForbidden, errorBody(request, "permission_denied", "permission is required", nil)
	case errors.Is(err, dnsproviderremotesource.ErrHubNotFound):
		return http.StatusNotFound, errorBody(request, "dns_hub_not_found", "DNS account or domain was not found", nil)
	case errors.Is(err, dnsproviderremotesource.ErrHubIdempotency):
		return http.StatusConflict, errorBody(request, "idempotency_conflict", "Idempotency-Key was used for another request", nil)
	case errors.As(err, &changed):
		return http.StatusConflict, errorBody(request, "dns_record_changed", "the record changed at the DNS provider; reload it",
			map[string]any{"current": changed.Current})
	case errors.As(err, &managed):
		return http.StatusConflict, errorBody(request, "dns_record_managed", "this record is used by the platform; confirm to change it",
			map[string]any{"managed": managed.Managed})
	case errors.Is(err, dnsproviderremotesource.ErrHubConflict):
		return http.StatusConflict, errorBody(request, "dns_record_conflict", "the record conflicts with records under the same name", nil)
	case errors.Is(err, dnsproviderremotesource.ErrHubUnsupported):
		return http.StatusUnprocessableEntity, errorBody(request, "dns_record_unsupported", "the DNS provider does not support this record", nil)
	case errors.As(err, &provider):
		extra := map[string]any{"provider_code": strings.TrimPrefix(string(provider.Code), "dns_provider_remote_")}
		if provider.Temporary && provider.RetryAfter > 0 {
			extra["retry_after_seconds"] = int(provider.RetryAfter.Seconds() + 0.999)
		}
		return http.StatusBadGateway, errorBody(request, "dns_provider_error", "the DNS provider did not complete the request", extra)
	default:
		return http.StatusServiceUnavailable, errorBody(request, "dns_hub_unavailable", "DNS records are temporarily unavailable", nil)
	}
}
