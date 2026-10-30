package cachecontrolhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	maxRequestBytes  = 17 << 20
	maxResponseBytes = 64 << 20
)

type Handler struct {
	service      *Service
	authenticate AuthenticateFunc
	mux          *http.ServeMux
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
		// Details: *TargetRejection (invalid_request) or *DailyLimitDetails
		// (daily_limit_exceeded).
		Details any `json:"details,omitempty"`
	} `json:"error"`
}

type publishBody struct {
	ExpectedRevision           *int64                       `json:"expected_revision"`
	BindingMode                cachecontrol.BindingMode     `json:"binding_mode"`
	DefinitionID               *string                      `json:"definition_id"`
	DefinitionRevision         *int64                       `json:"definition_revision"`
	ExpectedDefinitionRevision *int64                       `json:"expected_definition_revision"`
	Document                   *cachecontrol.PolicyDocument `json:"document"`
}

type createOperationBody struct {
	SiteID     string                  `json:"site_id"`
	Action     cachecontrol.Action     `json:"action"`
	TargetType cachecontrol.TargetType `json:"target_type"`
	Targets    []string                `json:"targets"`
	NodeIDs    []string                `json:"node_ids"`
	MaxRetries uint32                  `json:"max_retries"`
}

func NewHandler(service *Service, authenticate AuthenticateFunc) (*Handler, error) {
	if service == nil || service.control == nil || service.reader == nil || authenticate == nil {
		return nil, ErrInvalidRequest
	}
	handler := &Handler{service: service, authenticate: authenticate, mux: http.NewServeMux()}
	for _, route := range []struct {
		prefix   string
		audience Audience
	}{
		{"/v1", AudienceTenant},
		{"/v1/admin", AudiencePlatform},
	} {
		prefix, audience := route.prefix, route.audience
		handler.mux.HandleFunc(prefix+"/cache-policies/{site_id}", func(w http.ResponseWriter, r *http.Request) {
			handler.policy(w, r, audience)
		})
		handler.mux.HandleFunc(prefix+"/cache-policies/{site_id}/revisions", func(w http.ResponseWriter, r *http.Request) {
			handler.policyHistory(w, r, audience)
		})
		handler.mux.HandleFunc(prefix+"/cache-policies/{site_id}/revisions/{revision}", func(w http.ResponseWriter, r *http.Request) {
			handler.policyRevision(w, r, audience)
		})
		handler.mux.HandleFunc(prefix+"/cache-operations", func(w http.ResponseWriter, r *http.Request) {
			handler.operations(w, r, audience)
		})
		handler.mux.HandleFunc(prefix+"/cache-operations/daily-usage", func(w http.ResponseWriter, r *http.Request) {
			handler.dailyUsage(w, r, audience)
		})
		handler.mux.HandleFunc(prefix+"/cache-operations/target-sites", func(w http.ResponseWriter, r *http.Request) {
			handler.targetSites(w, r, audience)
		})
		handler.mux.HandleFunc(prefix+"/cache-operations/carrying-nodes", func(w http.ResponseWriter, r *http.Request) {
			handler.carryingNodes(w, r, audience)
		})
		handler.mux.HandleFunc(prefix+"/cache-operations/{operation_id}", func(w http.ResponseWriter, r *http.Request) {
			handler.operation(w, r, audience)
		})
		handler.mux.HandleFunc(prefix+"/cache-operations/{operation_id}/retry", func(w http.ResponseWriter, r *http.Request) {
			handler.command(w, r, audience, commandRetry)
		})
		handler.mux.HandleFunc(prefix+"/cache-operations/{operation_id}/cancel", func(w http.ResponseWriter, r *http.Request) {
			handler.command(w, r, audience, commandCancel)
		})
		handler.mux.HandleFunc(prefix+"/cache-operations/{operation_id}/resubmit", func(w http.ResponseWriter, r *http.Request) {
			handler.command(w, r, audience, commandResubmit)
		})
		// Not under /cache-operations/: {operation_id}/retry would make the
		// ServeMux patterns ambiguous.
		handler.mux.HandleFunc(prefix+"/cache-operation-requests/{idempotency_key}", func(w http.ResponseWriter, r *http.Request) {
			handler.writeReceipt(w, r, audience)
		})
	}
	handler.mux.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		handler.writeError(response, request, ErrNotFound)
	})
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	requestID := request.Header.Get("X-Request-ID")
	if !metadataPattern.MatchString(requestID) {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	response.Header().Set("X-Request-ID", requestID)
	handler.mux.ServeHTTP(response, request)
}

func (handler *Handler) policy(response http.ResponseWriter, request *http.Request, audience Audience) {
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "GET, POST")
		return
	}
	principal, targetScopeID, ok := handler.principal(response, request, audience, nil)
	if !ok {
		return
	}
	siteID, err := canonicalUUID(request.PathValue("site_id"))
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	if request.Method == http.MethodGet {
		result, err := handler.service.CurrentPolicy(request.Context(), principal, audience, targetScopeID, siteID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Revision))
		handler.writeJSON(response, request, http.StatusOK, result)
		return
	}
	metadata, err := writeMetadata(request)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	var body publishBody
	if decodeBody(response, request, &body) != nil || body.ExpectedRevision == nil {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	bindingMode := body.BindingMode
	if bindingMode == "" {
		bindingMode = cachecontrol.BindingOverride
	}
	var definitionID uuid.UUID
	if body.DefinitionID != nil {
		definitionID, err = canonicalUUID(*body.DefinitionID)
		if err != nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
	}
	var document cachecontrol.PolicyDocument
	var definitionRevision int64
	switch bindingMode {
	case cachecontrol.BindingInherit:
		if definitionID == uuid.Nil || body.DefinitionRevision == nil || *body.DefinitionRevision < 1 ||
			body.ExpectedDefinitionRevision != nil || body.Document != nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		definitionRevision = *body.DefinitionRevision
	case cachecontrol.BindingOverride:
		if body.Document == nil || body.DefinitionRevision != nil ||
			(body.ExpectedDefinitionRevision != nil && *body.ExpectedDefinitionRevision < 0) ||
			(definitionID != uuid.Nil && definitionID != siteID && body.ExpectedDefinitionRevision == nil) {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		document = *body.Document
	default:
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	result, err := handler.service.PublishPolicy(request.Context(), principal, audience, targetScopeID, PublishInput{
		SiteID: siteID, ExpectedRevision: *body.ExpectedRevision, BindingMode: bindingMode,
		DefinitionID: definitionID, DefinitionRevision: definitionRevision,
		ExpectedDefinitionRevision: body.ExpectedDefinitionRevision, Document: document, WriteMetadata: metadata,
	})
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	if result.Replayed {
		response.Header().Set("Idempotency-Replayed", "true")
	}
	response.Header().Set("ETag", quoteRevision(result.Value.Revision))
	response.Header().Set("Location", fmt.Sprintf("%s/revisions/%d", request.URL.Path, result.Value.Revision))
	handler.writeJSON(response, request, http.StatusCreated, result.Value)
}

func (handler *Handler) policyHistory(response http.ResponseWriter, request *http.Request, audience Audience) {
	if request.Method != http.MethodGet {
		handler.methodNotAllowed(response, request, "GET")
		return
	}
	principal, targetScopeID, ok := handler.principal(response, request, audience, map[string]bool{"limit": true, "cursor": true})
	if !ok {
		return
	}
	siteID, err := canonicalUUID(request.PathValue("site_id"))
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	limit, cursor, err := pageQuery(request)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	result, err := handler.service.PolicyHistory(request.Context(), principal, audience, targetScopeID, HistoryInput{
		SiteID: siteID, Limit: limit, Cursor: cursor,
	})
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeJSON(response, request, http.StatusOK, result)
}

func (handler *Handler) policyRevision(response http.ResponseWriter, request *http.Request, audience Audience) {
	if request.Method != http.MethodGet {
		handler.methodNotAllowed(response, request, "GET")
		return
	}
	principal, targetScopeID, ok := handler.principal(response, request, audience, nil)
	if !ok {
		return
	}
	siteID, err := canonicalUUID(request.PathValue("site_id"))
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	rawRevision := request.PathValue("revision")
	revision, err := strconv.ParseInt(rawRevision, 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != rawRevision {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	result, err := handler.service.PolicyRevision(request.Context(), principal, audience, targetScopeID, siteID, revision)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(result.Revision))
	handler.writeJSON(response, request, http.StatusOK, result)
}

func (handler *Handler) operations(response http.ResponseWriter, request *http.Request, audience Audience) {
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "GET, POST")
		return
	}
	allowed := map[string]bool{}
	if request.Method == http.MethodGet {
		allowed = map[string]bool{
			"limit": true, "cursor": true, "site_id": true, "action": true,
			"site_display_id": true, "search": true, "target_type": true, "state": true,
		}
	}
	principal, targetScopeID, ok := handler.principal(response, request, audience, allowed)
	if !ok {
		return
	}
	if request.Method == http.MethodGet {
		input, err := operationListInput(request)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.Operations(request.Context(), principal, audience, targetScopeID, input)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeJSON(response, request, http.StatusOK, result)
		return
	}
	metadata, err := writeMetadata(request)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	var body createOperationBody
	if decodeBody(response, request, &body) != nil {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	siteID, err := canonicalUUID(body.SiteID)
	// node_ids may be omitted: the operation then runs on every node that
	// carries the site (and nodes that start carrying it while it is open).
	if err != nil || len(body.NodeIDs) > 1000 || len(body.Targets) > EdgeCacheTaskV2MaxTargets {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	targetBytes := 0
	for _, target := range body.Targets {
		targetBytes += len(target)
		if len(target) > EdgeCacheTaskV2MaxTargetBytes || targetBytes > EdgeCacheTaskV2MaxTaskTargetBytes {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
	}
	nodeIDs := make([]uuid.UUID, len(body.NodeIDs))
	for index, raw := range body.NodeIDs {
		nodeIDs[index], err = canonicalUUID(raw)
		if err != nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
	}
	result, err := handler.service.CreateOperation(request.Context(), principal, audience, targetScopeID, CreateOperationInput{
		SiteID: siteID, Action: body.Action, TargetType: body.TargetType, Targets: body.Targets,
		NodeIDs: nodeIDs, MaxRetries: body.MaxRetries, WriteMetadata: metadata,
	})
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	if result.Replayed {
		response.Header().Set("Idempotency-Replayed", "true")
	}
	response.Header().Set("Location", request.URL.Path+"/"+result.Value.ID.String())
	handler.writeJSON(response, request, http.StatusAccepted, result.Value)
}

func (handler *Handler) operation(response http.ResponseWriter, request *http.Request, audience Audience) {
	if request.Method != http.MethodGet {
		handler.methodNotAllowed(response, request, "GET")
		return
	}
	principal, targetScopeID, ok := handler.principal(response, request, audience, nil)
	if !ok {
		return
	}
	operationID, err := canonicalUUID(request.PathValue("operation_id"))
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	result, err := handler.service.Operation(request.Context(), principal, audience, targetScopeID, operationID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeJSON(response, request, http.StatusOK, result)
}

type accountLimitsBody struct {
	ExpectedRevision *int64 `json:"expected_revision"`
	URLPurge         *int   `json:"url_purge_limit"`
	DirectoryPurge   *int   `json:"directory_purge_limit"`
	Prewarm          *int   `json:"prewarm_limit"`
}

// dailyUsage: GET .../cache-operations/daily-usage (CACHE-01): the account's
// quotas of today (fix-cachequota: per account; the platform route names the
// account with scope_id). PUT /v1/admin/cache-operations/daily-usage sets
// the account's own limits (null = follow the system setting default).
func (handler *Handler) dailyUsage(response http.ResponseWriter, request *http.Request, audience Audience) {
	if request.Method != http.MethodGet && (audience != AudiencePlatform || request.Method != http.MethodPut) {
		if audience == AudiencePlatform {
			handler.methodNotAllowed(response, request, "GET, PUT")
		} else {
			handler.methodNotAllowed(response, request, "GET")
		}
		return
	}
	principal, targetScopeID, ok := handler.principal(response, request, audience, nil)
	if !ok {
		return
	}
	var result cachecontrol.DailyUsage
	var err error
	if request.Method == http.MethodPut {
		var body accountLimitsBody
		if decodeBody(response, request, &body) != nil || body.ExpectedRevision == nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		requestID := request.Header.Get("X-Request-ID")
		result, err = handler.service.SetAccountLimits(request.Context(), principal, targetScopeID, cachecontrol.SetAccountLimitsRequest{
			ExpectedRevision: *body.ExpectedRevision, RequestID: requestID,
			Limits: cachecontrol.AccountLimits{URLPurge: body.URLPurge, DirectoryPurge: body.DirectoryPurge, Prewarm: body.Prewarm},
		})
	} else {
		result, err = handler.service.DailyUsage(request.Context(), principal, audience, targetScopeID)
	}
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeJSON(response, request, http.StatusOK, result)
}

type targetSitesBody struct {
	Action     cachecontrol.Action     `json:"action"`
	TargetType cachecontrol.TargetType `json:"target_type"`
	Targets    []string                `json:"targets"`
}

// targetSites: POST .../cache-operations/target-sites (fix-cachedlg), a read
// that writes nothing. The platform route's scope_id is optional: without it
// the URLs match every tenant's sites.
func (handler *Handler) targetSites(response http.ResponseWriter, request *http.Request, audience Audience) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	authAudience := audience
	if audience == AudiencePlatform && request.URL.Query().Get("scope_id") == "" {
		// principal() demands scope_id on the platform route; check the
		// rest of the query here instead.
		authAudience = AudienceTenant
	}
	principal, targetScopeID, ok := handler.principal(response, request, authAudience, nil)
	if !ok {
		return
	}
	var body targetSitesBody
	if decodeBody(response, request, &body) != nil || len(body.Targets) == 0 ||
		len(body.Targets) > EdgeCacheTaskV2MaxTargets {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	targetBytes := 0
	for _, target := range body.Targets {
		targetBytes += len(target)
		if len(target) > EdgeCacheTaskV2MaxTargetBytes || targetBytes > EdgeCacheTaskV2MaxTaskTargetBytes {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
	}
	result, err := handler.service.TargetSites(request.Context(), principal, audience, targetScopeID,
		cachecontrol.ResolveTargetSitesRequest{Action: body.Action, TargetType: body.TargetType, Targets: body.Targets})
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeJSON(response, request, http.StatusOK, result)
}

// carryingNodes: GET .../cache-operations/carrying-nodes, the nodes an
// operation of the scope without node IDs runs on.
func (handler *Handler) carryingNodes(response http.ResponseWriter, request *http.Request, audience Audience) {
	if request.Method != http.MethodGet {
		handler.methodNotAllowed(response, request, "GET")
		return
	}
	principal, targetScopeID, ok := handler.principal(response, request, audience, nil)
	if !ok {
		return
	}
	result, err := handler.service.CarryingNodes(request.Context(), principal, audience, targetScopeID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeJSON(response, request, http.StatusOK, result)
}

// writeReceipt: GET .../cache-operation-requests/{idempotency_key}?action=
// [&operation_id=] (fix-cacheflow5), what the server did with a write whose
// response was lost.
func (handler *Handler) writeReceipt(response http.ResponseWriter, request *http.Request, audience Audience) {
	if request.Method != http.MethodGet {
		handler.methodNotAllowed(response, request, "GET")
		return
	}
	principal, targetScopeID, ok := handler.principal(response, request, audience,
		map[string]bool{"action": true, "operation_id": true})
	if !ok {
		return
	}
	key := request.PathValue("idempotency_key")
	input := cachecontrol.WriteReceiptRequest{
		Action: cachecontrol.WriteAction(request.URL.Query().Get("action")), IdempotencyKey: key,
	}
	if raw := request.URL.Query().Get("operation_id"); raw != "" {
		operationID, err := canonicalUUID(raw)
		if err != nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		input.OperationID = operationID
	}
	needsOperation := input.Action == cachecontrol.WriteRetry || input.Action == cachecontrol.WriteCancel ||
		input.Action == cachecontrol.WriteResubmit
	if !metadataPattern.MatchString(key) ||
		(input.Action != cachecontrol.WriteCreate && !needsOperation) ||
		needsOperation != (input.OperationID != uuid.Nil) {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	result, err := handler.service.WriteReceipt(request.Context(), principal, audience, targetScopeID, input)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeJSON(response, request, http.StatusOK, result)
}

type operationCommand int

const (
	commandRetry operationCommand = iota
	commandCancel
	commandResubmit
)

func (handler *Handler) command(response http.ResponseWriter, request *http.Request, audience Audience, command operationCommand) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	principal, targetScopeID, ok := handler.principal(response, request, audience, nil)
	if !ok {
		return
	}
	operationID, err := canonicalUUID(request.PathValue("operation_id"))
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	metadata, err := writeMetadata(request)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	var body struct{}
	if decodeBody(response, request, &body) != nil {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	input := CommandInput{OperationID: operationID, WriteMetadata: metadata}
	var result WriteResult[OperationView]
	switch command {
	case commandRetry:
		result, err = handler.service.Retry(request.Context(), principal, audience, targetScopeID, input)
	case commandCancel:
		result, err = handler.service.Cancel(request.Context(), principal, audience, targetScopeID, input)
	default:
		result, err = handler.service.Resubmit(request.Context(), principal, audience, targetScopeID, input)
	}
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	if result.Replayed {
		response.Header().Set("Idempotency-Replayed", "true")
	}
	if command == commandResubmit {
		// The new operation, like POST /cache-operations.
		response.Header().Set("Location", strings.TrimSuffix(request.URL.Path,
			request.PathValue("operation_id")+"/resubmit")+result.Value.ID.String())
		handler.writeJSON(response, request, http.StatusAccepted, result.Value)
		return
	}
	handler.writeJSON(response, request, http.StatusOK, result.Value)
}

func (handler *Handler) principal(
	response http.ResponseWriter,
	request *http.Request,
	audience Audience,
	allowedQuery map[string]bool,
) (identity.Principal, *uuid.UUID, bool) {
	principal, err := handler.authenticate(request)
	if err != nil || principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		handler.writeError(response, request, ErrUnauthenticated)
		return identity.Principal{}, nil, false
	}
	allowed := make(map[string]bool, len(allowedQuery)+1)
	for key, value := range allowedQuery {
		allowed[key] = value
	}
	if audience == AudiencePlatform {
		allowed["scope_id"] = true
	}
	if validateQuery(request, allowed) != nil {
		handler.writeError(response, request, ErrInvalidRequest)
		return identity.Principal{}, nil, false
	}
	if audience == AudienceTenant {
		return principal, nil, true
	}
	scopeID, err := canonicalUUID(request.URL.Query().Get("scope_id"))
	if err != nil {
		handler.writeError(response, request, ErrInvalidRequest)
		return identity.Principal{}, nil, false
	}
	return principal, &scopeID, true
}

func operationListInput(request *http.Request) (OperationListInput, error) {
	limit, cursor, err := pageQuery(request)
	if err != nil {
		return OperationListInput{}, err
	}
	input := OperationListInput{Limit: limit, Cursor: cursor}
	input.Filters.Search = request.URL.Query().Get("search")
	if raw := request.URL.Query().Get("site_id"); raw != "" {
		value, err := canonicalUUID(raw)
		if err != nil {
			return OperationListInput{}, err
		}
		input.Filters.SiteID = &value
	}
	input.Filters.SiteDisplayID = request.URL.Query().Get("site_display_id")
	input.Filters.Action = cachecontrol.Action(request.URL.Query().Get("action"))
	input.Filters.TargetType = cachecontrol.TargetType(request.URL.Query().Get("target_type"))
	// state=a,b: any of the states, in any order.
	if raw := request.URL.Query().Get("state"); raw != "" {
		for _, value := range strings.Split(raw, ",") {
			state := cachecontrol.State(value)
			if !slices.Contains(input.Filters.States, state) {
				input.Filters.States = append(input.Filters.States, state)
			}
		}
		slices.Sort(input.Filters.States)
	}
	if !validFilters(input.Filters) {
		return OperationListInput{}, ErrInvalidRequest
	}
	return input, nil
}

func pageQuery(request *http.Request) (int, string, error) {
	limit := 50
	if raw := request.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 || strconv.Itoa(value) != raw {
			return 0, "", ErrInvalidRequest
		}
		limit = value
	}
	cursor := request.URL.Query().Get("cursor")
	if len(cursor) > maxCursorBytes {
		return 0, "", ErrInvalidRequest
	}
	return limit, cursor, nil
}

func validateQuery(request *http.Request, allowed map[string]bool) error {
	query, err := parseCanonicalQuery(request.URL.RawQuery)
	if err != nil {
		return err
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return ErrInvalidRequest
		}
	}
	return nil
}

var queryKeyPattern = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)

func parseCanonicalQuery(raw string) (url.Values, error) {
	if raw == "" {
		return url.Values{}, nil
	}
	// fix-cacheflow2 P2-07 (CACHE-ADD-02): a value is decoded once with the
	// standard rules (URLSearchParams sends "/" as %2F, "," as %2C, " " as
	// "+"); a key stays a plain name (no encoded alias), every pair needs a
	// value, and a bad escape, ";" or a repeated key is refused.
	for _, pair := range strings.Split(raw, "&") {
		rawKey, rawValue, found := strings.Cut(pair, "=")
		if !found || rawKey == "" || rawValue == "" || !queryKeyPattern.MatchString(rawKey) {
			return nil, ErrInvalidRequest
		}
		if _, err := url.QueryUnescape(rawValue); err != nil {
			return nil, ErrInvalidRequest
		}
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	for _, values := range query {
		if len(values) != 1 || values[0] == "" {
			return nil, ErrInvalidRequest
		}
	}
	return query, nil
}

func writeMetadata(request *http.Request) (WriteMetadata, error) {
	metadata := WriteMetadata{
		IdempotencyKey: request.Header.Get("Idempotency-Key"),
		RequestID:      request.Header.Get("X-Request-ID"),
	}
	if !validMetadata(metadata) {
		return WriteMetadata{}, ErrInvalidRequest
	}
	return metadata, nil
}

func decodeBody(response http.ResponseWriter, request *http.Request, destination any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || request.Body == nil {
		return ErrInvalidRequest
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || len(raw) == 0 || len(raw) > maxRequestBytes || rejectDuplicateKeys(raw) != nil ||
		validateBodyFields(raw, destination) != nil {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidRequest
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidRequest
				}
				folded := strings.ToLower(key)
				if _, exists := seen[folded]; exists {
					return ErrInvalidRequest
				}
				seen[folded] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrInvalidRequest
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func validateBodyFields(raw []byte, destination any) error {
	switch destination.(type) {
	case *publishBody:
		root, err := exactJSONObject(raw, []string{"expected_revision"}, []string{
			"binding_mode", "definition_id", "definition_revision", "expected_definition_revision", "document",
		})
		if err != nil {
			return err
		}
		rawDocument, exists := root["document"]
		if !exists {
			return nil
		}
		document, err := exactJSONObject(rawDocument, []string{
			"mode", "rules", "query_mode", "query_names", "vary_headers", "disk_quota_bytes",
		}, []string{"schema_version", "stale_if_error", "background_update", "min_object_bytes", "max_object_bytes", "slice_bytes"})
		if err != nil {
			return err
		}
		var rules []json.RawMessage
		if err := json.Unmarshal(document["rules"], &rules); err != nil || rules == nil {
			return ErrInvalidRequest
		}
		for _, rule := range rules {
			if _, err := exactJSONObject(rule, []string{"order", "ttl_seconds"},
				[]string{"extensions", "path_prefix", "status_codes", "action", "browser_ttl_seconds",
					"path_regex", "content_types",
					// schema v2 rule extras (edgeconfig.CacheRuleExtras); values are checked by Normalize
					"path_exact", "ignore_query", "slice_bytes", "force_cache", "ignore_vary", "no_cache"}); err != nil {
				return err
			}
		}
		return nil
	case *createOperationBody:
		_, err := exactJSONObject(raw, []string{
			"site_id", "action", "target_type", "targets", "node_ids", "max_retries",
		}, nil)
		return err
	case *targetSitesBody:
		_, err := exactJSONObject(raw, []string{"action", "target_type", "targets"}, nil)
		return err
	case *accountLimitsBody:
		// All four keys are required: null is "follow the default", an absent
		// key would silently reset a limit.
		// exactJSONObject refuses null, which here means "follow the default".
		var root map[string]json.RawMessage
		if json.Unmarshal(raw, &root) != nil || len(root) != 4 {
			return ErrInvalidRequest
		}
		for _, key := range []string{"expected_revision", "url_purge_limit", "directory_purge_limit", "prewarm_limit"} {
			if _, exists := root[key]; !exists {
				return ErrInvalidRequest
			}
		}
		return nil
	case *struct{}:
		_, err := exactJSONObject(raw, nil, nil)
		return err
	default:
		return ErrInvalidRequest
	}
}

func exactJSONObject(raw []byte, required, optional []string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, ErrInvalidRequest
	}
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = struct{}{}
	}
	for _, key := range optional {
		allowed[key] = struct{}{}
	}
	for key, value := range object {
		if _, exists := allowed[key]; !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrInvalidRequest
		}
	}
	for _, key := range required {
		if _, exists := object[key]; !exists {
			return nil, ErrInvalidRequest
		}
	}
	return object, nil
}

func quoteRevision(revision int64) string {
	return `"` + strconv.FormatInt(revision, 10) + `"`
}

func (handler *Handler) methodNotAllowed(response http.ResponseWriter, request *http.Request, allow string) {
	response.Header().Set("Allow", allow)
	handler.writeAPIError(response, request, http.StatusMethodNotAllowed, "method_not_allowed", "request method is not allowed")
}

func (handler *Handler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	var rejection *TargetRejection
	var limit *cachecontrol.DailyLimitError
	switch {
	case errors.As(err, &limit):
		handler.writeErrorEnvelope(response, request, http.StatusTooManyRequests, "daily_limit_exceeded",
			"the account's daily purge or prewarm limit would be exceeded", &DailyLimitDetails{
				Field: "targets", Reason: "daily_limit_exceeded", Quota: string(limit.Quota),
				Limit: limit.Limit, Used: limit.Used, Requested: limit.Requested,
			})
	case errors.As(err, &rejection):
		handler.writeErrorEnvelope(response, request, http.StatusBadRequest, "invalid_request", "a target is invalid for the site", rejection)
	case errors.Is(err, ErrUnauthenticated):
		handler.writeAPIError(response, request, http.StatusUnauthorized, "authentication_required", "authentication is required")
	case errors.Is(err, ErrWildcardTargetHost):
		handler.writeAPIError(response, request, http.StatusBadRequest, "wildcard_target_host",
			"a prewarm target URL host must be a concrete name, not a wildcard")
	case errors.Is(err, ErrInvalidRequest):
		handler.writeAPIError(response, request, http.StatusBadRequest, "invalid_request", "request is invalid")
	case errors.Is(err, ErrPermissionDenied):
		handler.writeAPIError(response, request, http.StatusForbidden, "permission_denied", "permission is denied")
	case errors.Is(err, ErrNotFound):
		handler.writeAPIError(response, request, http.StatusNotFound, "not_found", "resource was not found")
	case errors.Is(err, ErrRevisionConflict):
		handler.writeAPIError(response, request, http.StatusPreconditionFailed, "revision_conflict", "cache policy revision has changed")
	case errors.Is(err, ErrIdempotencyConflict):
		handler.writeAPIError(response, request, http.StatusConflict, "idempotency_conflict", "idempotency key was used with another request")
	case errors.Is(err, ErrInvalidTransition):
		handler.writeAPIError(response, request, http.StatusConflict, "invalid_operation_transition", "cache operation cannot transition from its current state")
	case errors.Is(err, ErrRetriesExhausted):
		handler.writeAPIError(response, request, http.StatusConflict, "retries_exhausted", "cache operation retry budget is exhausted")
	case errors.Is(err, ErrEntitlementDenied):
		handler.writeAPIError(response, request, http.StatusForbidden, "entitlement_denied", "cache operation is not allowed by the active entitlement")
	case errors.Is(err, ErrSiteLocked):
		handler.writeAPIError(response, request, http.StatusConflict, "site_locked", "site is locked by a platform administrator")
	case errors.Is(err, ErrDailyLimitExceeded):
		handler.writeAPIError(response, request, http.StatusTooManyRequests, "daily_limit_exceeded",
			"the account's daily purge or prewarm limit would be exceeded")
	case errors.Is(err, ErrNoCarryingNode):
		handler.writeAPIError(response, request, http.StatusConflict, "no_carrying_node", "no node carries the site yet")
	case errors.Is(err, ErrTargetNodeUnavailable):
		handler.writeErrorEnvelope(response, request, http.StatusConflict, "target_node_unavailable",
			"a named node is not available for the site", &TargetRejection{
				Field: "node_ids", Stage: "node_selection", Reason: "target_node_unavailable",
			})
	case errors.Is(err, ErrWildcardPurgeUnsupported):
		handler.writeAPIError(response, request, http.StatusConflict, "wildcard_purge_unsupported",
			"a target node does not support wildcard purge; upgrade the node agent or list concrete hosts")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		handler.writeAPIError(response, request, http.StatusRequestTimeout, "request_cancelled", "request was cancelled")
	default:
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "service_unavailable", "a required dependency is unavailable")
	}
}

func (handler *Handler) writeAPIError(response http.ResponseWriter, request *http.Request, status int, code, message string) {
	handler.writeErrorEnvelope(response, request, status, code, message, nil)
}

func (handler *Handler) writeErrorEnvelope(response http.ResponseWriter, request *http.Request, status int, code, message string,
	details any) {
	var envelope errorEnvelope
	envelope.Error.Code = code
	envelope.Error.Message = message
	if details != nil {
		envelope.Error.Details = details
	}
	envelope.Error.RequestID = request.Header.Get("X-Request-ID")
	if !metadataPattern.MatchString(envelope.Error.RequestID) {
		envelope.Error.RequestID = "invalid"
	}
	handler.writeJSON(response, request, status, envelope)
}

func (handler *Handler) writeJSON(response http.ResponseWriter, request *http.Request, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxResponseBytes {
		if status == http.StatusServiceUnavailable {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "service_unavailable", "a required dependency is unavailable")
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_, _ = response.Write(append(encoded, '\n'))
}
