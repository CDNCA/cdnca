package errorpagecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

const (
	apiPrefix       = "/v1/error-pages"
	maxJSONBody     = 64 << 10
	maxResponseBody = int(MaxEdgePolicyBytes) + maxJSONBody
)

type Authenticator interface {
	Authenticate(*http.Request) (Actor, error)
}

type HTTPDomain interface {
	InitiateAsset(context.Context, Actor, InitiateAssetRequest) (WriteResult[Asset], error)
	UploadAsset(context.Context, Actor, UploadAssetRequest) (WriteResult[Asset], error)
	FinalizeAsset(context.Context, Actor, FinalizeAssetRequest) (WriteResult[Asset], error)
	DeleteAsset(context.Context, Actor, DeleteAssetRequest) (WriteResult[Asset], error)
	GetAsset(context.Context, Actor, uuid.UUID) (Asset, error)
	GetAssetContent(context.Context, Actor, uuid.UUID) (AssetContent, error)
	ListAssets(context.Context, Actor, AssetPageRequest) (AssetPage, error)
	CreateRule(context.Context, Actor, CreateRuleRequest) (WriteResult[Rule], error)
	UpdateRule(context.Context, Actor, UpdateRuleRequest) (WriteResult[Rule], error)
	EnableRule(context.Context, Actor, ChangeRuleStateRequest) (WriteResult[Rule], error)
	DisableRule(context.Context, Actor, ChangeRuleStateRequest) (WriteResult[Rule], error)
	DeleteRule(context.Context, Actor, ChangeRuleStateRequest) (WriteResult[Rule], error)
	GetRule(context.Context, Actor, uuid.UUID) (Rule, error)
	ListRules(context.Context, Actor, RulePageRequest) (RulePage, error)
	PublicationSnapshot(context.Context, Actor) (PublicationSnapshot, error)
}

type Handler struct {
	domain HTTPDomain
	auth   Authenticator
}

func NewHandler(domain HTTPDomain, authenticator Authenticator) (*Handler, error) {
	if isNilDependency(domain) || isNilDependency(authenticator) {
		return nil, ErrInvalidStore
	}
	return &Handler{domain: domain, auth: authenticator}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setResponseHeaders(response)
	if requestID := request.Header.Get("X-Request-ID"); writeMetadataPattern.MatchString(requestID) {
		response.Header().Set("X-Request-ID", requestID)
	}
	if !validHost(request.Host) || request.URL.RawPath != "" {
		writeHTTPError(response, ErrInvalidInput)
		return
	}
	if request.URL.Path != apiPrefix && !strings.HasPrefix(request.URL.Path, apiPrefix+"/") {
		writeHTTPError(response, ErrNotFound)
		return
	}
	if !declaredRoute(request.URL.Path) {
		writeHTTPError(response, ErrNotFound)
		return
	}
	if _, err := url.ParseQuery(request.URL.RawQuery); err != nil {
		writeHTTPError(response, ErrInvalidInput)
		return
	}
	actor, err := handler.auth.Authenticate(request)
	if err != nil {
		if errors.Is(err, ErrInvalidCredential) || errors.Is(err, ErrUnauthenticated) {
			writeHTTPError(response, ErrUnauthenticated)
		} else {
			writeHTTPError(response, ErrUnavailable)
		}
		return
	}
	if err := validateActor(actor); err != nil {
		writeHTTPError(response, ErrUnauthenticated)
		return
	}
	path := strings.TrimPrefix(request.URL.Path, apiPrefix)
	if path == "" {
		path = "/"
	}
	methods := allowedMethods(path)
	methodAllowed := false
	for _, method := range methods {
		if request.Method == method {
			methodAllowed = true
			break
		}
	}
	if !methodAllowed {
		response.Header().Set("Allow", strings.Join(methods, ", "))
		writeHTTPError(response, errMethodNotAllowed)
		return
	}
	switch {
	case path == "/assets/initiate":
		handler.handleAssetInitiate(response, request, actor)
	case path == "/assets":
		handler.handleAssetList(response, request, actor)
	case strings.HasPrefix(path, "/assets/"):
		handler.handleAssetResource(response, request, actor, strings.TrimPrefix(path, "/assets/"))
	case path == "/rules":
		handler.handleRules(response, request, actor)
	case strings.HasPrefix(path, "/rules/"):
		handler.handleRuleResource(response, request, actor, strings.TrimPrefix(path, "/rules/"))
	case path == "/slots":
		handler.handleSlots(response, request, actor)
	case strings.HasPrefix(path, "/slots/"):
		handler.handleSlotResource(response, request, actor, strings.TrimPrefix(path, "/slots/"))
	case path == "/scope-overrides":
		handler.handleScopeOverrides(response, request, actor)
	case strings.HasPrefix(path, "/scope-overrides/"):
		handler.handleScopeOverrideResource(response, request, actor, strings.TrimPrefix(path, "/scope-overrides/"))
	case path == "/publication-snapshot":
		if request.Method != http.MethodGet || !onlyQuery(request.URL.Query()) {
			writeMethodOrInput(response, request.Method == http.MethodGet)
			return
		}
		result, err := handler.domain.PublicationSnapshot(request.Context(), actor)
		writeDomainResponse(response, http.StatusOK, result, err)
	default:
		writeHTTPError(response, ErrNotFound)
	}
}

func allowedMethods(path string) []string {
	switch path {
	case "/assets/initiate":
		return []string{http.MethodPost}
	case "/assets", "/slots", "/publication-snapshot":
		return []string{http.MethodGet}
	case "/rules", "/scope-overrides":
		return []string{http.MethodGet, http.MethodPost}
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 2 {
		switch parts[0] {
		case "assets":
			return []string{http.MethodGet, http.MethodDelete}
		case "rules":
			return []string{http.MethodGet, http.MethodPatch, http.MethodDelete}
		case "slots":
			return []string{http.MethodGet, http.MethodPut, http.MethodDelete}
		case "scope-overrides":
			return []string{http.MethodGet, http.MethodPatch, http.MethodDelete}
		}
	}
	if len(parts) == 3 {
		switch parts[0] + "/" + parts[2] {
		case "assets/content":
			return []string{http.MethodGet, http.MethodPut}
		case "assets/finalize", "rules/enable", "rules/disable":
			return []string{http.MethodPost}
		}
	}
	return nil
}

func declaredRoute(path string) bool {
	if path == apiPrefix+"/assets" || path == apiPrefix+"/assets/initiate" ||
		path == apiPrefix+"/rules" || path == apiPrefix+"/slots" ||
		path == apiPrefix+"/scope-overrides" || path == apiPrefix+"/publication-snapshot" {
		return true
	}
	relative := strings.TrimPrefix(path, apiPrefix+"/")
	parts := strings.Split(relative, "/")
	if len(parts) < 2 || parts[1] == "" {
		return false
	}
	if parts[0] == "slots" {
		return len(parts) == 2 && validSlotKey(parts[1])
	}
	if parts[0] == "scope-overrides" {
		_, err := positiveDisplayID(parts[1])
		return len(parts) == 2 && err == nil
	}
	if _, err := strictUUID(parts[1]); err != nil {
		return false
	}
	switch parts[0] {
	case "assets":
		return len(parts) == 2 || len(parts) == 3 &&
			(parts[2] == "content" || parts[2] == "finalize")
	case "rules":
		return len(parts) == 2 || len(parts) == 3 &&
			(parts[2] == "enable" || parts[2] == "disable")
	default:
		return false
	}
}

type initiateAssetBody struct {
	ScopeID   uuid.UUID `json:"scope_id"`
	Name      string    `json:"name"`
	MIMEType  string    `json:"mime_type"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
}

func (handler *Handler) handleAssetInitiate(response http.ResponseWriter, request *http.Request, actor Actor) {
	if request.Method != http.MethodPost || !onlyQuery(request.URL.Query()) {
		if request.Method == http.MethodPost {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		writeHTTPError(response, errMethodNotAllowed)
		return
	}
	metadata, err := writeMetadataFromHeaders(request)
	if err != nil {
		writeHTTPError(response, err)
		return
	}
	var body initiateAssetBody
	if err := decodeJSONBody(request, &body); err != nil {
		writeHTTPError(response, err)
		return
	}
	result, err := handler.domain.InitiateAsset(request.Context(), actor, InitiateAssetRequest{
		Target: AssetTarget{ScopeID: body.ScopeID}, Name: body.Name, MIME: body.MIMEType, Size: body.SizeBytes,
		SHA256: body.SHA256, WriteMetadata: metadata,
	})
	writeDomainResponse(response, http.StatusCreated, result, err)
}

func (handler *Handler) handleAssetList(response http.ResponseWriter, request *http.Request, actor Actor) {
	if request.Method != http.MethodGet {
		writeHTTPError(response, errMethodNotAllowed)
		return
	}
	if !onlyQuery(request.URL.Query(), "scope_id", "limit", "cursor", "status") {
		writeHTTPError(response, ErrInvalidInput)
		return
	}
	scopeID, err := optionalUUID(request.URL.Query().Get("scope_id"))
	if err != nil {
		writeHTTPError(response, err)
		return
	}
	limit, err := queryLimit(request.URL.Query().Get("limit"))
	if err != nil {
		writeHTTPError(response, err)
		return
	}
	result, err := handler.domain.ListAssets(request.Context(), actor, AssetPageRequest{
		TargetScopeID: scopeID, Limit: limit, Cursor: request.URL.Query().Get("cursor"),
		Status: request.URL.Query().Get("status"),
	})
	writeDomainResponse(response, http.StatusOK, result, err)
}

func (handler *Handler) handleAssetResource(response http.ResponseWriter, request *http.Request, actor Actor, suffix string) {
	parts := strings.Split(suffix, "/")
	if len(parts) < 1 || len(parts) > 2 {
		writeHTTPError(response, ErrNotFound)
		return
	}
	id, err := strictUUID(parts[0])
	if err != nil {
		writeHTTPError(response, err)
		return
	}
	if len(parts) == 2 {
		switch parts[1] {
		case "content":
			if request.Method == http.MethodGet {
				if !onlyQuery(request.URL.Query()) || !emptyBody(request) {
					writeHTTPError(response, ErrInvalidInput)
					return
				}
				result, err := handler.domain.GetAssetContent(request.Context(), actor, id)
				writeDomainResponse(response, http.StatusOK, result, err)
				return
			}
			handler.handleAssetUpload(response, request, actor, id)
		case "finalize":
			handler.handleAssetFinalize(response, request, actor, id)
		default:
			writeHTTPError(response, ErrNotFound)
		}
		return
	}
	switch request.Method {
	case http.MethodGet:
		if !onlyQuery(request.URL.Query()) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		result, err := handler.domain.GetAsset(request.Context(), actor, id)
		writeDomainResponse(response, http.StatusOK, result, err)
	case http.MethodDelete:
		if !onlyQuery(request.URL.Query()) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		metadata, err := writeMetadataFromHeaders(request)
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		revision, err := expectedRevision(request.Header.Get("If-Match"))
		if err != nil || !emptyBody(request) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		result, err := handler.domain.DeleteAsset(request.Context(), actor, DeleteAssetRequest{
			AssetID: id, ExpectedRevision: revision, WriteMetadata: metadata,
		})
		writeDomainResponse(response, http.StatusAccepted, result, err)
	default:
		writeHTTPError(response, errMethodNotAllowed)
	}
}

func (handler *Handler) handleAssetUpload(response http.ResponseWriter, request *http.Request, actor Actor, id uuid.UUID) {
	if request.Method != http.MethodPut || !onlyQuery(request.URL.Query()) {
		writeMethodOrInput(response, request.Method == http.MethodPut)
		return
	}
	metadata, err := writeMetadataFromHeaders(request)
	if err != nil {
		writeHTTPError(response, err)
		return
	}
	mime := request.Header.Get("Content-Type")
	if !validMIME(mime) || request.ContentLength < 1 || request.ContentLength > MaxEdgeResourceBytes {
		writeHTTPError(response, ErrInvalidInput)
		return
	}
	result, err := handler.domain.UploadAsset(request.Context(), actor, UploadAssetRequest{
		AssetID: id, MIMEType: mime, ContentLength: request.ContentLength, Body: request.Body,
		WriteMetadata: metadata,
	})
	writeDomainResponse(response, http.StatusOK, result, err)
}

func (handler *Handler) handleAssetFinalize(response http.ResponseWriter, request *http.Request, actor Actor, id uuid.UUID) {
	if request.Method != http.MethodPost || !onlyQuery(request.URL.Query()) {
		writeMethodOrInput(response, request.Method == http.MethodPost)
		return
	}
	metadata, err := writeMetadataFromHeaders(request)
	if err != nil || !emptyBody(request) {
		writeHTTPError(response, ErrInvalidInput)
		return
	}
	result, err := handler.domain.FinalizeAsset(request.Context(), actor, FinalizeAssetRequest{
		AssetID: id, WriteMetadata: metadata,
	})
	writeDomainResponse(response, http.StatusOK, result, err)
}

type createRuleBody struct {
	Target RuleTarget `json:"target"`
	Fields RuleFields `json:"fields"`
}

func (handler *Handler) handleRules(response http.ResponseWriter, request *http.Request, actor Actor) {
	switch request.Method {
	case http.MethodGet:
		if !onlyQuery(request.URL.Query(), "scope_id", "site_id", "enabled", "limit", "cursor") {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		scopeID, err := optionalUUID(request.URL.Query().Get("scope_id"))
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		siteID, err := optionalUUIDPointer(request.URL.Query().Get("site_id"))
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		enabled, err := optionalBool(request.URL.Query().Get("enabled"))
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		limit, err := queryLimit(request.URL.Query().Get("limit"))
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		result, err := handler.domain.ListRules(request.Context(), actor, RulePageRequest{
			TargetScopeID: scopeID, SiteID: siteID, Enabled: enabled, Limit: limit,
			Cursor: request.URL.Query().Get("cursor"),
		})
		writeDomainResponse(response, http.StatusOK, result, err)
	case http.MethodPost:
		if !onlyQuery(request.URL.Query()) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		metadata, err := writeMetadataFromHeaders(request)
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		var body createRuleBody
		if err := decodeJSONBody(request, &body); err != nil {
			writeHTTPError(response, err)
			return
		}
		result, err := handler.domain.CreateRule(request.Context(), actor, CreateRuleRequest{
			Target: body.Target, Fields: body.Fields, WriteMetadata: metadata,
		})
		writeDomainResponse(response, http.StatusCreated, result, err)
	default:
		writeHTTPError(response, errMethodNotAllowed)
	}
}

func (handler *Handler) handleRuleResource(response http.ResponseWriter, request *http.Request, actor Actor, suffix string) {
	parts := strings.Split(suffix, "/")
	if len(parts) < 1 || len(parts) > 2 {
		writeHTTPError(response, ErrNotFound)
		return
	}
	id, err := strictUUID(parts[0])
	if err != nil {
		writeHTTPError(response, err)
		return
	}
	if len(parts) == 2 {
		if parts[1] != "enable" && parts[1] != "disable" || request.Method != http.MethodPost {
			writeHTTPError(response, errMethodNotAllowed)
			return
		}
		if !onlyQuery(request.URL.Query()) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		metadata, err := writeMetadataFromHeaders(request)
		revision, revisionErr := expectedRevision(request.Header.Get("If-Match"))
		if err != nil || revisionErr != nil || !emptyBody(request) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		input := ChangeRuleStateRequest{RuleID: id, ExpectedRevision: revision, WriteMetadata: metadata}
		var result WriteResult[Rule]
		if parts[1] == "enable" {
			result, err = handler.domain.EnableRule(request.Context(), actor, input)
		} else {
			result, err = handler.domain.DisableRule(request.Context(), actor, input)
		}
		writeDomainResponse(response, http.StatusOK, result, err)
		return
	}
	switch request.Method {
	case http.MethodGet:
		if !onlyQuery(request.URL.Query()) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		result, err := handler.domain.GetRule(request.Context(), actor, id)
		writeDomainResponse(response, http.StatusOK, result, err)
	case http.MethodPatch:
		if !onlyQuery(request.URL.Query()) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		metadata, err := writeMetadataFromHeaders(request)
		revision, revisionErr := expectedRevision(request.Header.Get("If-Match"))
		if err != nil || revisionErr != nil {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		var fields RuleFields
		if err := decodeJSONBody(request, &fields); err != nil {
			writeHTTPError(response, err)
			return
		}
		result, err := handler.domain.UpdateRule(request.Context(), actor, UpdateRuleRequest{
			RuleID: id, ExpectedRevision: revision, Fields: fields, WriteMetadata: metadata,
		})
		writeDomainResponse(response, http.StatusOK, result, err)
	case http.MethodDelete:
		if !onlyQuery(request.URL.Query()) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		metadata, err := writeMetadataFromHeaders(request)
		revision, revisionErr := expectedRevision(request.Header.Get("If-Match"))
		if err != nil || revisionErr != nil || !emptyBody(request) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		result, err := handler.domain.DeleteRule(request.Context(), actor, ChangeRuleStateRequest{
			RuleID: id, ExpectedRevision: revision, WriteMetadata: metadata,
		})
		writeDomainResponse(response, http.StatusAccepted, result, err)
	default:
		writeHTTPError(response, errMethodNotAllowed)
	}
}

func writeMetadataFromHeaders(request *http.Request) (WriteMetadata, error) {
	metadata := WriteMetadata{
		IdempotencyKey: request.Header.Get("Idempotency-Key"),
		RequestID:      request.Header.Get("X-Request-ID"),
		TraceID:        request.Header.Get("X-Trace-ID"),
	}
	if err := validateWriteMetadata(metadata); err != nil {
		return WriteMetadata{}, err
	}
	return metadata, nil
}

func decodeJSONBody(request *http.Request, target any) error {
	if request.Header.Get("Content-Type") != "application/json" || request.ContentLength > maxJSONBody {
		return ErrInvalidInput
	}
	reader := &io.LimitedReader{R: request.Body, N: maxJSONBody + 1}
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || reader.N <= 0 {
		return ErrInvalidInput
	}
	return nil
}

func writeDomainResponse(response http.ResponseWriter, status int, value any, err error) {
	if err != nil {
		writeHTTPError(response, normalizeServiceError(err))
		return
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxResponseBody {
		writeHTTPError(response, ErrUnavailable)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

var errMethodNotAllowed = errors.New("method not allowed")

func writeHTTPError(response http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "service_unavailable"
	switch {
	case errors.Is(err, ErrInvalidInput):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, ErrInvalidCredential), errors.Is(err, ErrUnauthenticated):
		status, code = http.StatusUnauthorized, "authentication_required"
	case errors.Is(err, ErrPermissionDenied):
		status, code = http.StatusForbidden, "permission_denied"
	case errors.Is(err, ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, ErrConflict), errors.Is(err, ErrIdempotencyConflict):
		status, code = http.StatusConflict, "conflict"
	case errors.Is(err, ErrRevisionConflict):
		status, code = http.StatusPreconditionFailed, "revision_conflict"
	case errors.Is(err, ErrQuotaExceeded), errors.Is(err, ErrEntitlementDenied):
		status, code = http.StatusUnprocessableEntity, "quota_exceeded"
	case errors.Is(err, ErrUnsafeContent):
		status, code = http.StatusUnprocessableEntity, "unsafe_content"
	case errors.Is(err, ErrScanRejected):
		status, code = http.StatusUnprocessableEntity, "scan_rejected"
	case errors.Is(err, errMethodNotAllowed):
		status, code = http.StatusMethodNotAllowed, "method_not_allowed"
	}
	requestID := response.Header().Get("X-Request-ID")
	if !writeMetadataPattern.MatchString(requestID) {
		requestID = uuid.NewString()
		response.Header().Set("X-Request-ID", requestID)
	}
	encoded, _ := json.Marshal(map[string]any{"error": map[string]any{
		"code": code, "params": map[string]any{}, "request_id": requestID,
	}})
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func setResponseHeaders(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Disposition", "attachment")
	response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
	response.Header().Set("X-Content-Type-Options", "nosniff")
}

func strictUUID(value string) (uuid.UUID, error) {
	if len(value) != 36 || value != strings.ToLower(value) {
		return uuid.Nil, ErrInvalidInput
	}
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, ErrInvalidInput
	}
	return parsed, nil
}

func optionalUUID(value string) (uuid.UUID, error) {
	if value == "" {
		return uuid.Nil, nil
	}
	return strictUUID(value)
}

func optionalUUIDPointer(value string) (*uuid.UUID, error) {
	parsed, err := optionalUUID(value)
	if err != nil || parsed == uuid.Nil {
		return nil, err
	}
	return &parsed, nil
}

func expectedRevision(value string) (int64, error) {
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, ErrInvalidInput
	}
	revision, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != value[1:len(value)-1] {
		return 0, ErrInvalidInput
	}
	return revision, nil
}

func optionalBool(value string) (*bool, error) {
	if value == "" {
		return nil, nil
	}
	if value != "true" && value != "false" {
		return nil, ErrInvalidInput
	}
	parsed := value == "true"
	return &parsed, nil
}

func queryLimit(value string) (int, error) {
	if value == "" {
		return 50, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 || parsed > MaxPageSize || strconv.Itoa(parsed) != value {
		return 0, ErrInvalidInput
	}
	return parsed, nil
}

func onlyQuery(query url.Values, allowed ...string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		set[key] = struct{}{}
	}
	for key, values := range query {
		if _, found := set[key]; !found || len(values) != 1 {
			return false
		}
	}
	return true
}

func emptyBody(request *http.Request) bool {
	if request.ContentLength > 0 {
		return false
	}
	buffer := make([]byte, 1)
	read, err := request.Body.Read(buffer)
	return read == 0 && errors.Is(err, io.EOF)
}

func validHost(host string) bool {
	return host != "" && len(host) <= 255 && strings.TrimSpace(host) == host &&
		strings.IndexFunc(host, unicode.IsControl) < 0
}

func writeMethodOrInput(response http.ResponseWriter, validMethod bool) {
	if validMethod {
		writeHTTPError(response, ErrInvalidInput)
	} else {
		writeHTTPError(response, errMethodNotAllowed)
	}
}
