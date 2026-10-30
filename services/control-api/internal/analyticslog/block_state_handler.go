package analyticslog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type blockStateRoute struct {
	audience Audience
	kind     string
	blockID  uuid.UUID
}

type BlockStateHandler struct {
	service      *BlockStateService
	pool         *pgxpool.Pool
	authenticate AuthenticatePrincipalFunc
	authorizer   Authorizer
	errors       *Handler
	timeout      time.Duration
}

type blockUnlockRequest struct {
	ReasonCode string `json:"reason_code"`
}

func NewBlockStateHandler(service *BlockStateService, pool *pgxpool.Pool,
	authenticate AuthenticatePrincipalFunc, authorizer Authorizer, errorsHandler *Handler,
	timeout time.Duration,
) (*BlockStateHandler, error) {
	if service == nil || !configuredPGXPool(pool) || authenticate == nil || nilInterface(authorizer) ||
		errorsHandler == nil || timeout <= 0 || timeout > 30*time.Second {
		return nil, ErrInvalidConfiguration
	}
	return &BlockStateHandler{
		service: service, pool: pool, authenticate: authenticate, authorizer: authorizer,
		errors: errorsHandler, timeout: timeout,
	}, nil
}

func (handler *BlockStateHandler) Owns(path string) bool {
	_, ok := resolveBlockStateRoute(path)
	return ok
}

func (handler *BlockStateHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	request = requestWithID(request)
	writer.Header().Set("X-Request-ID", RequestIDFromContext(request.Context()))
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	route, ok := resolveBlockStateRoute(request.URL.Path)
	if !ok {
		handler.writeError(writer, request, ErrBlockStateNotFound)
		return
	}
	wantMethod := http.MethodGet
	if route.kind == "unlock" {
		wantMethod = http.MethodPost
	}
	if request.Method != wantMethod {
		writer.Header().Set("Allow", wantMethod)
		handler.errors.writeError(writer, request, http.StatusMethodNotAllowed,
			"analytics_logs_method_not_allowed", "method is not allowed")
		return
	}
	if route.kind != "unlock" && getRequestHasBody(request) {
		handler.writeError(writer, request, ErrInvalidInput)
		return
	}
	query, targetTenantID, err := parseBlockStateQuery(request, route.audience, route.kind)
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	request = request.WithContext(ctx)
	principal, err := handler.authenticate(request)
	if err != nil {
		if errors.Is(err, errAuthenticationRequired) {
			handler.errors.writeError(writer, request, http.StatusUnauthorized,
				"analytics_logs_authentication_required", "authentication is required")
			return
		}
		handler.writeError(writer, request, err)
		return
	}
	if route.audience == AudiencePlatform && principal.credentialKind == credentialAPIKey {
		handler.errors.writeError(writer, request, http.StatusUnauthorized,
			"analytics_logs_authentication_required", "authentication is required")
		return
	}
	var actor Actor
	principal, actor, err = scopedPrincipal(principal, route.audience, targetTenantID)
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	if route.audience == AudienceTenant {
		targetTenantID = actor.TenantID
	}
	permission := ReadPermission
	if route.kind == "unlock" {
		permission = blockManagePermission
	}
	authorization := AuthorizationRequest{
		Permission: permission, Audience: route.audience, TenantID: targetTenantID,
	}
	if query.SiteID != nil {
		authorization.SiteID = query.SiteID.String()
	}
	if err := handler.authorizer.AuthorizeAnalyticsLogRead(ctx, principal, authorization); err != nil {
		handler.writeError(writer, request, err)
		return
	}
	targetScopeID, err := handler.targetScope(ctx, principal, route.audience, targetTenantID)
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	switch route.kind {
	case "current":
		page, err := handler.service.ListCurrent(ctx, targetScopeID, query)
		if err != nil {
			handler.writeError(writer, request, err)
			return
		}
		handler.writeJSON(writer, request, http.StatusOK, page)
	case "history":
		page, err := handler.service.ListHistory(ctx, targetScopeID, query)
		if err != nil {
			handler.writeError(writer, request, err)
			return
		}
		handler.writeJSON(writer, request, http.StatusOK, page)
	case "current-count":
		page, err := handler.service.CountCurrent(ctx, targetScopeID)
		if err != nil {
			handler.writeError(writer, request, err)
			return
		}
		handler.writeJSON(writer, request, http.StatusOK, page)
	case "unlock":
		key, err := exactHeader(request, "Idempotency-Key")
		if err != nil {
			handler.writeError(writer, request, ErrInvalidInput)
			return
		}
		var body blockUnlockRequest
		if err := decodeBlockUnlockRequest(request, &body); err != nil {
			handler.writeError(writer, request, ErrInvalidInput)
			return
		}
		userID, userErr := uuid.Parse(principal.ID)
		actorScopeID, scopeErr := uuid.Parse(principal.ScopeID)
		if userErr != nil || scopeErr != nil {
			handler.writeError(writer, request, ErrScopeForbidden)
			return
		}
		result, err := handler.service.Unlock(ctx, BlockActor{
			UserID: userID, ActorScopeID: actorScopeID, TargetScopeID: targetScopeID,
			ScopeKind: principal.ScopeKind,
		}, route.blockID, body.ReasonCode, key, RequestIDFromContext(ctx))
		if err != nil {
			handler.writeError(writer, request, err)
			return
		}
		if result.Replayed {
			writer.Header().Set("Idempotency-Replayed", "true")
		}
		handler.writeJSON(writer, request, http.StatusAccepted, result)
	}
}

func resolveBlockStateRoute(path string) (blockStateRoute, bool) {
	for _, prefix := range []struct {
		value    string
		audience Audience
	}{{"/v1/admin/analytics/logs/blocks/", AudiencePlatform}, {"/v1/analytics/logs/blocks/", AudienceTenant}} {
		if !strings.HasPrefix(path, prefix.value) {
			continue
		}
		suffix := strings.TrimPrefix(path, prefix.value)
		if suffix == "current" || suffix == "history" || suffix == "current-count" {
			return blockStateRoute{audience: prefix.audience, kind: suffix}, true
		}
		parts := strings.Split(suffix, "/")
		if len(parts) == 3 && parts[0] == "current" && parts[2] == "unlock" {
			id, err := uuid.Parse(parts[1])
			if err == nil && id != uuid.Nil && id.String() == parts[1] {
				return blockStateRoute{audience: prefix.audience, kind: "unlock", blockID: id}, true
			}
		}
	}
	return blockStateRoute{}, false
}

func parseBlockStateQuery(request *http.Request, audience Audience, kind string) (BlockListRequest, string, error) {
	parsed, err := parseRawQuery(request)
	if err != nil {
		return BlockListRequest{}, "", ErrInvalidInput
	}
	allowed := map[string]bool{}
	if kind != "unlock" {
		allowed["site_id"] = true
		allowed["policy_id"] = true
		allowed["cidr"] = true
		allowed["limit"] = true
		allowed["offset"] = true
	}
	if kind == "history" {
		allowed["start"] = true
		allowed["end"] = true
	}
	if audience == AudiencePlatform {
		allowed["tenant_id"] = true
	}
	for key, values := range parsed {
		if !allowed[key] || len(values) != 1 || values[0] == "" {
			return BlockListRequest{}, "", ErrInvalidInput
		}
	}
	tenantID := ""
	if audience == AudiencePlatform {
		tenantID = strings.ToLower(request.URL.Query().Get("tenant_id"))
		if tenantID != "" && !validUUID(tenantID) || kind == "unlock" && tenantID == "" {
			return BlockListRequest{}, "", ErrInvalidInput
		}
	}
	if kind == "unlock" || kind == "current-count" {
		return BlockListRequest{Limit: DefaultLimit}, tenantID, nil
	}
	result := BlockListRequest{Limit: DefaultLimit}
	if raw := request.URL.Query().Get("site_id"); raw != "" {
		id, parseErr := uuid.Parse(raw)
		if parseErr != nil || id == uuid.Nil || id.String() != raw {
			return BlockListRequest{}, "", ErrInvalidInput
		}
		result.SiteID = &id
	}
	if raw := request.URL.Query().Get("policy_id"); raw != "" {
		id, parseErr := uuid.Parse(raw)
		if parseErr != nil || id == uuid.Nil || id.String() != raw {
			return BlockListRequest{}, "", ErrInvalidInput
		}
		result.PolicyID = &id
	}
	if raw := request.URL.Query().Get("cidr"); raw != "" {
		if !validBlockCIDR(raw) {
			return BlockListRequest{}, "", ErrInvalidInput
		}
		result.CIDR = raw
	}
	if raw := request.URL.Query().Get("limit"); raw != "" {
		value, parseErr := strconv.ParseUint(raw, 10, 16)
		if parseErr != nil || value < 1 || value > uint64(MaxLimit) {
			return BlockListRequest{}, "", ErrInvalidInput
		}
		result.Limit = uint16(value)
	}
	if raw := request.URL.Query().Get("offset"); raw != "" {
		value, parseErr := strconv.ParseUint(raw, 10, 32)
		if parseErr != nil || value > uint64(MaxBlockOffset) {
			return BlockListRequest{}, "", ErrInvalidInput
		}
		result.Offset = uint32(value)
	}
	if kind == "history" {
		if raw := request.URL.Query().Get("start"); raw != "" {
			value, parseErr := strconv.ParseInt(raw, 10, 64)
			if parseErr != nil || value < 0 {
				return BlockListRequest{}, "", ErrInvalidInput
			}
			from := time.Unix(value, 0).UTC()
			result.OccurredFrom = &from
		}
		if raw := request.URL.Query().Get("end"); raw != "" {
			value, parseErr := strconv.ParseInt(raw, 10, 64)
			if parseErr != nil || value < 0 {
				return BlockListRequest{}, "", ErrInvalidInput
			}
			to := time.Unix(value, 0).UTC()
			result.OccurredTo = &to
		}
	}
	return result, tenantID, nil
}

func (handler *BlockStateHandler) targetScope(ctx context.Context, principal Principal,
	audience Audience, tenantID string,
) (uuid.UUID, error) {
	if audience == AudienceTenant {
		id, err := uuid.Parse(principal.ScopeID)
		if err != nil || id == uuid.Nil {
			return uuid.Nil, ErrScopeForbidden
		}
		return id, nil
	}
	if tenantID == "" {
		return uuid.Nil, nil
	}
	tenant, err := uuid.Parse(tenantID)
	if err != nil || tenant == uuid.Nil {
		return uuid.Nil, ErrInvalidInput
	}
	var scopeID uuid.UUID
	err = handler.pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='tenant' AND tenant_id=$1`, tenant).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrScopeForbidden
	}
	if err != nil || scopeID == uuid.Nil {
		return uuid.Nil, ErrStorageUnavailable
	}
	return scopeID, nil
}

func (handler *BlockStateHandler) writeJSON(writer http.ResponseWriter, request *http.Request,
	status int, value any,
) {
	encoded, err := json.Marshal(value)
	if err != nil {
		handler.writeError(writer, request, ErrStorageUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}

func (handler *BlockStateHandler) writeError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		handler.errors.writeError(writer, request, http.StatusGatewayTimeout, "analytics_logs_timeout", "request timed out")
	case errors.Is(err, ErrInvalidInput):
		handler.errors.writeError(writer, request, http.StatusBadRequest, "analytics_logs_invalid_request", "request is invalid")
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrScopeForbidden):
		handler.errors.writeError(writer, request, http.StatusForbidden, "analytics_logs_permission_denied", "permission is denied")
	case errors.Is(err, ErrBlockStateNotFound):
		handler.errors.writeError(writer, request, http.StatusNotFound, "analytics_block_not_found", "block state was not found")
	case errors.Is(err, ErrBlockStateConflict):
		handler.errors.writeError(writer, request, http.StatusConflict, "analytics_block_unlock_conflict", "block state changed")
	default:
		handler.errors.writeError(writer, request, http.StatusServiceUnavailable, "analytics_logs_storage_unavailable", "analytics log storage is unavailable")
	}
}

func exactHeader(request *http.Request, name string) (string, error) {
	values := request.Header.Values(name)
	if len(values) != 1 || !blockWriteKeyPattern.MatchString(values[0]) {
		return "", ErrInvalidInput
	}
	return values[0], nil
}

func decodeBlockUnlockRequest(request *http.Request, target *blockUnlockRequest) error {
	encoded, err := io.ReadAll(io.LimitReader(request.Body, 4097))
	if err != nil || len(encoded) > 4096 {
		return ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF || target.ReasonCode == "" {
		return ErrInvalidInput
	}
	return nil
}

var _ blockPolicyUpdater = (*securitypolicy.Service)(nil)
