package plugininstallation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	ScopeTenant      = "tenant"
	ScopePlatform    = "platform"
	PermissionRead   = "plugin_installations.read"
	PermissionManage = "plugin_installations.manage"
	// Platform plugin installations (themes, rule data packs): exact permissions of the controller's
	// platform administrators, never derived from platform.admin or tenant permissions.
	PermissionPlatformRead   = "plugin_installations.platform.read"
	PermissionPlatformManage = "plugin_installations.platform.manage"
)

var (
	ErrResultUnknown = errors.New("plugin installation mutation result unknown")
	pluginFilter     = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)
)

type Actor struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	// TenantID is the local access scope holding the installation heads: a tenant scope, or the controller's
	// platform scope for instance-wide plugins.
	TenantID uuid.UUID
	// ScopeKind is the kind of that access scope (ResourceScopeTenant or ResourceScopePlatform); only plugins
	// of the same signed resource scope are visible and confirmable there. Empty means tenant.
	ScopeKind string
	RequestID string
	// Username names the controller administrator to the license service when it confirms a market
	// authorization (license migration 076).
	Username string
}

type ListRequest struct {
	TenantID uuid.UUID
	Limit    int
	Cursor   string
	Status   string
	PluginID string
}

type MutationRequest struct {
	TenantID                      uuid.UUID
	AuthorizationID               uuid.UUID
	Action                        string
	ExpectedRevision              uint64
	IdempotencyKey                string
	RequestID                     string
	VerificationID                uuid.UUID
	ApprovedScopes                []string
	SensitivePermissionsConfirmed bool
	NewPermissionsConfirmed       bool
	Reason                        string
}

type InstallationView struct {
	Installation Installation
	NewScopes    []string
	// AuthorizationStatus is the platform authorization state reported by the license service
	// (authorized/enabled/disabled). Empty when the license service was not consulted. A locally enabled
	// plugin whose authorization is disabled is paused by the platform: runtime projections are denied.
	AuthorizationStatus string
	// PausedBy/PausedReason say who stopped a disabled authorization on the platform (license paused_by):
	// installation is this controller's own pause; operator/service is a platform pause it cannot resume.
	PausedBy     string
	PausedReason string
	// AvailableUpgrade is a newer version the platform has already authorized for this installation.
	AvailableUpgrade *AvailableUpgrade
}

type AvailableUpgrade struct {
	VerificationID  uuid.UUID
	Version         string
	ManifestScopes  []string
	ApprovedScopes  []string
	SensitiveScopes []string
	NewScopes       []string
}

type Page struct {
	Items      []InstallationView
	NextCursor string
}

type Domain interface {
	List(context.Context, Actor, ListRequest) (Page, error)
	Get(context.Context, Actor, uuid.UUID) (InstallationView, error)
	Mutate(context.Context, Actor, MutationRequest) (InstallationView, error)
}

type HandlerDependencies struct {
	AuthenticateSession func(context.Context, string) (identity.AuthenticatedSession, error)
	Domain              Domain
}

type Handler struct {
	authenticate func(context.Context, string) (identity.AuthenticatedSession, error)
	domain       Domain
}

func NewHandler(dependencies HandlerDependencies) (*Handler, error) {
	if dependencies.AuthenticateSession == nil || dependencies.Domain == nil {
		return nil, ErrInvalidInput
	}
	return &Handler{authenticate: dependencies.AuthenticateSession, domain: dependencies.Domain}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.authenticate == nil || handler.domain == nil || request == nil {
		writePluginInstallationError(response, http.StatusInternalServerError, "internal_error")
		return
	}
	session, err := handler.authenticateRequest(request)
	if err != nil {
		writePluginInstallationError(response, http.StatusUnauthorized, "authentication_required")
		return
	}
	route, err := parsePluginInstallationRoute(request)
	if err != nil {
		writePluginInstallationError(response, http.StatusNotFound, "not_found")
		return
	}
	permission := PermissionRead
	if route.action != "" {
		permission = PermissionManage
	}
	scopeKind := ScopeTenant
	if route.platform {
		// /v1/platform/plugin-installations: the platform scope of this controller only.
		if session.Principal.ScopeKind != ScopePlatform || session.Principal.TenantID != nil ||
			session.Principal.ScopeID == uuid.Nil {
			writePluginInstallationError(response, http.StatusForbidden, "permission_denied")
			return
		}
		route.tenantID, scopeKind = session.Principal.ScopeID, ScopePlatform
		permission = map[string]string{PermissionRead: PermissionPlatformRead, PermissionManage: PermissionPlatformManage}[permission]
	} else if session.Principal.ScopeKind != ScopeTenant || session.Principal.TenantID == nil ||
		*session.Principal.TenantID != route.tenantID || session.Principal.ScopeID != route.tenantID {
		writePluginInstallationError(response, http.StatusForbidden, "permission_denied")
		return
	}
	if !hasExactPermission(session.Principal.Permissions, permission) {
		writePluginInstallationError(response, http.StatusForbidden, "permission_denied")
		return
	}
	requestID, err := exactPluginHeader(request, "X-Request-ID", true)
	if err != nil || !validRequestID(requestID) {
		writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	actor := Actor{UserID: session.Principal.UserID, SessionID: session.SessionID,
		TenantID: route.tenantID, ScopeKind: scopeKind, RequestID: requestID, Username: session.Principal.Username}
	switch {
	case request.Method == http.MethodGet && route.authorizationID == uuid.Nil:
		handler.list(response, request, actor, route.tenantID)
	case request.Method == http.MethodGet && route.action == "":
		handler.get(response, request, actor, route.authorizationID)
	case request.Method == http.MethodPost && route.action != "":
		handler.mutate(response, request, actor, route)
	default:
		writePluginInstallationError(response, http.StatusNotFound, "not_found")
	}
}

// resourceScope is the resource scope this actor manages.
func (actor Actor) resourceScope() string {
	if actor.ScopeKind == ResourceScopePlatform {
		return ResourceScopePlatform
	}
	return ResourceScopeTenant
}

func (handler *Handler) authenticateRequest(request *http.Request) (identity.AuthenticatedSession, error) {
	value, err := exactPluginHeader(request, "Authorization", true)
	if err != nil || !strings.HasPrefix(value, "Bearer ") || len(value) <= len("Bearer ") ||
		strings.TrimSpace(value) != value || strings.Contains(value[len("Bearer "):], " ") {
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	}
	return handler.authenticate(request.Context(), value[len("Bearer "):])
}

func (handler *Handler) list(response http.ResponseWriter, request *http.Request, actor Actor, tenantID uuid.UUID) {
	query := request.URL.Query()
	for key, values := range query {
		if len(values) != 1 || (key != "limit" && key != "cursor" && key != "status" && key != "plugin_id") {
			writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	input := ListRequest{TenantID: tenantID, Limit: 50, Cursor: query.Get("cursor"),
		Status: query.Get("status"), PluginID: query.Get("plugin_id")}
	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != raw {
			writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		input.Limit = limit
	}
	if !validCursor(input.Cursor) || !validStatusFilter(input.Status) ||
		(input.PluginID != "" && !pluginFilter.MatchString(input.PluginID)) {
		writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	page, err := handler.domain.List(request.Context(), actor, input)
	if err != nil {
		writePluginInstallationDomainError(response, err, false)
		return
	}
	wire := installationPageWire{Items: make([]installationWire, len(page.Items)), NextCursor: page.NextCursor}
	for index, item := range page.Items {
		wire.Items[index] = installationToWire(item)
	}
	writePluginInstallationJSON(response, http.StatusOK, wire)
}

func (handler *Handler) get(response http.ResponseWriter, request *http.Request, actor Actor,
	authorizationID uuid.UUID) {
	if request.URL.RawQuery != "" {
		writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := handler.domain.Get(request.Context(), actor, authorizationID)
	if err != nil {
		writePluginInstallationDomainError(response, err, false)
		return
	}
	response.Header().Set("ETag", fmt.Sprintf(`"%d"`, result.Installation.Revision))
	writePluginInstallationJSON(response, http.StatusOK, installationToWire(result))
}

func (handler *Handler) mutate(response http.ResponseWriter, request *http.Request, actor Actor,
	route pluginInstallationRoute) {
	if request.URL.RawQuery != "" {
		writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	revision, err := pluginExpectedRevision(request)
	if err != nil {
		writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	idempotencyKey, err := exactPluginHeader(request, "Idempotency-Key", true)
	if err != nil || !idempotencyPattern.MatchString(idempotencyKey) {
		writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, 64<<10+1))
	if err != nil || len(raw) > 64<<10 {
		writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	input := MutationRequest{TenantID: route.tenantID, AuthorizationID: route.authorizationID,
		Action: route.action, ExpectedRevision: revision, IdempotencyKey: idempotencyKey,
		RequestID: actor.RequestID}
	switch route.action {
	case ActionConfirm, ActionUpgrade:
		var body struct {
			VerificationID                uuid.UUID `json:"verification_id"`
			ApprovedScopes                []string  `json:"approved_scopes"`
			SensitivePermissionsConfirmed bool      `json:"sensitive_permissions_confirmed"`
			NewPermissionsConfirmed       bool      `json:"new_permissions_confirmed"`
		}
		if strictJSON(raw, &body) != nil || body.VerificationID == uuid.Nil || body.ApprovedScopes == nil ||
			!validScopes(body.ApprovedScopes) {
			writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		input.VerificationID = body.VerificationID
		input.ApprovedScopes = append([]string{}, body.ApprovedScopes...)
		input.SensitivePermissionsConfirmed = body.SensitivePermissionsConfirmed
		input.NewPermissionsConfirmed = body.NewPermissionsConfirmed
	case ActionDisable, ActionUninstall:
		var body struct {
			Reason string `json:"reason"`
		}
		if strictJSON(raw, &body) != nil || !validReason(body.Reason) {
			writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		input.Reason = body.Reason
	case ActionResume:
		// Resume carries no approval and no reason: it restores exactly the authorization this controller paused.
		var body struct{}
		if strictJSON(raw, &body) != nil {
			writePluginInstallationError(response, http.StatusBadRequest, "invalid_request")
			return
		}
	default:
		writePluginInstallationError(response, http.StatusNotFound, "not_found")
		return
	}
	result, err := handler.domain.Mutate(request.Context(), actor, input)
	if err != nil {
		writePluginInstallationDomainError(response, err, true)
		return
	}
	response.Header().Set("ETag", fmt.Sprintf(`"%d"`, result.Installation.Revision))
	writePluginInstallationJSON(response, http.StatusOK,
		struct {
			Installation installationWire `json:"installation"`
		}{Installation: installationToWire(result)})
}

type pluginInstallationRoute struct {
	platform        bool
	tenantID        uuid.UUID
	authorizationID uuid.UUID
	action          string
}

func parsePluginInstallationRoute(request *http.Request) (pluginInstallationRoute, error) {
	const prefix, platformPrefix = "/v1/tenant-scopes/", "/v1/platform/"
	if request.URL.RawPath != "" {
		return pluginInstallationRoute{}, ErrInvalidInput
	}
	var route pluginInstallationRoute
	var parts []string
	switch {
	case strings.HasPrefix(request.URL.Path, platformPrefix):
		// /v1/platform/plugin-installations[/{authorization_id}[/{action}]]; the scope comes from the session.
		parts = strings.Split(strings.TrimPrefix(request.URL.Path, platformPrefix), "/")
		parts = append([]string{""}, parts...)
		route.platform = true
	case strings.HasPrefix(request.URL.Path, prefix):
		parts = strings.Split(strings.TrimPrefix(request.URL.Path, prefix), "/")
	default:
		return pluginInstallationRoute{}, ErrInvalidInput
	}
	if len(parts) < 2 || len(parts) > 4 || parts[1] != "plugin-installations" {
		return pluginInstallationRoute{}, ErrInvalidInput
	}
	var err error
	if !route.platform {
		if route.tenantID, err = canonicalPluginUUID(parts[0]); err != nil {
			return pluginInstallationRoute{}, err
		}
	}
	if len(parts) >= 3 {
		route.authorizationID, err = canonicalPluginUUID(parts[2])
		if err != nil {
			return pluginInstallationRoute{}, err
		}
	}
	if len(parts) == 4 {
		route.action = parts[3]
		if route.action != ActionConfirm && route.action != ActionUpgrade &&
			route.action != ActionDisable && route.action != ActionUninstall && route.action != ActionResume {
			return pluginInstallationRoute{}, ErrInvalidInput
		}
	}
	return route, nil
}

func canonicalPluginUUID(raw string) (uuid.UUID, error) {
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return uuid.Nil, ErrInvalidInput
	}
	return value, nil
}

func exactPluginHeader(request *http.Request, name string, required bool) (string, error) {
	values, found := request.Header[http.CanonicalHeaderKey(name)]
	if !found {
		if required {
			return "", ErrInvalidInput
		}
		return "", nil
	}
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
		return "", ErrInvalidInput
	}
	return values[0], nil
}

func pluginExpectedRevision(request *http.Request) (uint64, error) {
	value, err := exactPluginHeader(request, "If-Match", true)
	if err != nil || len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, ErrInvalidInput
	}
	raw := value[1 : len(value)-1]
	revision, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || revision == 0 || strconv.FormatUint(revision, 10) != raw {
		return 0, ErrInvalidInput
	}
	return revision, nil
}

func hasExactPermission(permissions []string, required string) bool {
	for _, permission := range permissions {
		if permission == required {
			return true
		}
	}
	return false
}

func validCursor(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 1024 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func validStatusFilter(value string) bool {
	switch value {
	case "", "pending_confirmation", "authorized", "installing", StatusEnabled, StatusDisabled,
		"upgrade_failed_lkg_preserved", StatusUninstalled:
		return true
	default:
		return false
	}
}

type installationWire struct {
	Schema                    string       `json:"schema"`
	TenantID                  uuid.UUID    `json:"tenant_scope_id"`
	AuthorizationID           uuid.UUID    `json:"authorization_id"`
	InstallationID            uuid.UUID    `json:"installation_id"`
	VerificationID            uuid.UUID    `json:"verification_id"`
	PluginID                  string       `json:"plugin_id"`
	Version                   string       `json:"version"`
	ManifestSHA256            string       `json:"manifest_sha256"`
	ConfigurationSchemaSHA256 string       `json:"configuration_schema_sha256"`
	ManifestScopes            []string     `json:"manifest_scopes"`
	ApprovedScopes            []string     `json:"approved_scopes"`
	SensitiveScopes           []string     `json:"sensitive_scopes"`
	NewScopes                 []string     `json:"new_scopes"`
	ResourceScope             string       `json:"resource_scope"`
	EntrypointType            string       `json:"entrypoint_type"`
	Status                    string       `json:"status"`
	Revision                  uint64       `json:"revision"`
	IdentityGeneration        uint64       `json:"identity_generation"`
	LKGVerificationID         *uuid.UUID   `json:"lkg_verification_id"`
	LKGVersion                *string      `json:"lkg_version"`
	StableReasonCode          *string      `json:"stable_reason_code"`
	UpdatedAt                 string       `json:"updated_at"`
	AuthorizationStatus       string       `json:"authorization_status,omitempty"`
	PausedBy                  string       `json:"paused_by,omitempty"`
	PausedReason              string       `json:"paused_reason,omitempty"`
	AvailableUpgrade          *upgradeWire `json:"available_upgrade,omitempty"`
}

type upgradeWire struct {
	VerificationID  uuid.UUID `json:"verification_id"`
	Version         string    `json:"version"`
	ManifestScopes  []string  `json:"manifest_scopes"`
	ApprovedScopes  []string  `json:"approved_scopes"`
	SensitiveScopes []string  `json:"sensitive_scopes"`
	NewScopes       []string  `json:"new_scopes"`
}

type installationPageWire struct {
	Items      []installationWire `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

func installationToWire(view InstallationView) installationWire {
	value := view.Installation
	wire := installationWire{Schema: value.Schema, TenantID: value.TenantID,
		AuthorizationID: value.AuthorizationID, InstallationID: value.InstallationID,
		VerificationID: value.VerificationID, PluginID: value.PluginID, Version: value.Version,
		ManifestSHA256: value.ManifestSHA256, ConfigurationSchemaSHA256: value.ConfigurationSchemaSHA256,
		ManifestScopes: append([]string{}, value.ManifestScopes...), ApprovedScopes: append([]string{}, value.ApprovedScopes...),
		SensitiveScopes: append([]string{}, value.SensitiveScopes...), NewScopes: append([]string{}, view.NewScopes...),
		ResourceScope: value.ResourceScope, EntrypointType: value.EntrypointType, Status: value.Status, Revision: value.Revision,
		IdentityGeneration: value.IdentityGeneration,
		UpdatedAt:          value.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z")}
	if value.LKGVerificationID != uuid.Nil {
		wire.LKGVerificationID = &value.LKGVerificationID
	}
	if value.LKGVersion != "" {
		wire.LKGVersion = &value.LKGVersion
	}
	if value.StableReasonCode != "" {
		wire.StableReasonCode = &value.StableReasonCode
	}
	wire.AuthorizationStatus = view.AuthorizationStatus
	wire.PausedBy, wire.PausedReason = view.PausedBy, view.PausedReason
	if upgrade := view.AvailableUpgrade; upgrade != nil {
		wire.AvailableUpgrade = &upgradeWire{VerificationID: upgrade.VerificationID, Version: upgrade.Version,
			ManifestScopes:  append([]string{}, upgrade.ManifestScopes...),
			ApprovedScopes:  append([]string{}, upgrade.ApprovedScopes...),
			SensitiveScopes: append([]string{}, upgrade.SensitiveScopes...),
			NewScopes:       append([]string{}, upgrade.NewScopes...)}
	}
	return wire
}

func writePluginInstallationDomainError(response http.ResponseWriter, err error, mutation bool) {
	status, code := http.StatusInternalServerError, "internal_error"
	switch {
	case errors.Is(err, identity.ErrInvalidSession):
		status, code = http.StatusUnauthorized, "authentication_required"
	case errors.Is(err, identity.ErrPermissionDenied):
		status, code = http.StatusForbidden, "permission_denied"
	case errors.Is(err, ErrInvalidInput):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, ErrNotFound):
		status, code = http.StatusNotFound, "plugin_installation_not_found"
	case errors.Is(err, ErrRevisionConflict):
		status, code = http.StatusConflict, "plugin_installation_revision_conflict"
	case errors.Is(err, ErrIdempotencyConflict):
		status, code = http.StatusConflict, "plugin_installation_idempotency_conflict"
	case errors.Is(err, ErrConsentRequired), errors.Is(err, ErrFactRequired), errors.Is(err, ErrFactDenied):
		status, code = http.StatusUnprocessableEntity, "plugin_installation_scope_approval_required"
	case errors.Is(err, ErrPlatformPaused):
		status, code = http.StatusConflict, "plugin_installation_platform_paused"
	case errors.Is(err, ErrFactUnavailable):
		status, code = http.StatusServiceUnavailable, "plugin_installation_license_unavailable"
	case errors.Is(err, ErrTransitionInvalid):
		status, code = http.StatusConflict, "plugin_installation_state_conflict"
	case errors.Is(err, ErrResultUnknown), mutation && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)):
		status, code = http.StatusServiceUnavailable, "plugin_installation_result_unknown"
	}
	writePluginInstallationError(response, status, code)
}

func writePluginInstallationJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writePluginInstallationError(response http.ResponseWriter, status int, code string) {
	writePluginInstallationJSON(response, status, struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}{Error: struct {
		Code string `json:"code"`
	}{Code: code}})
}
