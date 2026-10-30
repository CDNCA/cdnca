package openrestysecurityhttp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityrulecatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// System rule catalog routes (delivered by the license service):
//
//	GET  /v1/security-system-rules?kind=cc_rule_group|cc_matcher|cc_filter|waf_rule_set
//	GET  /v1/security-system-rules/status                      (platform)
//	GET  /v1/security-system-rules/republication               (CRS rule text change being republished)
//	GET  /v1/security-system-rules/default-crawlers            (default CC trusted crawlers with official ranges)
//	POST /v1/security-system-rules/{system_key}/enable|disable (tenant: per-tenant switch)
//	PUT  /v1/security-system-rules/{system_key}/visibility     (platform: is_show/show_to overlay)
const systemRulesPrefix = "/v1/security-system-rules"

type SystemRuleCatalog interface {
	List(context.Context, securityrulecatalog.Viewer, string, securityrulecatalog.Authorize) ([]securityrulecatalog.Rule, error)
	SetTenantEnabled(context.Context, securityrulecatalog.Viewer, string, bool, securityrulecatalog.Authorize) (securityrulecatalog.Rule, error)
	SetVisibility(context.Context, securityrulecatalog.Viewer, string, bool, []uuid.UUID, securityrulecatalog.Authorize) (securityrulecatalog.Rule, error)
	Status(context.Context, securityrulecatalog.Authorize) (securityrulecatalog.Status, error)
	Republication(context.Context, securityrulecatalog.Viewer, securityrulecatalog.Authorize) (securityrulecatalog.Republication, error)
	DefaultCrawlers(context.Context, securityrulecatalog.Authorize) ([]securityrulecatalog.DefaultCrawler, error)
}

type ruleGroupTxAuthorizer interface {
	openrestysecurity.TxAuthorizer
	AuthorizeRuleGroups(context.Context, pgx.Tx, openrestysecurity.Actor, uuid.UUID) error
}

// IsSystemRulePath reports whether the composed router must send path here.
func IsSystemRulePath(path string) bool {
	return path == systemRulesPrefix || strings.HasPrefix(path, systemRulesPrefix+"/")
}

func (handler *Handler) serveSystemRules(response http.ResponseWriter, request *http.Request, actor openrestysecurity.Actor) {
	if handler.catalog == nil || handler.catalogAuthorizer == nil {
		writeAPIError(response, http.StatusServiceUnavailable, "security_rule_catalog_unavailable")
		return
	}
	viewer := securityrulecatalog.Viewer{UserID: actor.UserID, ScopeID: actor.ScopeID, Platform: actor.ScopeKind == openrestysecurity.ScopePlatform}
	read := func(ctx context.Context, tx pgx.Tx) error {
		return handler.catalogAuthorizer.AuthorizeRuleGroups(ctx, tx, actor, actor.ScopeID)
	}
	manage := func(ctx context.Context, tx pgx.Tx) error {
		return handler.catalogAuthorizer.Authorize(ctx, tx, actor, actor.ScopeID, openrestysecurity.PermissionManage)
	}
	path := request.URL.Path
	switch {
	case path == systemRulesPrefix && request.Method == http.MethodGet:
		rules, err := handler.catalog.List(request.Context(), viewer, request.URL.Query().Get("kind"), read)
		if err != nil {
			writeSystemRuleError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"items": rules})
	case path == systemRulesPrefix+"/status" && request.Method == http.MethodGet:
		if !viewer.Platform {
			writeError(response, openrestysecurity.ErrPermissionDenied)
			return
		}
		status, err := handler.catalog.Status(request.Context(), read)
		if err != nil {
			writeSystemRuleError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, status)
	case path == systemRulesPrefix+"/republication" && request.Method == http.MethodGet:
		republication, err := handler.catalog.Republication(request.Context(), viewer, read)
		if err != nil {
			writeSystemRuleError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, republication)
	case path == systemRulesPrefix+"/default-crawlers" && request.Method == http.MethodGet:
		crawlers, err := handler.catalog.DefaultCrawlers(request.Context(), read)
		if err != nil {
			writeSystemRuleError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"items": crawlers})
	case request.Method == http.MethodPost && (strings.HasSuffix(path, "/enable") || strings.HasSuffix(path, "/disable")):
		enabled := strings.HasSuffix(path, "/enable")
		key := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(path, systemRulesPrefix+"/"), "/enable"), "/disable")
		if viewer.Platform || key == "" || strings.Contains(key, "/") {
			writeError(response, openrestysecurity.ErrInvalidInput)
			return
		}
		rule, err := handler.catalog.SetTenantEnabled(request.Context(), viewer, key, enabled, read)
		if err != nil {
			writeSystemRuleError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, rule)
	case request.Method == http.MethodPut && strings.HasSuffix(path, "/visibility"):
		key := strings.TrimSuffix(strings.TrimPrefix(path, systemRulesPrefix+"/"), "/visibility")
		var input struct {
			Visible        *bool       `json:"visible"`
			ShowToScopeIDs []uuid.UUID `json:"show_to_scope_ids"`
		}
		if !viewer.Platform || key == "" || strings.Contains(key, "/") || decodeBody(response, request, &input) != nil || input.Visible == nil {
			writeError(response, openrestysecurity.ErrInvalidInput)
			return
		}
		rule, err := handler.catalog.SetVisibility(request.Context(), viewer, key, *input.Visible, input.ShowToScopeIDs, manage)
		if err != nil {
			writeSystemRuleError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, rule)
	default:
		writeAPIError(response, http.StatusNotFound, "not_found")
	}
}

func writeSystemRuleError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, securityrulecatalog.ErrNotFound):
		writeAPIError(response, http.StatusNotFound, "security_system_rule_not_found")
	case errors.Is(err, securityrulecatalog.ErrWithdrawnRule):
		writeAPIError(response, http.StatusConflict, "security_system_rule_withdrawn")
	case errors.Is(err, securityrulecatalog.ErrInvalidInput):
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
	default:
		writeError(response, err)
	}
}
