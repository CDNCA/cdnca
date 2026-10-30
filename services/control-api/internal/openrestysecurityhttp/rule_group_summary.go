package openrestysecurityhttp

import (
	"context"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityrulecatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ruleGroupSummaryPath: GET the CC rule group pill counts (全部/系统/
// 自定义/显示/禁用) over every group, not one page.
const ruleGroupSummaryPath = "/v1/cc-rule-groups/summary"

type ruleGroupSummary struct {
	All      int `json:"all"`
	System   int `json:"system"`
	Custom   int `json:"custom"`
	Visible  int `json:"visible"`
	Disabled int `json:"disabled"`
}

// ruleGroupSummary counts system groups from the signed catalog once it has
// synced (its one installation-wide copy replaces the per-tenant projection,
// as the page lists them), else from the projection; custom groups are the
// scope's CC policies.
func (handler *Handler) ruleGroupSummary(ctx context.Context, actor openrestysecurity.Actor, targetScopeID uuid.UUID) (ruleGroupSummary, error) {
	groups, err := handler.api.RuleGroups(ctx, openrestysecurity.RuleGroupsRequest{Actor: actor, TargetScopeID: targetScopeID})
	if err != nil {
		return ruleGroupSummary{}, err
	}
	var summary ruleGroupSummary
	var systemEnabled, customEnabled int
	for _, group := range groups {
		switch {
		case group.Kind == "system" && group.SystemRule:
			summary.System++
			if group.Enabled {
				systemEnabled++
			}
		case group.Kind == "custom":
			summary.Custom++
			if group.Enabled {
				customEnabled++
			}
		}
	}
	if handler.catalog != nil && handler.catalogAuthorizer != nil {
		viewer := securityrulecatalog.Viewer{UserID: actor.UserID, ScopeID: actor.ScopeID, Platform: actor.ScopeKind == openrestysecurity.ScopePlatform}
		rules, err := handler.catalog.List(ctx, viewer, rulecatalog.KindCCRuleGroup, func(ctx context.Context, tx pgx.Tx) error {
			return handler.catalogAuthorizer.AuthorizeRuleGroups(ctx, tx, actor, actor.ScopeID)
		})
		// An unavailable catalog keeps the projection, as the page does.
		if err == nil && len(rules) > 0 {
			summary.System, systemEnabled = len(rules), 0
			for _, rule := range rules {
				if rule.Enabled {
					systemEnabled++
				}
			}
		}
	}
	summary.All = summary.System + summary.Custom
	summary.Visible = systemEnabled + customEnabled
	summary.Disabled = summary.All - summary.Visible
	return summary, nil
}
