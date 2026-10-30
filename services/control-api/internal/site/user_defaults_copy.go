package site

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 网站列表 > 默认设置 复制快照：用户在默认设置
// 里选好本人的规则库（CC / WAF / 黑白名单 IP；区域屏蔽、爬虫、内置模块等都是
// 库里的规则）、屏蔽透明代理、区域屏蔽预设、源站请求头与上传限制，建站时在同一事务里复制一份
// 给新站：规则库复制成新站专用的新库并绑定，HTTP 策略新建一条。之后改原库或默认
// 不影响已建站点。复用各模块已有路径：securitypolicy 的校验/版本/审计，
// securitybinding 的首次绑定（发布由激活 worker 的 rebind 带出，同"规则页保存后
// 自动下发"），httppolicycontrol 的修订写入（随站点发布）。

var siteDefaultPolicyKinds = map[string]string{
	SiteDefaultCCPolicy:  securitypolicy.KindCC,
	SiteDefaultWAFPolicy: securitypolicy.KindWAF,
	SiteDefaultACLPolicy: securitypolicy.KindACL,
}

// checkSiteDefaultPolicy: a 规则库 default must name a live library of the
// owner's own of that kind (not a subscribed one), checked when saved.
func checkSiteDefaultPolicy(ctx context.Context, tx pgx.Tx, scopeID, ownerID uuid.UUID, name, value string) error {
	kind, ok := siteDefaultPolicyKinds[name]
	if !ok {
		return nil
	}
	id, err := uuid.Parse(value)
	if err != nil {
		return ErrInvalidInput
	}
	if err := securitypolicy.CheckSiteCopySourceTx(ctx, tx, scopeID, ownerID, id, kind); errors.Is(err, securitypolicy.ErrSiteCopyUnusable) {
		return ErrSiteDefaultPolicy
	} else if err != nil {
		return err
	}
	return nil
}

// ErrSiteDefaultPolicy: the default names no usable rule library of the owner.
var ErrSiteDefaultPolicy = errors.New("site default rule library is not usable")

// copySiteDefaults runs at the end of the site create's tx. A library that
// is gone, or a package that does not include the feature, skips that copy
// (the site is still created, as 默认设置 > DNS API does).
func (defaults siteCreationUserDefaults) copySiteDefaults(ctx context.Context, tx pgx.Tx, actor Actor, request CreateRequest,
	siteID uuid.UUID, now time.Time) error {
	policyActor := securitypolicy.Actor{UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind}
	copied := func(kind string, source *uuid.UUID, extra []securitypolicy.Rule) error {
		if packageDenies(ctx, tx, request.TargetScopeID, siteID, kind, now) {
			return nil
		}
		policy, err := securitypolicy.CopyForSiteTx(ctx, tx, policyActor, securitypolicy.SiteCopyRequest{
			ScopeID: request.TargetScopeID, OwnerID: request.OwnerUserID, Kind: kind, SourceID: source,
			SiteID: siteID, SiteName: request.Fields.Domain, Extra: extra}, now)
		if errors.Is(err, securitypolicy.ErrSiteCopyUnusable) {
			return nil
		}
		if err != nil {
			return err
		}
		return securitybinding.AttachNewSiteTx(ctx, tx, request.TargetScopeID, siteID, policy.ID, kind, now)
	}
	for _, name := range []string{SiteDefaultCCPolicy, SiteDefaultACLPolicy} {
		if value, ok := defaults[name]; ok {
			if id, err := uuid.Parse(value); err == nil {
				if err := copied(siteDefaultPolicyKinds[name], &id, nil); err != nil {
					return err
				}
			}
		}
	}
	// 屏蔽透明代理 and 区域屏蔽 ride on the site's WAF library (its own copy,
	// or a new one of just these rules when no WAF library is a default).
	proxy := defaults.wafExtraRules()
	var waf *uuid.UUID
	if value, ok := defaults[SiteDefaultWAFPolicy]; ok {
		if id, err := uuid.Parse(value); err == nil {
			waf = &id
		}
	}
	if waf != nil || len(proxy) != 0 {
		if err := copied(securitypolicy.KindWAF, waf, proxy); err != nil {
			return err
		}
	}
	return defaults.createHTTPPolicy(ctx, tx, actor, request, siteID, now)
}

// wafExtraRules: the system rules 屏蔽透明代理 (on) and 区域屏蔽 (a preset
// other than 不屏蔽) add to the new site's WAF library; none when neither is
// set, so nothing is created or checked.
func (defaults siteCreationUserDefaults) wafExtraRules() []securitypolicy.Rule {
	var rules []securitypolicy.Rule
	if defaults[SiteDefaultBlockProxy] == "1" {
		rules = securitypolicy.ProxyBlockRules()
	}
	return append(rules, securitypolicy.RegionBlockRules(defaults[SiteDefaultBlockRegion])...)
}

// packageDenies: a CC or WAF library needs the site's package feature (as
// publishing it does, securitybinding.CheckSitePolicyFeature); ACL never.
func packageDenies(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, kind string, now time.Time) bool {
	err := securitybinding.CheckSitePolicyFeature(ctx, tx, scopeID, siteID, securitypolicy.Policy{Kind: kind, Enabled: true}, now)
	return errors.Is(err, packageaddon.ErrFeatureDenied) || errors.Is(err, packageaddon.ErrSubscriptionInactive)
}

// createHTTPPolicy writes #18 源站请求头 / #25 上传限制 as the site's HTTP
// policy when the creator may manage HTTP policies (its revision trigger
// requires http_policies.manage); otherwise the defaults are skipped.
func (defaults siteCreationUserDefaults) createHTTPPolicy(ctx context.Context, tx pgx.Tx, actor Actor, request CreateRequest,
	siteID uuid.UUID, now time.Time) error {
	headersValue, hasHeaders := defaults[SiteDefaultReqHeader]
	sizeValue, hasSize := defaults[SiteDefaultPostSize]
	if !hasHeaders && !hasSize || !request.DefaultHTTPPolicyAllowed {
		return nil
	}
	var headers []httppolicycontrol.HeaderAction
	if hasHeaders {
		parsed, ok := parseSiteDefaultRequestHeaders(headersValue)
		if !ok {
			return nil
		}
		headers = parsed
	}
	maxUpload := int64(0)
	if megabytes, err := strconv.Atoi(sizeValue); hasSize && err == nil {
		maxUpload = int64(megabytes) << 20
	} else if maxUpload, err = systemMaxUploadBytes(ctx, tx); err != nil {
		return err
	}
	config, err := httppolicycontrol.NewSitePolicyConfig(maxUpload, headers)
	if err != nil {
		return nil
	}
	var tenantID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, request.TargetScopeID).Scan(&tenantID); err != nil {
		return err
	}
	_, err = httppolicycontrol.CreateForNewSiteTx(ctx, tx, actor.ScopeID, actor.UserID, request.TargetScopeID, tenantID,
		siteID, request.OwnerUserID, config, now)
	if errors.Is(err, httppolicycontrol.ErrConflict) {
		return nil // 租户 HTTP 策略已满（MaxSites）：在写入前拒绝，跳过默认
	}
	return err
}

// systemMaxUploadBytes: without an upload default the policy keeps the
// node's limit, the system client_max_body_size (nginx's 1m when none is
// published), capped at what an HTTP policy accepts.
func systemMaxUploadBytes(ctx context.Context, tx pgx.Tx) (int64, error) {
	value, err := loadSystemClientMaxBody(ctx, tx)
	if err != nil {
		return 0, err
	}
	return min(value, httppolicycontrol.MaxUploadBytes), nil
}

func loadSystemClientMaxBody(ctx context.Context, tx pgx.Tx) (int64, error) {
	active, found, err := systemconfig.LoadActiveEdgeNginx(ctx, tx)
	if err != nil {
		return 0, err
	}
	if !found || active.Nginx.ClientMaxBodyBytes < 1 {
		return 1 << 20, nil // edgeskeleton.DefaultSystemMaxBody
	}
	return active.Nginx.ClientMaxBodyBytes, nil
}
