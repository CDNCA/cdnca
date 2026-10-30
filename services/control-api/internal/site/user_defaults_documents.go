package site

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 网站默认设置里独立维护的两份规则文档：
//   - proxy_cache（#3 网站缓存）：一份缓存策略文档（与站点缓存页同一 cachecontrol.PolicyDocument），
//     建站同事务写成新站首个缓存策略修订（override），随 site.create 发布，不另入队。
//   - cond_origin（#30 条件源站）：只有条件规则（写法同站点条件源站的 routes），不含源站地址；
//     规则的 pool_id 只能是占位 SiteDefaultCondOriginPool，建站时换成新站自身的默认源站池。
// 两者都不引用别的站点；之后改默认不影响已建站点。

// SiteDefaultCondOriginPool: the placeholder pool of a 条件源站 default rule,
// "the new site's default origin pool".
const SiteDefaultCondOriginPool = "@default"

// siteDefaultDocumentMaxRunes is the setting_value bound of the document
// defaults (migration 518).
const siteDefaultDocumentMaxRunes = 65536

// cacheAuditor appends the cache_policy.publish audit (audit.Log).
type cacheAuditor interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type siteDefaultCondOriginDocument struct {
	Routes []ConditionalOriginRoute `json:"routes"`
}

func decodeSiteDefaultDocument(value string, target any) bool {
	if utf8.RuneCountInString(value) > siteDefaultDocumentMaxRunes {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(value)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.More() {
		return false
	}
	_, err := decoder.Token()
	return err != nil // only EOF may follow
}

func normalizeSiteDefaultCacheRule(value string) (string, bool) {
	var document cachecontrol.PolicyDocument
	if !decodeSiteDefaultDocument(value, &document) {
		return "", false
	}
	normalized, err := cachecontrol.NormalizePolicyDocument(document)
	if err != nil {
		return "", false
	}
	encoded, err := json.Marshal(normalized)
	return string(encoded), err == nil && utf8.RuneCount(encoded) <= siteDefaultDocumentMaxRunes
}

// normalizeSiteDefaultCondOrigin validates the rules as the site's own
// document would (NormalizeConditionalOriginDocument over the placeholder
// pool) and keeps only the rules.
func normalizeSiteDefaultCondOrigin(value string) (string, bool) {
	var document siteDefaultCondOriginDocument
	if !decodeSiteDefaultDocument(value, &document) || len(document.Routes) == 0 {
		return "", false
	}
	for _, route := range document.Routes {
		if route.PoolID != SiteDefaultCondOriginPool || route.FallbackPoolID != "" {
			return "", false
		}
	}
	probe, err := NormalizeConditionalOriginDocument(condOriginOverPool(document.Routes, ConditionalOriginPool{
		ID: "default", Endpoints: []ConditionalOriginEndpoint{{ID: "origin-00", Host: "192.0.2.1", Port: 80, Weight: 1}},
	}, ConditionalOriginRetry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 10, ReadTimeoutMS: 10, TotalBudgetMS: 20}))
	if err != nil {
		return "", false
	}
	for index := range probe.Routes {
		probe.Routes[index].PoolID = SiteDefaultCondOriginPool
	}
	encoded, err := json.Marshal(siteDefaultCondOriginDocument{Routes: probe.Routes})
	return string(encoded), err == nil && utf8.RuneCount(encoded) <= siteDefaultDocumentMaxRunes
}

// condOriginOverPool: a conditional origin document of one pool whose rules
// all name it (the placeholder replaced).
func condOriginOverPool(routes []ConditionalOriginRoute, pool ConditionalOriginPool, retry ConditionalOriginRetry) ConditionalOriginDocument {
	copied := make([]ConditionalOriginRoute, len(routes))
	for index, route := range routes {
		route.PoolID = pool.ID
		copied[index] = route
	}
	return ConditionalOriginDocument{Schema: ConditionalOriginSchemaV1, Pools: []ConditionalOriginPool{pool},
		DefaultPoolID: pool.ID, Routes: copied, Retry: retry}
}

// copySiteDefaultDocuments runs in the site create's tx after the site's
// origins are written. A stored default that no longer validates (a later
// release tightened a rule) is skipped, as a gone rule library is.
func (defaults siteCreationUserDefaults) copySiteDefaultDocuments(ctx context.Context, tx pgx.Tx, auditor cacheAuditor,
	actor Actor, request CreateRequest, siteID uuid.UUID, now time.Time) error {
	if value, ok := defaults[SiteDefaultCacheRule]; ok {
		var document cachecontrol.PolicyDocument
		if normalized, valid := normalizeSiteDefaultCacheRule(value); valid && json.Unmarshal([]byte(normalized), &document) == nil {
			var tenantID uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, request.TargetScopeID).Scan(&tenantID); err != nil {
				return err
			}
			_, err := cachecontrol.CreateForNewSiteTx(ctx, tx, auditor, cachecontrol.Actor{
				UserID: actor.UserID, ScopeID: request.TargetScopeID, ActorScopeID: actor.ScopeID,
			}, tenantID, siteID, document, request.RequestID, now)
			if err != nil && !errors.Is(err, cachecontrol.ErrInvalidInput) {
				return err
			}
		}
	}
	if value, ok := defaults[SiteDefaultCondOrigin]; ok {
		var rules siteDefaultCondOriginDocument
		if normalized, valid := normalizeSiteDefaultCondOrigin(value); valid && json.Unmarshal([]byte(normalized), &rules) == nil {
			base, _, err := readDefaultConditionalOriginDocument(ctx, tx, siteID)
			if errors.Is(err, ErrInvalidInput) {
				return nil // 新站自身源站池不满足条件源站文档（如超过 32 个源站）：跳过
			} else if err != nil {
				return err
			}
			document, err := NormalizeConditionalOriginDocument(condOriginOverPool(rules.Routes, base.Pools[0], base.Retry))
			if err != nil {
				return nil // 新站自身源站池不满足条件源站文档（如超过 32 个源站）：跳过
			}
			document.IngressSourceEnabled = base.IngressSourceEnabled
			if err := replaceConditionalOriginDocument(ctx, tx, siteID, actor.UserID, document, now); err != nil {
				return err
			}
		}
	}
	return nil
}
