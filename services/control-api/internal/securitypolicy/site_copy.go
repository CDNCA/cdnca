package securitypolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 网站列表 > 默认设置 复制快照：建站时在建站事务里把默认
// 设置引用的规则库复制成新站专用的一份（新 ID、新规则 ID），之后改原库或默认
// 设置都不影响已建站点。复制走与 Create 相同的校验与写入（版本、审计）。

// ProxyHeaders are the request headers 屏蔽透明代理 treats as "via a proxy"
// (any one present): 按代理请求头识别，经企业代理访问的用户也会被拦截。
var ProxyHeaders = []string{"via", "x-forwarded-for", "forwarded"}

// ProxyBlockRules are the WAF rules of 屏蔽透明代理: one block rule per
// header, matching when the header is present (a WAF header inspect clause
// sees no value for an absent header). Priority 1 runs them first.
func ProxyBlockRules() []Rule {
	rules := make([]Rule, 0, len(ProxyHeaders))
	for _, header := range ProxyHeaders {
		rules = append(rules, Rule{Name: "屏蔽透明代理 " + header, Priority: 1, Enabled: true, Action: ActionBlock, Flow: FlowStop,
			Conditions: []Condition{{Field: "header", Key: header, Operator: "regex", Values: []string{"."}}}})
	}
	return rules
}

// 区域屏蔽快捷预设（#4/#31，block_region 的四个取值，拼写保持接口原样）：一条 WAF country
// 规则，按客户端 IP 在节点 IP 情报库里的国家/地区判定。港澳台按地区代码
// HK/MO/TW 计。节点没有 IP 库时 country 条件一律不命中（cdnca_iplib.test），
// 不会误拦；库里查不到的地址没有国家，not_in 视为命中（"海外"含未知地址）。
const (
	RegionBlockAbroad      = "abrord_inc"    // 屏蔽境外（含港澳台）：非 CN 都拦
	RegionBlockAbroadNoHMT = "abrord_no_inc" // 屏蔽境外（不含港澳台）：CN/HK/MO/TW 以外拦
	RegionBlockChina       = "china_inc"     // 屏蔽境内（含港澳台）：CN/HK/MO/TW 拦
	RegionBlockChinaNoHMT  = "china_not_inc" // 屏蔽境内（不含港澳台）：只拦 CN
	RegionBlockNone        = "none"          // 不屏蔽（可用分组默认覆盖全局默认）
)

var regionBlockPresets = map[string]struct {
	name     string
	operator string
	values   []string
}{
	RegionBlockAbroad:      {"屏蔽境外（含港澳台）", "not_in", []string{"CN"}},
	RegionBlockAbroadNoHMT: {"屏蔽境外（不含港澳台）", "not_in", []string{"CN", "HK", "MO", "TW"}},
	RegionBlockChina:       {"屏蔽境内（含港澳台）", "in", []string{"CN", "HK", "MO", "TW"}},
	RegionBlockChinaNoHMT:  {"屏蔽境内（不含港澳台）", "in", []string{"CN"}},
}

// ValidRegionBlockPreset reports whether preset is one of the presets or none.
func ValidRegionBlockPreset(preset string) bool {
	_, ok := regionBlockPresets[preset]
	return ok || preset == RegionBlockNone
}

// RegionBlockRules is the WAF rule of a 区域屏蔽 preset (none for "none" or
// an unknown preset). Priority 1 runs it with 屏蔽透明代理, before the rest.
func RegionBlockRules(preset string) []Rule {
	value, ok := regionBlockPresets[preset]
	if !ok {
		return nil
	}
	return []Rule{{Name: "区域屏蔽 " + value.name, Priority: 1, Enabled: true, Action: ActionBlock, Flow: FlowStop,
		Conditions: []Condition{{Field: "country", Operator: value.operator, Values: append([]string(nil), value.values...)}}}}
}

// SiteCopyRequest names what a new site gets: the policy sourceID of kind
// (nil: a new policy of only Extra, WAF only) with Extra appended.
type SiteCopyRequest struct {
	ScopeID  uuid.UUID
	OwnerID  uuid.UUID
	Kind     string
	SourceID *uuid.UUID
	SiteID   uuid.UUID
	SiteName string
	Extra    []Rule
	// SourceScopeID / SourceOwnerID: where SourceID lives when it is not the
	// target's own library (site transfer copies the old site's library into
	// the new owner's tenant); zero means ScopeID / OwnerID.
	SourceScopeID uuid.UUID
	SourceOwnerID uuid.UUID
}

// ErrSiteCopyUnusable: the referenced policy is gone, another owner's, of
// another kind or a protected (subscribed) library; the copy is skipped.
var ErrSiteCopyUnusable = errors.New("site default security policy is not usable")

// CheckSiteCopySourceTx: the policy a default names must be the owner's own,
// live, of kind and not a subscribed (protected) library.
func CheckSiteCopySourceTx(ctx context.Context, tx pgx.Tx, scopeID, ownerID, id uuid.UUID, kind string) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM security_policies WHERE id=$1 AND scope_id=$2
		AND owner_user_id=$3 AND kind=$4 AND deleted_at IS NULL AND description NOT LIKE $5)`,
		id, scopeID, ownerID, kind, licensedWAFDescriptionPrefix+"%").Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrSiteCopyUnusable
	}
	return nil
}

// CopyForSiteTx creates the site's own policy inside the site create's tx
// and returns it; ErrSiteCopyUnusable when the source cannot be copied.
func CopyForSiteTx(ctx context.Context, tx pgx.Tx, actor Actor, request SiteCopyRequest, now time.Time) (Policy, error) {
	fields := PolicyFields{Kind: request.Kind, Enabled: true, DefaultAction: ActionAllow}
	var block *QuickBlock
	baseName := "网站默认防护"
	if request.SourceID != nil {
		sourceScope, sourceOwner := request.ScopeID, request.OwnerID
		if request.SourceScopeID != uuid.Nil {
			sourceScope, sourceOwner = request.SourceScopeID, request.SourceOwnerID
		}
		if err := CheckSiteCopySourceTx(ctx, tx, sourceScope, sourceOwner, *request.SourceID, request.Kind); err != nil {
			return Policy{}, err
		}
		source, err := selectPolicy(ctx, tx, *request.SourceID, false)
		if err != nil {
			return Policy{}, err
		}
		baseName = source.Name
		fields.Description, fields.Enabled, fields.DefaultAction = source.Description, source.Enabled, source.DefaultAction
		// Quick block rules carry IDs derived from the policy: re-derived below.
		fields.Rules = cloneRules(MergeQuickBlockRules(source.ID, source.Rules, nil))
		if source.QuickBlock != nil && source.QuickBlock.Active() {
			block = source.QuickBlock
		}
		fields.CCSettings = cloneCCSettings(source.CCSettings)
		fields.WAFSettings = cloneWAFSettings(source.WAFSettings)
	} else if request.Kind != KindWAF {
		return Policy{}, ErrInvalidInput
	}
	for index := range fields.Rules {
		fields.Rules[index].ID = uuid.Nil
	}
	fields.Rules = append(fields.Rules, cloneRules(request.Extra)...)
	if fields.CCSettings != nil && fields.CCSettings.AutoSwitch != nil {
		for index := range fields.CCSettings.AutoSwitch.Rules {
			fields.CCSettings.AutoSwitch.Rules[index].ID = uuid.Nil
		}
	}
	fields.Name = siteCopyName(baseName, request.SiteName, request.SiteID)
	policyID, err := uuid.NewV7()
	if err != nil {
		return Policy{}, err
	}
	// Fresh rule IDs, then the quick block rules under this policy's derived
	// IDs; checked as Update stores them (IDs assigned).
	if err := assignRuleIDs(fields.Rules, nil); err != nil {
		return Policy{}, err
	}
	if fields.Rules = MergeQuickBlockRules(policyID, fields.Rules, block); len(fields.Rules) > 100 {
		return Policy{}, ErrQuickBlockRuleBudget
	}
	// The copy is not a request body: refusals name no field.
	if err := normalizePublishableFields(&fields, false); err != nil {
		return Policy{}, unlocated(err)
	}
	if fields.Kind == KindACL {
		if err := validateACLFields(fields.Rules); err != nil {
			return Policy{}, err
		}
	}
	if err := normalizeCCSettings(fields.Kind, fields.CCSettings, true); err != nil {
		return Policy{}, unlocated(err)
	}
	if err := requireUsableIPLists(ctx, tx, request.ScopeID, fields.Rules); err != nil {
		return Policy{}, err
	}
	tenantID, err := authorizeTargetScope(ctx, tx, actor, request.ScopeID, request.OwnerID)
	if err != nil {
		return Policy{}, err
	}
	if err := assignCCSettingsRuleIDs(policyID, fields.Rules, fields.CCSettings, nil); err != nil {
		return Policy{}, err
	}
	store := NewStoreWithClock(nil, func() time.Time { return now })
	rules, settings, wafSettings, quickBlock, err := encodeSiteCopy(fields, block)
	if err != nil {
		return Policy{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security_policies (
			id, scope_id, tenant_id, owner_user_id, kind, name, description,
			enabled, default_action, rules, created_by_user_id, updated_by_user_id,
			created_at, updated_at, cc_settings, waf_settings, quick_block
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$12,$12,$13,$14,$15)`,
		policyID, request.ScopeID, tenantID, request.OwnerID, fields.Kind, fields.Name, fields.Description,
		fields.Enabled, fields.DefaultAction, rules, actor.UserID, now, settings, wafSettings, quickBlock); err != nil {
		if isUniqueViolation(err) {
			return Policy{}, ErrConflict
		}
		return Policy{}, err
	}
	item, err := selectPolicy(ctx, tx, policyID, false)
	if err != nil {
		return Policy{}, err
	}
	if err := store.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
		return Policy{}, err
	}
	if err := store.appendAudit(ctx, tx, actor, item, "site-default-copy:"+request.SiteID.String(), "security_policy.create"); err != nil {
		return Policy{}, err
	}
	return item, nil
}

func encodeSiteCopy(fields PolicyFields, block *QuickBlock) (rules, settings, wafSettings, quickBlock []byte, err error) {
	if rules, err = json.Marshal(fields.Rules); err != nil {
		return
	}
	if settings, err = encodeCCSettings(fields.CCSettings); err != nil {
		return
	}
	if wafSettings, err = encodeWAFSettings(fields.WAFSettings); err != nil {
		return
	}
	if block != nil {
		quickBlock, err = json.Marshal(block)
	}
	return
}

// siteCopyName is "<source> · <site>-<last 8 hex of the site ID>" (the
// random part of a UUIDv7) within the 128 character name limit, so copies
// of one library for different sites do not collide.
func siteCopyName(source, site string, siteID uuid.UUID) string {
	tail := siteID.String()[28:]
	suffix := fmt.Sprintf(" · %s-%s", site, tail)
	if utf8.RuneCountInString(suffix) > 64 {
		suffix = " · " + tail
	}
	runes := []rune(source)
	if room := 128 - utf8.RuneCountInString(suffix); len(runes) > room {
		runes = runes[:room]
	}
	return strings.TrimSpace(string(runes)) + suffix
}
