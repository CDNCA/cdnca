package ruleintel

import (
	"cmp"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/cdnca/cdnca/libs/entitlement/ruleintel/cluster"
	"github.com/cdnca/cdnca/libs/entitlement/ruleintel/redact"
)

// 攻击片段段 attack_fragments（ADR 0011 §4.4）：只来自被强信号拦下的
// 请求，打码后上报（libs/entitlement/ruleintel/redact）；正常请求的值永远不报。授权端用同一
// 打码库复核，仍检出个人信息则整份拒收（ErrNotRedacted）。合格片段规范化后写入语料库
// （rule_intel_corpus kind=attack, source=report），不进候选池。
const (
	// MaxReportFragments 是一份报告的片段条数上限；MaxFragmentSectionBytes 是该段编码后的
	// 字节预算（AggregateFragments 保证不超，留出报告其余段的空间）。
	MaxReportFragments      = 512
	MaxFragmentSectionBytes = 192 << 10
	// MaxSiteHourFragments 是每站每小时上限（同节点契约 autodefense.MaxWAFFragments）。
	MaxSiteHourFragments = 32
	// FragmentSignalStrong：强分达阈值；其余信号是结构化检测器名。
	FragmentSignalStrong = "strong"
	// DimFragment / DimFragmentEncoding 是片段在规范形式里的维度。
	DimFragment         = "fragment"
	DimFragmentEncoding = "fragment.encoding"
	// FragmentEngine 是片段对应的规则引擎（CRS 档位包）。
	FragmentEngine = "modsecurity"
)

// FragmentLocations 是片段位置（同节点契约 autodefense.WAFFragmentLocations）。
var FragmentLocations = []string{"args", "body", "cookie", "header", "path"}

var (
	fragmentRule     = regexp.MustCompile(`^9[0-9]{5}$`)
	fragmentParamKey = regexp.MustCompile(`^[a-z0-9_.\[\]*-]{1,64}$`)
	fragmentSignal   = regexp.MustCompile(`^[a-z_]{1,16}$`)
	fragmentPack     = regexp.MustCompile(`^system/crs-[a-z0-9][a-z0-9-]{0,59}$`)
)

// Fragment 是一条攻击片段（同一片段跨站点、节点合并后计数）。不含站点、租户、节点标识。
type Fragment struct {
	Target   cluster.Target `json:"target"` // engine=modsecurity, pack_id=system/crs-*, rule_id
	Location string         `json:"location"`
	ParamKey string         `json:"param_key,omitempty"` // path/body 为空
	Fragment string         `json:"fragment"`
	Encoding string         `json:"encoding"` // redact.EncodingText | redact.EncodingPercent
	Signal   string         `json:"signal"`   // strong | 检测器名
	Hits     int64          `json:"hits"`     // 本周期被拦次数
	Sites    int64          `json:"sites"`    // 本安装出现的站点数
}

func (f Fragment) key() string {
	return f.Target.PackID + "\x00" + f.Target.RuleID + "\x00" + f.Location + "\x00" + f.ParamKey + "\x00" + f.Fragment + "\x00" + f.Encoding
}

func validateFragment(f Fragment) error {
	// 先复核打码（个人信息一律归 ErrNotRedacted → 422，与形状错误区分）：参数名与片段再跑一遍
	// 打码都不变；片段编码不规范或超长同样按未脱敏拒收（无法证明已打码）。
	if !redact.Clean(f.ParamKey) || !redact.CleanFragment(f.Fragment, f.Encoding) {
		return fmt.Errorf("%w: attack fragment", ErrNotRedacted)
	}
	if f.Target.Engine != FragmentEngine || !fragmentPack.MatchString(f.Target.PackID) || !fragmentRule.MatchString(f.Target.RuleID) ||
		f.Target.Set != "" || !slices.Contains(FragmentLocations, f.Location) || !fragmentSignal.MatchString(f.Signal) ||
		f.Hits <= 0 || f.Sites <= 0 || f.Sites > f.Hits {
		return fmt.Errorf("%w: attack fragment shape", ErrInvalid)
	}
	named := f.Location != "path" && f.Location != "body"
	if named != (f.ParamKey != "") || (named && !fragmentParamKey.MatchString(f.ParamKey)) {
		return fmt.Errorf("%w: attack fragment param_key", ErrInvalid)
	}
	if f.Encoding != redact.EncodingText && f.Encoding != redact.EncodingPercent {
		return fmt.Errorf("%w: attack fragment encoding", ErrInvalid)
	}
	return nil
}

// Raw 把片段转成 cluster.RawCandidate（入语料库前 Normalize 取指纹去重）。
func (f Fragment) Raw() cluster.RawCandidate {
	conds := []cluster.Cond{{Dim: cluster.DimParamLoc, Value: f.Location}, {Dim: DimFragment, Value: f.Fragment},
		{Dim: DimFragmentEncoding, Value: f.Encoding}}
	if f.ParamKey != "" {
		conds = append(conds, cluster.Cond{Dim: cluster.DimParamName, Value: f.ParamKey})
	}
	return cluster.RawCandidate{Kind: cluster.KindAttackFragment, Target: f.Target, Conds: conds}
}

// FragmentSighting 是主控从节点 waf_evidence 收到的一条片段（RI-08 从 autodefense.WAFFragment
// 与所在报告的站点、小时、档位包映射而来）。
type FragmentSighting struct {
	SiteID   string
	Hour     int64
	PackID   string
	RuleID   int64
	Location string
	ParamKey string
	Fragment string
	Encoding string
	Signal   string
}

// AggregateFragments 是主控汇总（RI-08 上报前调用）：
//   - enabled=false（平台关闭“向官方贡献规则情报”，Q1）时返回 nil，报告不带该段；
//   - 每条片段解码后用同一打码库重新打码（节点漏打的在主控补上，结果为空的丢弃）；
//   - 每站每小时只取前 MaxSiteHourFragments 条（按输入顺序）；
//   - 相同 (档位包, 规则, 位置, 参数, 片段) 合并：Hits 求和、Sites 计不同站点数；
//   - 按 Hits 降序（同数按键升序）取至多 MaxReportFragments 条且编码后不超过
//     MaxFragmentSectionBytes，结果按键升序（确定性）。
//
// dropped 是被丢弃的条数（形状不合法、打码后为空、超每站每小时上限、超报告上限）。
func AggregateFragments(enabled bool, sightings []FragmentSighting) (fragments []Fragment, dropped int) {
	if !enabled {
		return nil, 0
	}
	type siteHour struct {
		site string
		hour int64
	}
	perSiteHour := map[siteHour]int{}
	merged := map[string]*Fragment{}
	sites := map[string]map[string]bool{}
	for _, s := range sightings {
		raw, ok := redact.DecodeFragment(s.Fragment, s.Encoding)
		if !ok {
			dropped++
			continue
		}
		text, encoding, _ := redact.RedactFragment([]byte(raw))
		paramKey, _ := redact.Redact(s.ParamKey)
		f := Fragment{Target: cluster.Target{Engine: FragmentEngine, PackID: s.PackID, RuleID: strconv.FormatInt(s.RuleID, 10)},
			Location: s.Location, ParamKey: paramKey, Fragment: text, Encoding: encoding, Signal: s.Signal, Hits: 1, Sites: 1}
		if text == "" || validateFragment(f) != nil {
			dropped++
			continue
		}
		sh := siteHour{s.SiteID, s.Hour}
		if perSiteHour[sh] >= MaxSiteHourFragments {
			dropped++
			continue
		}
		perSiteHour[sh]++
		k := f.key()
		if existing, ok := merged[k]; ok {
			existing.Hits++
			if !sites[k][s.SiteID] {
				sites[k][s.SiteID] = true
				existing.Sites++
			}
			continue
		}
		merged[k] = &f
		sites[k] = map[string]bool{s.SiteID: true}
	}
	all := make([]Fragment, 0, len(merged))
	for _, f := range merged {
		all = append(all, *f)
	}
	slices.SortFunc(all, func(a, b Fragment) int { return cmp.Or(cmp.Compare(b.Hits, a.Hits), cmp.Compare(a.key(), b.key())) })
	budget := MaxFragmentSectionBytes
	for _, f := range all {
		encoded, _ := json.Marshal(f)
		if len(fragments) >= MaxReportFragments || len(encoded)+1 > budget {
			dropped++
			continue
		}
		budget -= len(encoded) + 1
		fragments = append(fragments, f)
	}
	sortFragments(fragments)
	return fragments, dropped
}

func sortFragments(fragments []Fragment) {
	slices.SortFunc(fragments, func(a, b Fragment) int { return cmp.Compare(a.key(), b.key()) })
}
