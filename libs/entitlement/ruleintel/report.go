// Package ruleintel 是主控 → 授权端规则情报上报（ADR 0011 §4.3，`cdnca.rule-intel-report/v1`）
// 的报告格式、脱敏校验与签名消息。主控（RI-08）构造并签名，授权端（RI-09）复核后摄取，
// 两端共用本包，保证同一份报告得到同一摘要。
package ruleintel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/entitlement/ruleintel/cluster"
)

const (
	Schema      = "cdnca.rule-intel-report/v1"
	Path        = "/installation/v1/rule-intel-reports"
	ProofDomain = "cdnca-rule-intel-report-proof/v1"
	// MaxReportBytes 是报告正文（json.Marshal(Report)）压缩前上限。
	MaxReportBytes = 512 << 10
	// MaxReportsPerDay 是每安装每 UTC 天上报次数上限（主控每 6 小时一次）。
	MaxReportsPerDay = 4
	maxConds         = 32
	maxValueBytes    = 128
	maxParams        = 8
)

// 各段条数上限（§4.3 表）。
var SectionLimits = map[string]int{
	"waf_exclusions": 512, "waf_rejections": 256, "waf_tighten": 128, "waf_rule_stats": 1000,
	"autodefense_signatures": 256, "cc_rule_stats": 1000, "cc_rule_tunes": 256,
	"false_positives": 256, "scanner_fingerprints": 128, "attack_fragments": MaxReportFragments,
	"pack_receipts": 256,
}

var (
	// ErrNotRedacted：出现原始值、IP、路径、标识等不允许出主控的数据，整份拒收。
	ErrNotRedacted = errors.New("ruleintel: report is not redacted")
	// ErrTooLarge：正文或某段条数超限（主控应顺延到下次，不截断）。
	ErrTooLarge = errors.New("ruleintel: report too large")
	// ErrInvalid：结构不合法（种类与段不符、计数为负、比例越界等）。
	ErrInvalid = errors.New("ruleintel: invalid report")
)

// Report 是报告正文。所有段都必须出现（空段用 []）。
type Report struct {
	WAFExclusions         []Item     `json:"waf_exclusions"`
	WAFRejections         []Item     `json:"waf_rejections"`
	WAFTighten            []Item     `json:"waf_tighten"`
	WAFRuleStats          []RuleStat `json:"waf_rule_stats"`
	AutodefenseSignatures []Item     `json:"autodefense_signatures"`
	CCRuleStats           []RuleStat `json:"cc_rule_stats"`
	CCRuleTunes           []Item     `json:"cc_rule_tunes"`
	FalsePositives        []Item     `json:"false_positives"`
	ScannerFingerprints   []Item     `json:"scanner_fingerprints"`
	// AttackFragments 是攻击片段段（§4.4，AggregateFragments 产出）；平台关闭情报贡献时省略。
	// 出现则非空，按键升序且不重复。
	AttackFragments []Fragment `json:"attack_fragments,omitempty"`
	// PackReceipts 是节点制品集回执按官方包版本的汇总（ADR 0007 §4.3、ADR 0011 §6.2 自动暂停）：
	// 主控按每个节点最近一份回执计数。出现则非空，按 (pack_id, version) 升序且不重复；没有官方包下发时省略
	// （省略时报告字节与加字段前一致）。
	PackReceipts []PackReceipt `json:"pack_receipts,omitempty"`
}

// PackReceipt 是一个官方包版本（system 层规则包或 CRS 档位包 system/crs-<级>）在本安装节点上的回执计数。
type PackReceipt struct {
	PackID   string `json:"pack_id"`
	Version  string `json:"version"`
	Applied  int64  `json:"applied"`
	Rejected int64  `json:"rejected"`
}

// Item 是一条候选证据：规范条件 + 统计。没有参数值、请求体、IP、域名、站点/租户标识。
type Item struct {
	Kind   cluster.Kind   `json:"kind"`
	Target cluster.Target `json:"target"`
	// Conds 是 [维度, 值] 对；维度只能取 AllowedDims（或 bucket.* / *.threshold）。
	Conds       [][2]string `json:"conds"`
	Hits        int64       `json:"hits"`
	Sources     int64       `json:"sources"`
	Days        int         `json:"days"`
	PassRatio   *float64    `json:"pass_ratio,omitempty"`
	AttackRatio *float64    `json:"attack_ratio,omitempty"`
	// Params 只用于 cc_rule_tunes：本安装的建议参数（window、threshold 等）。
	Params map[string]float64 `json:"params,omitempty"`
	// Reason 只用于 waf_rejections / false_positives：false_positive | attack | unneeded。
	Reason string `json:"reason,omitempty"`
}

// RuleStat 是官方规则的现场效果（waf_rule_stats / cc_rule_stats 段）。
type RuleStat struct {
	Engine        string  `json:"engine"`
	PackID        string  `json:"pack_id"`
	PackVersion   string  `json:"pack_version"`
	RuleID        string  `json:"rule_id"`
	Hits          int64   `json:"hits"`
	GreyRatio     float64 `json:"grey_ratio"`
	PassRatio     float64 `json:"pass_ratio"`
	ExcludedSites int64   `json:"excluded_sites"`
}

// AllowedDims 是可以出主控的条件维度（§4.3 脱敏规则 2–4）。不在表内的一律视为未脱敏，
// 例如 cidr、ip、path（原始路径）、value、body、cookie、ua、host、domain、site_id、tenant_id。
var AllowedDims = map[string]bool{
	cluster.DimParamName: true, cluster.DimParamHash: true, cluster.DimParamLoc: true, cluster.DimParamClass: true,
	cluster.DimValueType: true, cluster.DimPathClass: true, "len_bucket": true, "charset": true,
	"method": true, "ja4": true, "ua_family": true, "header_order_hash": true, "http_version": true,
	"asn": true, "country": true, "status": true, "attack_class": true, "window": true, "threshold": true,
}

// 每段允许的候选种类；FP 段（驳回/误判）的证据记为 fp。
var sectionKinds = map[string]map[cluster.Kind]bool{
	"waf_exclusions":         {cluster.KindWAFExclusion: true, cluster.KindWAFTypedParam: true},
	"waf_rejections":         {cluster.KindWAFExclusion: true},
	"waf_tighten":            {cluster.KindWAFReweight: true},
	"autodefense_signatures": {cluster.KindAutodefenseSignature: true},
	"cc_rule_tunes":          {cluster.KindCCRuleTune: true},
	"false_positives": {cluster.KindWAFExclusion: true, cluster.KindWAFTypedParam: true, cluster.KindWAFReweight: true,
		cluster.KindAutodefenseSignature: true, cluster.KindCCRuleTune: true, cluster.KindScannerFingerprint: true},
	"scanner_fingerprints": {cluster.KindScannerFingerprint: true},
}

var reasons = map[string]bool{"false_positive": true, "attack": true, "unneeded": true}

var (
	valuePattern  = regexp.MustCompile(`^[A-Za-z0-9_.*\-\[\]]+$`)
	pathClass     = regexp.MustCompile(`^/[A-Za-z0-9_.*\-/]*$`)
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9_.\-/]{0,128}$`)
	hashPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	paramKey      = regexp.MustCompile(`^[a-z_.]{1,32}$`)
	uuidLike      = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	dottedQuad    = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	domainLike    = regexp.MustCompile(`(?i)^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$`)
	reportFPKinds = map[string]bool{"waf_rejections": true, "false_positives": true}
	// 官方包（system 层）与版本号：回执汇总只报官方包，租户/开发者包名不出主控。
	officialPackID = regexp.MustCompile(`^system/[a-z0-9][a-z0-9-]{0,62}$`)
	semverPattern  = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)
)

// Section 是 Validate 展开后的一段，供摄取逐条处理。
type Section struct {
	Name  string
	Items []Item
	// FP = 该段证据计为误判/驳回（waf_rejections、false_positives）。
	FP bool
}

// Sections 按固定顺序返回候选段。
func (r Report) Sections() []Section {
	return []Section{
		{"waf_exclusions", r.WAFExclusions, false}, {"waf_rejections", r.WAFRejections, true},
		{"waf_tighten", r.WAFTighten, false}, {"autodefense_signatures", r.AutodefenseSignatures, false},
		{"cc_rule_tunes", r.CCRuleTunes, false}, {"false_positives", r.FalsePositives, true},
		{"scanner_fingerprints", r.ScannerFingerprints, false},
	}
}

// Counts 返回各段条数（收据用）。
func (r Report) Counts() map[string]int {
	counts := map[string]int{"waf_rule_stats": len(r.WAFRuleStats), "cc_rule_stats": len(r.CCRuleStats),
		"attack_fragments": len(r.AttackFragments)}
	if r.PackReceipts != nil {
		counts["pack_receipts"] = len(r.PackReceipts)
	}
	for _, s := range r.Sections() {
		counts[s.Name] = len(s.Items)
	}
	return counts
}

// Digest 是报告正文的 SHA-256（json.Marshal(Report)，两端同一结构体故字节一致）。
func Digest(r Report) ([32]byte, []byte, error) {
	encoded, err := json.Marshal(r)
	if err != nil {
		return [32]byte{}, nil, err
	}
	return sha256.Sum256(encoded), encoded, nil
}

// ProofMessage 是安装 Ed25519 签名的消息（同 051 ReportProofMessage 构造）。
func ProofMessage(schema, requestID, installationID string, sequence uint64, observedAt int64, digest [32]byte) []byte {
	return rulecatalog.DigestFields(ProofDomain, schema, requestID, installationID,
		strconv.FormatUint(sequence, 10), strconv.FormatInt(observedAt, 10), hex.EncodeToString(digest[:]))
}

// Validate 校验结构、体积与脱敏。返回 ErrTooLarge / ErrNotRedacted / ErrInvalid（包装了原因）。
func Validate(r Report) error {
	if r.WAFExclusions == nil || r.WAFRejections == nil || r.WAFTighten == nil || r.WAFRuleStats == nil ||
		r.AutodefenseSignatures == nil || r.CCRuleStats == nil || r.CCRuleTunes == nil || r.FalsePositives == nil ||
		r.ScannerFingerprints == nil {
		return fmt.Errorf("%w: missing section", ErrInvalid)
	}
	for name, n := range r.Counts() {
		if n > SectionLimits[name] {
			return fmt.Errorf("%w: %s has %d items (limit %d)", ErrTooLarge, name, n, SectionLimits[name])
		}
	}
	_, encoded, err := Digest(r)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(encoded) > MaxReportBytes {
		return fmt.Errorf("%w: %d bytes", ErrTooLarge, len(encoded))
	}
	for _, s := range r.Sections() {
		for i, item := range s.Items {
			if err := validateItem(s.Name, item); err != nil {
				return fmt.Errorf("%s[%d]: %w", s.Name, i, err)
			}
		}
	}
	if r.AttackFragments != nil && len(r.AttackFragments) == 0 {
		return fmt.Errorf("%w: empty attack_fragments", ErrInvalid)
	}
	for i, f := range r.AttackFragments {
		if err := validateFragment(f); err != nil {
			return fmt.Errorf("attack_fragments[%d]: %w", i, err)
		}
		if i > 0 && r.AttackFragments[i-1].key() >= f.key() {
			return fmt.Errorf("%w: attack_fragments not ascending", ErrInvalid)
		}
	}
	if r.PackReceipts != nil && len(r.PackReceipts) == 0 {
		return fmt.Errorf("%w: empty pack_receipts", ErrInvalid)
	}
	for i, receipt := range r.PackReceipts {
		if !officialPackID.MatchString(receipt.PackID) || !semverPattern.MatchString(receipt.Version) ||
			receipt.Applied < 0 || receipt.Rejected < 0 || receipt.Applied+receipt.Rejected == 0 {
			return fmt.Errorf("%w: pack_receipts[%d]", ErrInvalid, i)
		}
		if i > 0 {
			previous := r.PackReceipts[i-1]
			if previous.PackID > receipt.PackID || previous.PackID == receipt.PackID && previous.Version >= receipt.Version {
				return fmt.Errorf("%w: pack_receipts not ascending", ErrInvalid)
			}
		}
	}
	for _, stats := range [][]RuleStat{r.WAFRuleStats, r.CCRuleStats} {
		for i, st := range stats {
			if err := validateRuleStat(st); err != nil {
				return fmt.Errorf("rule_stats[%d]: %w", i, err)
			}
		}
	}
	return nil
}

func validateItem(section string, item Item) error {
	if !sectionKinds[section][item.Kind] {
		return fmt.Errorf("%w: kind %q not allowed in %s", ErrInvalid, item.Kind, section)
	}
	if err := validateTarget(item.Target); err != nil {
		return err
	}
	if len(item.Conds) == 0 || len(item.Conds) > maxConds {
		return fmt.Errorf("%w: %d conds", ErrInvalid, len(item.Conds))
	}
	for _, c := range item.Conds {
		if err := validateCond(c[0], c[1]); err != nil {
			return err
		}
	}
	if item.Hits < 0 || item.Sources < 0 || item.Days < 0 || item.Days > 366 || !ratio(item.PassRatio) || !ratio(item.AttackRatio) {
		return fmt.Errorf("%w: counter out of range", ErrInvalid)
	}
	if reportFPKinds[section] != (item.Reason != "") || (item.Reason != "" && !reasons[item.Reason]) {
		return fmt.Errorf("%w: reason %q", ErrInvalid, item.Reason)
	}
	if len(item.Params) > 0 && section != "cc_rule_tunes" {
		return fmt.Errorf("%w: params only for cc_rule_tunes", ErrInvalid)
	}
	if len(item.Params) > maxParams {
		return fmt.Errorf("%w: %d params", ErrInvalid, len(item.Params))
	}
	for k, v := range item.Params {
		if !paramKey.MatchString(k) || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return fmt.Errorf("%w: param %q", ErrInvalid, k)
		}
	}
	return nil
}

func ratio(v *float64) bool { return v == nil || (*v >= 0 && *v <= 1) }

func validateTarget(t cluster.Target) error {
	for _, v := range []string{t.Engine, t.PackID, t.RuleID, t.Set} {
		if !idPattern.MatchString(v) {
			return fmt.Errorf("%w: target %q", ErrInvalid, v)
		}
		if leaks(v) {
			return fmt.Errorf("%w: target %q", ErrNotRedacted, v)
		}
	}
	if t.Engine == "" || t.PackID == "" || (t.RuleID == "" && t.Set == "") {
		return fmt.Errorf("%w: incomplete target", ErrInvalid)
	}
	return nil
}

func validateRuleStat(st RuleStat) error {
	for _, v := range []string{st.Engine, st.PackID, st.PackVersion, st.RuleID} {
		if v == "" || !idPattern.MatchString(v) {
			return fmt.Errorf("%w: rule stat id %q", ErrInvalid, v)
		}
		if leaks(v) {
			return fmt.Errorf("%w: rule stat id %q", ErrNotRedacted, v)
		}
	}
	if st.Hits < 0 || st.ExcludedSites < 0 || st.GreyRatio < 0 || st.GreyRatio > 1 || st.PassRatio < 0 || st.PassRatio > 1 ||
		math.IsNaN(st.GreyRatio) || math.IsNaN(st.PassRatio) {
		return fmt.Errorf("%w: rule stat counter", ErrInvalid)
	}
	return nil
}

// validateCond：维度白名单、值字符集（无空白/引号/=&?%@:，挡住查询串、请求体、邮箱、URL、IPv6）、
// 不得出现 IP / 网段 / UUID 标识 / 域名；param.hash 必须是 64 位小写十六进制；
// path.class 只能是路径模板类别。
func validateCond(dim, value string) error {
	d := strings.ToLower(strings.TrimSpace(dim))
	if !(AllowedDims[d] || strings.HasPrefix(d, "bucket.") || strings.HasSuffix(d, ".threshold")) {
		return fmt.Errorf("%w: dimension %q", ErrNotRedacted, dim)
	}
	if value == "" || len(value) > maxValueBytes {
		return fmt.Errorf("%w: %s value length", ErrNotRedacted, d)
	}
	switch d {
	case cluster.DimParamHash, "header_order_hash":
		if !hashPattern.MatchString(value) {
			return fmt.Errorf("%w: %s must be a hex digest", ErrNotRedacted, d)
		}
		return nil
	case cluster.DimPathClass:
		if !pathClass.MatchString(value) || leaks(value) {
			return fmt.Errorf("%w: path.class %q", ErrNotRedacted, value)
		}
		return nil
	}
	if !valuePattern.MatchString(value) || leaks(value) {
		return fmt.Errorf("%w: %s value", ErrNotRedacted, d)
	}
	if d != cluster.DimParamName && domainLike.MatchString(value) && strings.Contains(value, ".") {
		return fmt.Errorf("%w: %s looks like a domain", ErrNotRedacted, d)
	}
	return nil
}

func leaks(v string) bool {
	if v == "" {
		return false
	}
	if net.ParseIP(v) != nil || dottedQuad.MatchString(v) || uuidLike.MatchString(v) {
		return true
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		return true
	}
	return false
}

// Raw 把一条已校验的上报转成 cluster.RawCandidate（入库前再 Normalize）。
func (item Item) Raw() cluster.RawCandidate {
	conds := make([]cluster.Cond, len(item.Conds))
	for i, c := range item.Conds {
		conds[i] = cluster.Cond{Dim: c[0], Value: c[1]}
	}
	return cluster.RawCandidate{Kind: item.Kind, Target: item.Target, Conds: conds}
}
