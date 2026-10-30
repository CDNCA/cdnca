// Package cluster 是授权端规则情报的去重合并与容量库（ADR 0011 §5.2、§5.3，
// 任务 RI-10）。全部是纯函数：不碰数据库、不读时钟、不用随机数，同输入得同输出。
//
// 流水线：Normalize（规范化 + 指纹）→ CapDaily（单安装每日封顶）→ Run
// （恢复 → 类别级合成 → MinHash/LSH 聚类 → 包含合并 → 证据累加 → 衰减打分 →
// 状态与墓碑 → 容量淘汰）。被合并的变体和被淘汰的候选输出为 ArchiveItem，
// 由调用方永久写入语料库；本库从不“丢弃”样本，已发布候选永不参与衰减与淘汰。
package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
)

// Kind 是候选种类（ADR 0011 §5.1）。
type Kind string

const (
	KindWAFExclusion         Kind = "waf_exclusion"
	KindWAFTypedParam        Kind = "waf_typed_param"
	KindWAFReweight          Kind = "waf_reweight"
	KindAutodefenseSignature Kind = "autodefense_signature"
	KindCCRuleTune           Kind = "cc_rule_tune"
	KindScannerFingerprint   Kind = "scanner_fingerprint"
	// KindAttackFragment 是攻击片段（ADR 0011 §4.4）：只规范化取指纹后进语料库，不进候选池。
	KindAttackFragment Kind = "attack_fragment"
)

// Kinds 是全部已知种类，按字典序。
var Kinds = []Kind{KindAttackFragment, KindAutodefenseSignature, KindCCRuleTune, KindScannerFingerprint, KindWAFExclusion, KindWAFReweight, KindWAFTypedParam}

func (k Kind) valid() bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// Target 是候选作用的官方规则（`{engine, pack_id, rule_id|set}`）。
type Target struct {
	Engine string `json:"engine"`
	PackID string `json:"pack_id"`
	RuleID string `json:"rule_id,omitempty"`
	Set    string `json:"set,omitempty"`
}

func (t Target) key() string {
	return t.Engine + "\x1f" + t.PackID + "\x1f" + t.RuleID + "\x1f" + t.Set
}

// Cond 是一条规范条件（维度, 值）。
type Cond struct {
	Dim   string
	Value string
}

// 维度约定（规范化按维度名分派）：
//
//	param.name             参数名：小写、去 `[]` 后缀、数字下标改 `*`；命中参数字典时补 param.class
//	param.hash/loc/class   小写
//	value_type             小写
//	path                   路径模板：命中路径字典改为 path.class，否则小写且数字段改 `*`
//	path.class             小写
//	*.regex / regex        regexp/syntax（Perl）解析后 Simplify 的字符串
//	*.threshold / threshold 数值，按 1/2/5/10… 对数档向下取整
//	其它                   去首尾空白，原样保留
const (
	DimParamName  = "param.name"
	DimParamHash  = "param.hash"
	DimParamLoc   = "param.loc"
	DimParamClass = "param.class"
	DimValueType  = "value_type"
	DimPath       = "path"
	DimPathClass  = "path.class"
)

// MaxCanonicalBytes 是规范 JSON 上限（rule_intel_candidates.canonical ≤ 4 KiB）。
const MaxCanonicalBytes = 4096

var (
	// ErrInvalid：种类未知、正则不可解析、数值不可解析。
	ErrInvalid = errors.New("ruleintel/cluster: invalid candidate")
	// ErrEmpty：规范化后没有任何条件（ADR §5.2 第 1 步：直接丢）。
	ErrEmpty = errors.New("ruleintel/cluster: empty after normalization")
	// ErrTooLarge：规范 JSON 超过 MaxCanonicalBytes。
	ErrTooLarge = errors.New("ruleintel/cluster: canonical form too large")
)

// RawCandidate 是摄取（RI-09）解析出的、尚未规范化的候选。
type RawCandidate struct {
	Kind   Kind
	Target Target
	Conds  []Cond
}

// Canon 是规范化结果。Canonical 是写入 canonical 列的 JSON。
type Canon struct {
	Kind        Kind
	Target      Target
	Conds       []Cond
	Canonical   []byte
	Fingerprint string
}

// Normalizer 的三个钩子都可为 nil。
type Normalizer struct {
	// ParamClass 把规范化后的参数名映射到字典类别（"" = 字典外）。
	ParamClass func(name string) string
	// PathClass 把规范化后的路径模板映射到字典类别（"" = 字典外）。
	PathClass func(path string) string
	// Compilable 判定维度能否被 rulepack 编译（同 AD-03 CompilableOnly）；
	// 返回 false 的维度丢弃。nil = 全部保留。
	Compilable func(kind Kind, dim string) bool
}

var (
	bracketIndex = regexp.MustCompile(`\[[0-9]+\]`)
	lowerDims    = map[string]bool{DimParamHash: true, DimParamLoc: true, DimParamClass: true, DimValueType: true, DimPathClass: true}
)

// Normalize 规范化并计算指纹，确定性。
func (n Normalizer) Normalize(raw RawCandidate) (Canon, error) {
	if !raw.Kind.valid() {
		return Canon{}, fmt.Errorf("%w: kind %q", ErrInvalid, raw.Kind)
	}
	target := Target{
		Engine: strings.ToLower(strings.TrimSpace(raw.Target.Engine)),
		PackID: strings.ToLower(strings.TrimSpace(raw.Target.PackID)),
		RuleID: strings.TrimSpace(raw.Target.RuleID),
		Set:    strings.ToLower(strings.TrimSpace(raw.Target.Set)),
	}
	seen := map[Cond]bool{}
	var conds []Cond
	add := func(c Cond) {
		if c.Value != "" && !seen[c] {
			seen[c] = true
			conds = append(conds, c)
		}
	}
	hasClass := false
	for _, c := range raw.Conds {
		if strings.EqualFold(strings.TrimSpace(c.Dim), DimParamClass) {
			hasClass = true
		}
	}
	for _, c := range raw.Conds {
		dim := strings.ToLower(strings.TrimSpace(c.Dim))
		val := strings.TrimSpace(c.Value)
		if dim == "" || val == "" {
			continue
		}
		if n.Compilable != nil && !n.Compilable(raw.Kind, dim) {
			continue
		}
		switch {
		case dim == DimParamName:
			val = normParam(val)
			if n.ParamClass != nil && !hasClass {
				add(Cond{DimParamClass, strings.ToLower(n.ParamClass(val))})
			}
		case dim == DimPath:
			val = normPath(val)
			if n.PathClass != nil {
				if class := strings.ToLower(n.PathClass(val)); class != "" {
					dim, val = DimPathClass, class
				}
			}
		case dim == "regex" || strings.HasSuffix(dim, ".regex"):
			re, err := syntax.Parse(val, syntax.Perl)
			if err != nil {
				return Canon{}, fmt.Errorf("%w: %s regex: %v", ErrInvalid, dim, err)
			}
			val = re.Simplify().String()
		case dim == "threshold" || strings.HasSuffix(dim, ".threshold"):
			b, err := LogBucket(val)
			if err != nil {
				return Canon{}, fmt.Errorf("%w: %s: %v", ErrInvalid, dim, err)
			}
			val = b
		case lowerDims[dim]:
			val = strings.ToLower(val)
		}
		add(Cond{dim, val})
	}
	if len(conds) == 0 {
		return Canon{}, ErrEmpty
	}
	sortConds(conds)
	return finish(raw.Kind, target, conds)
}

func finish(kind Kind, target Target, conds []Cond) (Canon, error) {
	pairs := make([][2]string, len(conds))
	for i, c := range conds {
		pairs[i] = [2]string{c.Dim, c.Value}
	}
	canonical, err := json.Marshal(struct {
		Conds [][2]string `json:"conds"`
	}{pairs})
	if err != nil {
		return Canon{}, err
	}
	if len(canonical) > MaxCanonicalBytes {
		return Canon{}, ErrTooLarge
	}
	return Canon{Kind: kind, Target: target, Conds: conds, Canonical: canonical, Fingerprint: fingerprint(kind, target, canonical)}, nil
}

// fingerprint = SHA-256(kind ‖ target ‖ 规范 JSON)，字段间用 0x00 分隔。
func fingerprint(kind Kind, target Target, canonical []byte) string {
	h := sha256.New()
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(target.key()))
	h.Write([]byte{0})
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

func sortConds(conds []Cond) {
	sort.Slice(conds, func(i, j int) bool {
		if conds[i].Dim != conds[j].Dim {
			return conds[i].Dim < conds[j].Dim
		}
		return conds[i].Value < conds[j].Value
	})
}

func normParam(s string) string {
	s = strings.ToLower(s)
	for strings.HasSuffix(s, "[]") {
		s = strings.TrimSuffix(s, "[]")
	}
	s = bracketIndex.ReplaceAllString(s, "[*]")
	return digitSegments(s, ".")
}

func normPath(s string) string {
	return digitSegments(strings.ToLower(s), "/")
}

func digitSegments(s, sep string) string {
	parts := strings.Split(s, sep)
	for i, p := range parts {
		if p != "" && strings.Trim(p, "0123456789") == "" {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, sep)
}

// LogBucket 把数值向下取整到 1/2/5×10^k 档（≤0 归 "0"）。
func LogBucket(s string) (string, error) {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return "", fmt.Errorf("not a finite number: %q", s)
	}
	if v <= 0 {
		return "0", nil
	}
	e := math.Floor(math.Log10(v))
	m := v / math.Pow(10, e)
	if m < 1 { // Log10 浮点误差
		e--
	} else if m >= 10 {
		e++
	}
	base := math.Pow(10, e)
	m = v / base
	step := 1.0
	switch {
	case m >= 5:
		step = 5
	case m >= 2:
		step = 2
	}
	return strconv.FormatFloat(step*base, 'g', 12, 64), nil
}
