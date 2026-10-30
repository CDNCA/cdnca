// Package evalreport 是质量门 G3（ADR 0011 §5.5、RI-11）的评测报告格式与判定。
// 评测工具（cdnca-waf-check -only eval -report）只写逐条原始结果；结论只由 Decide
// 从新旧两份原始报告算出，所以任何时候拿存下来的两份报告重算都得到同一结论（可复算）。
package evalreport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
)

// Schema 是报告格式版本。
const Schema = "cdnca.waf-eval-report/v1"

// 逐档结果字母（Result.Outcome 第 i 个字节对应 Tiers[i]）。
const (
	Passed     = 'p' // 放行（200..499 中非 403）
	Blocked    = 'b' // 403
	Challenged = 'c' // 灰区挑战（含挑战计为拦截）
	Failed     = 'e' // 连接失败 / 5xx：评测本身出错
	Excluded   = 'x' // 通用数据集样本无应答：按 waf-comparison 口径不计（只允许 std: 样本）
)

// ModeMark 是只打标情报包的回放模式（Report.Mode）。打标包只加分不拦截，"拦截率"即命中率：攻击语料命中不降、
// 正常语料命中不升，与档位包同一 Decide。
const ModeMark = "mark"

// StdPrefix 是通用数据集样本的 ID 前缀（std:<数据集>:<原 ID>）。
const StdPrefix = "std:"

// StdSource 是一次评测带上的通用数据集（waf-comparison，ADR 0011 §5.5：每次发布带
// --fast 子集，全量只在手动重评时）。样本原文太大不进库，只记文件摘要与条数，同一份文件即可复现。
type StdSource struct {
	Mode  string    `json:"mode"` // fast | full
	Files []StdFile `json:"files"`
}

// StdFile 是一个数据集文件（scripts/security/datasets/convert.py 产物 <name>.jsonl.gz）。
type StdFile struct {
	Name     string `json:"name"`
	SHA256   string `json:"sha256"`
	Requests int    `json:"requests"`
}

// 通用数据集模式。
const (
	StdFast = "fast"
	StdFull = "full"
)

// Tier 是一档：一个 CRS 档位包。
type Tier struct {
	PackID  string `json:"pack_id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Result 是一条语料请求在各档的结果。
type Result struct {
	ID       string `json:"id"`
	Attack   bool   `json:"attack"`
	Category string `json:"category,omitempty"`
	Outcome  string `json:"outcome"`
}

// Report 是一次评测（一组档位包 × 一份语料）的原始结果。
type Report struct {
	Schema     string     `json:"schema"`
	CRSVersion string     `json:"crs_version"`
	Tiers      []Tier     `json:"tiers"`
	Corpus     string     `json:"corpus_sha256"` // 有序语料（ID + 请求内容）的摘要，新旧两次必须相同
	Std        *StdSource `json:"std,omitempty"` // 带通用数据集时：样本排在语料之后，ID 以 StdPrefix 开头
	// Mode 为空 = CRS 档位包回放（逐档 p/b/c/e 是节点应答）；ModeMark = 规则情报只打标包（system/scanner-signatures、
	// system/autodefense-intel）回放：唯一一"档"是该包，b = 请求被该包打标（命中），p = 未命中。
	Mode string `json:"mode,omitempty"`
	Results    []Result   `json:"results"`
}

// Request 是一条语料请求（评测语料文件一行一条 JSON，与 cdnca-waf-check 的 evalRequest 同形）：
// Value 非空时按 query 参数与表单字段各发一次，否则按整条请求原样发送。
type Request struct {
	ID       string            `json:"id"`
	Attack   bool              `json:"attack"`
	Category string            `json:"category,omitempty"`
	Method   string            `json:"method,omitempty"`
	URI      string            `json:"uri,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Data     string            `json:"data,omitempty"`
	Value    string            `json:"value,omitempty"`
	// Client 是客户端属性（规则情报合成复现请求的 ja4/country/asn 维度）：只有情报包回放（G3 打标模式）用，
	// CRS 档位包回放发往真实节点时忽略。
	Client *Client `json:"client,omitempty"`
}

// Client 是一条语料请求的客户端属性（节点上来自 TLS 指纹与 IP 库，回放时由评测工具注入）。
type Client struct {
	JA4     string `json:"ja4,omitempty"`
	Country string `json:"country,omitempty"`
	ASN     string `json:"asn,omitempty"`
}

// CorpusDigest 是有序语料的摘要（每条 json.Marshal 后加换行；map 键 Go 按序编码），
// 评测工具与授权端各算一次，报告里的 corpus_sha256 必须与授权端组装的语料一致。
func CorpusDigest(requests []Request) string {
	hash := sha256.New()
	for _, request := range requests {
		encoded, _ := json.Marshal(request)
		hash.Write(encoded)
		hash.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// Decode 严格解析一份报告（未知字段、尾随数据、形状不对都拒绝）。
func Decode(content []byte) (Report, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, fmt.Errorf("decode eval report: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Report{}, errors.New("decode eval report: trailing data")
	}
	if report.Schema != Schema || len(report.Tiers) == 0 || len(report.Results) == 0 || len(report.Corpus) != 64 ||
		report.Mode != "" && report.Mode != ModeMark {
		return Report{}, errors.New("decode eval report: not a " + Schema + " report")
	}
	seen := make(map[string]bool, len(report.Results))
	for _, result := range report.Results {
		if result.ID == "" || seen[result.ID] || len(result.Outcome) != len(report.Tiers) {
			return Report{}, fmt.Errorf("decode eval report: result %q", result.ID)
		}
		seen[result.ID] = true
		for index := range len(result.Outcome) {
			switch result.Outcome[index] {
			case Passed, Blocked, Challenged, Failed:
			case Excluded:
				if !strings.HasPrefix(result.ID, StdPrefix) {
					return Report{}, fmt.Errorf("decode eval report: result %q excluded outside the public datasets", result.ID)
				}
			default:
				return Report{}, fmt.Errorf("decode eval report: result %q outcome %q", result.ID, result.Outcome)
			}
		}
	}
	return report, nil
}

// Digest 是报告字节的 SHA-256（判定里记下两份输入的摘要）。
func Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// TierCount 是一档的计数（拦截含挑战）。
type TierCount struct {
	Attacks        int `json:"attacks"`
	Blocked        int `json:"blocked"`
	Benign         int `json:"benign"`
	FalsePositives int `json:"false_positives"`
	Errors         int `json:"errors"`
	Excluded       int `json:"excluded"` // 新旧任一次无应答的通用数据集样本（两边都不计）
}

// TierVerdict 是一档的新旧对比。
type TierVerdict struct {
	PackID    string    `json:"pack_id"`
	Name      string    `json:"name"`
	Base      TierCount `json:"base"`
	Candidate TierCount `json:"candidate"`
	Changed   int       `json:"changed"`
}

// Change 是一条被新版本改变结果的样本。
type Change struct {
	ID     string `json:"id"`
	Attack bool   `json:"attack"`
	Tier   string `json:"tier"`
	From   string `json:"from"`
	To     string `json:"to"`
}

// 拒绝原因。
const (
	ReasonMismatch        = "report_mismatch"    // 两份报告不是同一语料/同一组档
	ReasonEvalErrors      = "eval_errors"        // 评测出错（连接失败/5xx），需重跑，不代表候选好坏
	ReasonBlockRateDrop   = "block_rate_dropped" // 某档拦截率（含挑战）低于旧版
	ReasonFalsePosRise    = "false_positive_rose"
	ReasonStandardChanged = "standard_changed" // 标准档逐条结果与旧版不同
)

// Verdict 是 G3 结论。Passed 当且仅当 Reasons 为空。
type Verdict struct {
	Schema          string        `json:"schema"`
	Passed          bool          `json:"passed"`
	Reasons         []string      `json:"reasons"`
	BaseSHA256      string        `json:"base_report_sha256"`
	CandidateSHA256 string        `json:"candidate_report_sha256"`
	Standard        string        `json:"standard_pack_id"`
	Corpus          string        `json:"corpus_sha256"`
	Std             *StdSource    `json:"std,omitempty"`
	Samples         int           `json:"samples"`
	Tiers           []TierVerdict `json:"tiers"`
	Changes         []Change      `json:"changes"`
}

// VerdictSchema 是结论格式版本。
const VerdictSchema = "cdnca.waf-gate-verdict/v1"

// StandardPackID 是标准防护档（逐条结果必须与旧版相同）。
const StandardPackID = "system/crs-pl1"

// Decide 由新旧两份原始报告字节算出 G3 结论：每档拦截率（含挑战）不低于旧版、误报率不高于旧版、
// 标准档（standard）逐条结果完全相同、评测无错误；每条改变结果的样本都列出。两次评测语料相同，
// 所以比较计数即比较比率。
func Decide(baseContent, candidateContent []byte, standard string) (Verdict, error) {
	base, err := Decode(baseContent)
	if err != nil {
		return Verdict{}, err
	}
	candidate, err := Decode(candidateContent)
	if err != nil {
		return Verdict{}, err
	}
	verdict := Verdict{Schema: VerdictSchema, Reasons: []string{}, Changes: []Change{}, Standard: standard,
		BaseSHA256: Digest(baseContent), CandidateSHA256: Digest(candidateContent), Corpus: base.Corpus, Std: base.Std, Samples: len(base.Results)}
	if !sameShape(base, candidate) {
		verdict.Reasons = append(verdict.Reasons, ReasonMismatch)
		return verdict, nil
	}
	reasons := map[string]bool{}
	for index, tier := range base.Tiers {
		row := TierVerdict{PackID: tier.PackID, Name: tier.Name}
		for position, before := range base.Results {
			after := candidate.Results[position]
			from, to := before.Outcome[index], after.Outcome[index]
			if from == Excluded || to == Excluded { // 无应答不计（waf-comparison 口径），两边同样剔除，比率仍可比
				row.Base.Excluded++
				row.Candidate.Excluded++
				continue
			}
			count(&row.Base, before.Attack, from)
			count(&row.Candidate, before.Attack, to)
			if from == to {
				continue
			}
			row.Changed++
			verdict.Changes = append(verdict.Changes, Change{ID: before.ID, Attack: before.Attack, Tier: tier.PackID,
				From: string(from), To: string(to)})
			if tier.PackID == standard {
				reasons[ReasonStandardChanged] = true
			}
		}
		if row.Base.Errors != 0 || row.Candidate.Errors != 0 {
			reasons[ReasonEvalErrors] = true
		}
		if row.Candidate.Blocked < row.Base.Blocked {
			reasons[ReasonBlockRateDrop] = true
		}
		if row.Candidate.FalsePositives > row.Base.FalsePositives {
			reasons[ReasonFalsePosRise] = true
		}
		verdict.Tiers = append(verdict.Tiers, row)
	}
	for reason := range reasons {
		verdict.Reasons = append(verdict.Reasons, reason)
	}
	sort.Strings(verdict.Reasons)
	verdict.Passed = len(verdict.Reasons) == 0
	return verdict, nil
}

// sameShape：同一组档（按包 ID，版本可不同）、同一语料、同样的样本顺序。
func sameShape(base, candidate Report) bool {
	if base.Mode != candidate.Mode || base.Corpus != candidate.Corpus || base.CRSVersion != candidate.CRSVersion || len(base.Tiers) != len(candidate.Tiers) ||
		len(base.Results) != len(candidate.Results) || !sameStd(base.Std, candidate.Std) {
		return false
	}
	for index, tier := range base.Tiers {
		if candidate.Tiers[index].PackID != tier.PackID {
			return false
		}
	}
	for index, result := range base.Results {
		if other := candidate.Results[index]; other.ID != result.ID || other.Attack != result.Attack {
			return false
		}
	}
	return true
}

func sameStd(a, b *StdSource) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Mode == b.Mode && slices.Equal(a.Files, b.Files)
}

func count(tally *TierCount, attack bool, outcome byte) {
	if outcome == Failed {
		tally.Errors++
		return
	}
	hit := outcome == Blocked || outcome == Challenged
	if attack {
		tally.Attacks++
		if hit {
			tally.Blocked++
		}
		return
	}
	tally.Benign++
	if hit {
		tally.FalsePositives++
	}
}
