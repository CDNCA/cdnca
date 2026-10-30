package cluster

import (
	"math"
	"sort"
)

// Evidence 对应 rule_intel_evidence_daily 一行（一个指纹 × 一天 × 一个安装）。
// 同一键出现多行时按相加处理，再封顶。
type Evidence struct {
	Fingerprint  string
	Day          int
	Installation string // installation_hash
	Customer     string
	Weight       float64 // 正向证据
	FP           float64 // 误判反馈 / 驳回证据
	Hits         int64
	// Params 只对 cc_rule_tune：该安装当天上报的建议参数（窗口、阈值等）。
	Params map[string]float64
}

type dayInstall struct {
	day     int
	install string
}

type dayCustomer struct {
	day      int
	customer string
}

type cappedRow struct {
	day      int
	install  string
	customer string
	w, fp    float64
	hits     int64
	params   map[string]float64
}

// CapDaily 按 §5.3 封顶：每安装每天 ≤ PerInstallDailyCap，同一客户多个安装当天
// 合计 ≤ PerCustomerDailyCap（超出按比例缩小）。Weight 与 FP 分别封顶（防一个
// 客户刷出共识，也防一个客户刷误判压掉别人的候选）。输入行属于同一个证据组
// （一个指纹，或一个簇的全部成员）；输出按 (day, installation) 升序。
// RI-09 写 rule_intel_evidence_daily.weight 时对单指纹调用；Run 对合并后的
// 整组再调用一次，所以一个安装刷多个变体也只算一份。
func (c Config) CapDaily(rows []Evidence) []Evidence {
	capped := c.capRows(rows)
	out := make([]Evidence, len(capped))
	for i, r := range capped {
		out[i] = Evidence{Day: r.day, Installation: r.install, Customer: r.customer, Weight: r.w, FP: r.fp, Hits: r.hits, Params: r.params}
	}
	if len(rows) > 0 {
		fp := rows[0].Fingerprint
		for _, r := range rows[1:] {
			if r.Fingerprint != fp {
				fp = ""
				break
			}
		}
		for i := range out {
			out[i].Fingerprint = fp
		}
	}
	return out
}

func (c Config) capRows(rows []Evidence) []cappedRow {
	// 浮点累加与输入顺序有关：先按全键排序，保证同输入不同顺序结果逐位相同。
	rows = append([]Evidence(nil), rows...)
	sort.Slice(rows, func(i, j int) bool {
		a, b := &rows[i], &rows[j]
		switch {
		case a.Day != b.Day:
			return a.Day < b.Day
		case a.Installation != b.Installation:
			return a.Installation < b.Installation
		case a.Customer != b.Customer:
			return a.Customer < b.Customer
		case a.Weight != b.Weight:
			return a.Weight < b.Weight
		case a.FP != b.FP:
			return a.FP < b.FP
		}
		return a.Hits < b.Hits
	})
	byKey := map[dayInstall]*cappedRow{}
	for _, r := range rows {
		k := dayInstall{r.Day, r.Installation}
		cr := byKey[k]
		if cr == nil {
			cr = &cappedRow{day: r.Day, install: r.Installation, customer: r.Customer}
			byKey[k] = cr
		}
		if r.Customer < cr.customer || cr.customer == "" { // 同安装多客户（不应出现）取最小，确定性
			cr.customer = r.Customer
		}
		cr.w += nonneg(r.Weight)
		cr.fp += nonneg(r.FP)
		cr.hits += r.Hits
		if len(r.Params) > 0 {
			if cr.params == nil {
				cr.params = map[string]float64{}
			}
			for k, v := range r.Params { // 同键多行取最大，确定性
				if old, ok := cr.params[k]; !ok || v > old {
					cr.params[k] = v
				}
			}
		}
	}
	out := make([]cappedRow, 0, len(byKey))
	for _, cr := range byKey {
		cr.w = math.Min(cr.w, c.PerInstallDailyCap)
		cr.fp = math.Min(cr.fp, c.PerInstallDailyCap)
		out = append(out, *cr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].day != out[j].day {
			return out[i].day < out[j].day
		}
		return out[i].install < out[j].install
	})
	sumW := map[dayCustomer]float64{}
	sumFP := map[dayCustomer]float64{}
	for _, r := range out {
		k := dayCustomer{r.day, r.customer}
		sumW[k] += r.w
		sumFP[k] += r.fp
	}
	for i := range out {
		k := dayCustomer{out[i].day, out[i].customer}
		if s := sumW[k]; s > c.PerCustomerDailyCap {
			out[i].w *= c.PerCustomerDailyCap / s
		}
		if s := sumFP[k]; s > c.PerCustomerDailyCap {
			out[i].fp *= c.PerCustomerDailyCap / s
		}
	}
	return out
}

func nonneg(v float64) float64 {
	if v > 0 && !math.IsInf(v, 1) {
		return v
	}
	return 0
}

// stats 是一个证据组在 today 的聚合。
type stats struct {
	weight, fp                    float64
	installs7d, installs30d, cust int
	hits                          int64
	lastSeen                      int
	firstSeen                     int
	tune                          map[string]TuneStat
}

// aggregate 封顶后按半衰期衰减求和；只看 (today-EvidenceWindow, today] 的行。
func (c Config) aggregate(rows []Evidence, today int) stats {
	var s stats
	s.lastSeen, s.firstSeen = -1, -1
	inWindow := rows[:0:0]
	for _, r := range rows {
		if r.Day <= today && r.Day > today-c.EvidenceWindow {
			inWindow = append(inWindow, r)
		}
	}
	capped := c.capRows(inWindow)
	inst7, inst30 := map[string]map[string]bool{}, map[string]map[string]bool{}
	latest := map[string]cappedRow{} // 每安装最近一天带参数的行
	for _, r := range capped {
		age := float64(today - r.day)
		s.weight += r.w * math.Pow(0.5, age/c.WeightHalfLife)
		s.fp += r.fp * math.Pow(0.5, age/c.FPHalfLife)
		s.hits += r.hits
		if r.w > 0 {
			if r.day > s.lastSeen {
				s.lastSeen = r.day
			}
			if s.firstSeen < 0 || r.day < s.firstSeen {
				s.firstSeen = r.day
			}
			if today-r.day < 30 {
				addSet(inst30, r.customer, r.install)
			}
			if today-r.day < 7 {
				addSet(inst7, r.customer, r.install)
			}
		}
		if len(r.params) > 0 {
			if old, ok := latest[r.install]; !ok || r.day >= old.day {
				latest[r.install] = r
			}
		}
	}
	s.installs7d = c.effectiveInstalls(inst7)
	s.installs30d = c.effectiveInstalls(inst30)
	s.cust = len(inst30)
	if len(latest) > 0 {
		s.tune = tuneStats(latest)
	}
	return s
}

func addSet(m map[string]map[string]bool, customer, install string) {
	if m[customer] == nil {
		m[customer] = map[string]bool{}
	}
	m[customer][install] = true
}

// effectiveInstalls：每个客户最多计 PerCustomerInstallCap 个安装（单客户多安装刷不出共识）。
func (c Config) effectiveInstalls(m map[string]map[string]bool) int {
	n := 0
	for _, set := range m {
		if len(set) > c.PerCustomerInstallCap {
			n += c.PerCustomerInstallCap
		} else {
			n += len(set)
		}
	}
	return n
}

// tuneStats：每个安装取最近一天的建议值，跨安装取中位数与四分位（线性插值）。
func tuneStats(latest map[string]cappedRow) map[string]TuneStat {
	vals := map[string][]float64{}
	for _, r := range latest {
		for k, v := range r.params {
			if !math.IsNaN(v) && !math.IsInf(v, 0) {
				vals[k] = append(vals[k], v)
			}
		}
	}
	out := make(map[string]TuneStat, len(vals))
	for k, v := range vals {
		sort.Float64s(v)
		out[k] = TuneStat{Median: quantile(v, 0.5), Q1: quantile(v, 0.25), Q3: quantile(v, 0.75), N: len(v)}
	}
	return out
}

func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	if lo >= len(sorted)-1 {
		return sorted[len(sorted)-1]
	}
	frac := pos - float64(lo)
	return sorted[lo] + frac*(sorted[lo+1]-sorted[lo])
}

// WilsonLower / WilsonUpper：二项比例 k/n 的 Wilson 区间端点（n ≤ 0 时 0 / 1）。
func WilsonLower(k, n, z float64) float64 {
	if n <= 0 {
		return 0
	}
	p := k / n
	z2 := z * z
	return math.Max(0, (p+z2/(2*n)-z*math.Sqrt(p*(1-p)/n+z2/(4*n*n)))/(1+z2/n))
}

func WilsonUpper(k, n, z float64) float64 {
	if n <= 0 {
		return 1
	}
	p := k / n
	z2 := z * z
	return math.Min(1, (p+z2/(2*n)+z*math.Sqrt(p*(1-p)/n+z2/(4*n*n)))/(1+z2/n))
}

// confidence = 证据安装数的 Wilson 下界（全部安装都给正向证据：k = n = 30 天有效
// 安装数）× (1 − 误判率 fp/(weight+fp) 的 Wilson 上界)。cc_rule_tune 再乘
// 1/(1 + 平均相对四分位距)：各安装建议值越分散，置信越低。
func (c Config) confidence(s stats) float64 {
	n := float64(s.installs30d)
	conf := WilsonLower(n, n, c.Z) * (1 - WilsonUpper(s.fp, s.weight+s.fp, c.Z))
	if len(s.tune) > 0 {
		var rel float64
		for _, t := range s.tune {
			if t.Median != 0 {
				rel += (t.Q3 - t.Q1) / math.Abs(t.Median)
			}
		}
		conf /= 1 + rel/float64(len(s.tune))
	}
	return conf
}

func fpRatio(weight, fp float64) float64 {
	if weight <= 0 {
		if fp > 0 {
			return math.Inf(1)
		}
		return 0
	}
	return fp / weight
}
