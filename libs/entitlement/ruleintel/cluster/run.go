package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Input 是一次运行（每天一次）的全部输入。Candidates 是全部已知候选（含已发布、
// 已合并、已过期、已驳回、已隔离），Evidence 是窗口内全部证据行（单指纹已按
// CapDaily 封顶或未封顶均可，Run 会按合并后的整组重新封顶）。
type Input struct {
	Today      int
	Candidates []Candidate
	Evidence   []Evidence
	Tombstones []Tombstone
}

// Output 是运行结果；Candidates 按指纹升序，含本次新合成的类别级候选。
type Output struct {
	Candidates []Candidate
	Clusters   []Cluster
	// Archive 是本次新产生的、必须永久写入语料库的样本（按指纹升序）。
	Archive []ArchiveItem
	// Pool 是运行后未发布候选池（new/ready/drafted，非变体）各 kind 的数量。
	Pool      map[Kind]int
	PoolTotal int
}

// ErrConfig：参数不自洽（如 Bands×Rows ≠ NumHashes）。
var ErrConfig = errors.New("ruleintel/cluster: invalid config")

// ErrDuplicate：输入里同一指纹出现两次。
var ErrDuplicate = errors.New("ruleintel/cluster: duplicate fingerprint")

// Blocked 报告指纹当前是否被墓碑挡住（RI-09 摄取时调用：被挡住的不建候选行）。
func Blocked(tombs []Tombstone, fingerprint string, today int) bool {
	for _, t := range tombs {
		if t.Fingerprint == fingerprint && t.active(today) {
			return true
		}
	}
	return false
}

// ParseCanonical 从库里的 kind/target/canonical 列还原 Canon 并复算指纹。
func ParseCanonical(kind Kind, target Target, canonical []byte) (Canon, error) {
	var doc struct {
		Conds [][2]string `json:"conds"`
	}
	if err := json.Unmarshal(canonical, &doc); err != nil {
		return Canon{}, fmt.Errorf("%w: canonical: %v", ErrInvalid, err)
	}
	if !kind.valid() {
		return Canon{}, fmt.Errorf("%w: kind %q", ErrInvalid, kind)
	}
	conds := make([]Cond, len(doc.Conds))
	for i, p := range doc.Conds {
		conds[i] = Cond{p[0], p[1]}
	}
	if len(conds) == 0 {
		return Canon{}, ErrEmpty
	}
	sortConds(conds)
	return finish(kind, target, conds)
}

func (c Config) validate() error {
	if c.NumHashes <= 0 || c.Bands <= 0 || c.Rows <= 0 || c.Bands*c.Rows != c.NumHashes {
		return fmt.Errorf("%w: bands %d × rows %d ≠ hashes %d", ErrConfig, c.Bands, c.Rows, c.NumHashes)
	}
	if c.WeightHalfLife <= 0 || c.FPHalfLife <= 0 || c.EvidenceWindow <= 0 || c.PerInstallDailyCap <= 0 || c.PerCustomerDailyCap <= 0 || c.PerCustomerInstallCap <= 0 {
		return fmt.Errorf("%w: non-positive decay/cap", ErrConfig)
	}
	return nil
}

func pinned(s State) bool { return s == StateReleased || s == StateDrafted }

func inUniverse(s State) bool { return s.unpublished() || s == StateReleased }

type node struct {
	idx    int // 在 cands 中的下标
	tokens []string
	sig    []uint32
	pre    stats
	score  float64
}

// Run 执行一次确定性的去重合并、打分、状态推进与容量淘汰。
func (c Config) Run(in Input) (Output, error) {
	if err := c.validate(); err != nil {
		return Output{}, err
	}
	today := in.Today
	cands := make([]Candidate, len(in.Candidates))
	copy(cands, in.Candidates)
	sort.Slice(cands, func(i, j int) bool { return cands[i].Fingerprint < cands[j].Fingerprint })
	idx := make(map[string]int, len(cands))
	in0 := make(map[string]struct{}, len(cands)) // 输入里已有的指纹
	for i := range cands {
		fp := cands[i].Fingerprint
		if _, dup := idx[fp]; dup {
			return Output{}, fmt.Errorf("%w: %s", ErrDuplicate, fp)
		}
		idx[fp] = i
		in0[fp] = struct{}{}
		cands[i].Variants = nil
		cands[i].GeneralizationOf = ""
	}
	tombs := map[string]Tombstone{}
	for _, t := range in.Tombstones {
		old, ok := tombs[t.Fingerprint]
		if !ok || t.Permanent || (!old.Permanent && t.Until > old.Until) {
			tombs[t.Fingerprint] = t
		}
	}
	blocked := func(fp string) bool { t, ok := tombs[fp]; return ok && t.active(today) }
	rowsBy := map[string][]Evidence{}
	for _, e := range in.Evidence {
		if _, ok := idx[e.Fingerprint]; ok {
			rowsBy[e.Fingerprint] = append(rowsBy[e.Fingerprint], e)
		}
	}

	// 0. 解析已有变体链（指向缺失或成环的视为根）。
	root := make([]int, len(cands))
	for i := range cands {
		root[i] = -1
	}
	var resolve func(i int, depth int) int
	resolve = func(i, depth int) int {
		if root[i] >= 0 {
			return root[i]
		}
		j, ok := idx[cands[i].MergedInto]
		if cands[i].MergedInto == "" || !ok || j == i || depth > len(cands) {
			cands[i].MergedInto = ""
			root[i] = i
			return i
		}
		root[i] = resolve(j, depth+1)
		return root[i]
	}
	for i := range cands {
		resolve(i, 0)
	}
	family := map[int][]int{}
	for i := range cands {
		family[root[i]] = append(family[root[i]], i)
	}
	famRows := func(r int) []Evidence {
		var rows []Evidence
		for _, m := range family[r] {
			rows = append(rows, rowsBy[cands[m].Fingerprint]...)
		}
		return rows
	}

	// 1. 墓碑与恢复（只看根）。
	for i := range cands {
		cd := &cands[i]
		if root[i] != i || cd.State == StateReleased {
			continue
		}
		if blocked(cd.Fingerprint) {
			if cd.State != StateRejected {
				cd.State, cd.StateDay = StateRejected, today
			}
			continue
		}
		if cd.State == StateExpired || cd.State == StateRejected {
			for _, e := range famRows(i) {
				if e.Day > cd.StateDay && e.Day <= today && e.Weight > 0 {
					cd.State, cd.StateDay, cd.PoolSince = StateNew, today, today
					break
				}
			}
		}
	}

	// 2. 按 kind + target 分组聚类合并。
	groups := map[string][]int{}
	for i := range cands {
		if root[i] == i && inUniverse(cands[i].State) {
			k := string(cands[i].Kind) + "\x00" + cands[i].Target.key()
			groups[k] = append(groups[k], i)
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var archive []ArchiveItem
	dropped := map[int]bool{} // 本次合成但什么都没吸收的类别级候选：不输出
	seedv := seeds(c.NumHashes)
	sigOf := map[int][]uint32{}
	for _, k := range keys {
		members := groups[k]
		// 2a. 类别级合成（waf_exclusion 同规则同值类型、同字典类别的不同参数名）。
		if cands[members[0]].Kind == KindWAFExclusion {
			for _, s := range c.synthesize(cands, members, idx, blocked, today) {
				cands = append(cands, s)
				i := len(cands) - 1
				idx[s.Fingerprint] = i
				root = append(root, i)
				family[i] = []int{i}
				members = append(members, i)
			}
		}
		nodes := make([]node, len(members))
		for n, i := range members {
			toks := Tokens(cands[i].Conds)
			nodes[n] = node{idx: i, tokens: toks, sig: minhashWith(toks, seedv)}
			sigOf[i] = nodes[n].sig
		}
		post := map[string][]int{}
		for n := range nodes {
			for _, t := range nodes[n].tokens {
				post[t] = append(post[t], n)
			}
		}
		// 预统计：自身家族；合成候选另含它所包含的全部根的家族。
		for n := range nodes {
			rows := famRows(nodes[n].idx)
			if cands[nodes[n].idx].Synthetic {
				for _, b := range supersets(nodes, post, n) {
					rows = append(rows, famRows(nodes[b].idx)...)
				}
			}
			nodes[n].pre = c.statsFor(rows, cands[nodes[n].idx].State, today)
			nodes[n].score = nodes[n].pre.weight * c.confidence(nodes[n].pre)
		}
		mergeTo := c.absorb(cands, nodes, post)
		c.nearDup(cands, nodes, mergeTo)
		final := func(n int) int {
			for d := 0; mergeTo[n] >= 0 && d <= len(nodes); d++ {
				n = mergeTo[n]
			}
			return n
		}
		for n := range nodes {
			f := final(n)
			if f == n {
				continue
			}
			from, to := nodes[n].idx, nodes[f].idx
			for _, m := range family[from] {
				if _, existed := in0[cands[m].Fingerprint]; m == from && existed {
					st := c.statsFor(famRows(from), cands[from].State, today)
					archive = append(archive, ArchiveItem{
						Source: ArchiveVariant, Kind: cands[from].Kind, Target: cands[from].Target,
						Fingerprint: cands[from].Fingerprint, Conds: cands[from].Conds, Canonical: cands[from].Canonical,
						MergedInto: cands[to].Fingerprint, Weight: st.weight, FPWeight: st.fp, Installs30d: st.installs30d, LastSeen: maxInt(st.lastSeen, cands[from].LastSeen),
					})
				}
				cands[m].MergedInto = cands[to].Fingerprint
				root[m] = to
			}
			family[to] = append(family[to], family[from]...)
			delete(family, from)
		}
		// 本次新合成的类别级候选：没吸收到任何变体，或自身又被更通用者吸收 → 不输出。
		for _, n := range nodes {
			i := n.idx
			if _, existed := in0[cands[i].Fingerprint]; !existed && (root[i] != i || len(family[i]) == 1) {
				dropped[i] = true
			}
		}
	}

	// 3. 证据累加、打分、状态推进（根）。
	var pool []int
	for i := range cands {
		cd := &cands[i]
		if root[i] != i || dropped[i] {
			continue
		}
		cd.ClusterID = cd.Fingerprint
		fam := append([]int(nil), family[i]...)
		sort.Slice(fam, func(a, b int) bool { return cands[fam[a]].Fingerprint < cands[fam[b]].Fingerprint })
		for _, m := range fam {
			if m != i && !dropped[m] {
				cd.Variants = append(cd.Variants, Variant{Fingerprint: cands[m].Fingerprint, Conds: cands[m].Conds, Canonical: cands[m].Canonical})
				cands[m].ClusterID = cd.Fingerprint
			}
		}
		if !inUniverse(cd.State) && cd.State != StateQuarantined {
			continue // 已驳回 / 已过期：保持原证据快照
		}
		st := c.statsFor(famRows(i), cd.State, today)
		cd.Weight, cd.FPWeight, cd.Hits = st.weight, st.fp, st.hits
		cd.Installs7d, cd.Installs30d, cd.Customers30d = st.installs7d, st.installs30d, st.cust
		cd.LastSeen = maxInt(cd.LastSeen, st.lastSeen)
		if st.firstSeen >= 0 && (cd.FirstSeen == 0 || st.firstSeen < cd.FirstSeen) {
			cd.FirstSeen = st.firstSeen
		}
		cd.Tune = nil
		if cd.Kind == KindCCRuleTune {
			cd.Tune = st.tune
		}
		cd.Confidence = c.confidence(st)
		cd.Score = cd.Weight * cd.Confidence
		if !cd.State.unpublished() {
			continue
		}
		ratio := fpRatio(st.weight, st.fp)
		since := cd.PoolSince
		if since == 0 {
			since = cd.FirstSeen
		}
		switch {
		case (st.weight > 0 || st.fp > 0) && ratio > c.QuarantineFPRatio:
			cd.State, cd.StateDay = StateQuarantined, today
		case today-since >= c.ExpireDays && st.weight < c.ExpireWeight:
			archive = append(archive, c.expire(cd, "decay", today))
		case cd.State == StateNew && c.ready(cd, st, ratio, today):
			cd.State, cd.StateDay = StateReady, today
		case cd.State == StateReady && !c.ready(cd, st, ratio, today):
			cd.State, cd.StateDay = StateNew, today
		}
		if cd.State.unpublished() {
			pool = append(pool, i)
		}
	}

	// 4. 容量淘汰：先每 kind，再总量。drafted 最后淘汰，其余 score 低者先。
	less := func(a, b int) bool {
		x, y := &cands[a], &cands[b]
		if (x.State == StateDrafted) != (y.State == StateDrafted) {
			return y.State == StateDrafted
		}
		if x.Score != y.Score {
			return x.Score < y.Score
		}
		if x.LastSeen != y.LastSeen {
			return x.LastSeen < y.LastSeen
		}
		return x.Fingerprint < y.Fingerprint
	}
	sort.Slice(pool, func(a, b int) bool { return less(pool[a], pool[b]) })
	byKind := map[Kind]int{}
	for _, i := range pool {
		byKind[cands[i].Kind]++
	}
	var kept []int
	for _, i := range pool { // 升序：从最该淘汰的开始
		k := cands[i].Kind
		if byKind[k] > c.KindCap {
			byKind[k]--
			archive = append(archive, c.expire(&cands[i], "capacity", today))
			continue
		}
		kept = append(kept, i)
	}
	for over := len(kept) - c.TotalCap; over > 0; over-- {
		i := kept[0]
		kept = kept[1:]
		byKind[cands[i].Kind]--
		archive = append(archive, c.expire(&cands[i], "capacity", today))
	}

	out := Output{Pool: map[Kind]int{}}
	for k, n := range byKind {
		if n > 0 {
			out.Pool[k] = n
		}
	}
	out.PoolTotal = len(kept)
	// 输出：候选按指纹升序（含新合成的）。
	order := make([]int, len(cands))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return cands[order[a]].Fingerprint < cands[order[b]].Fingerprint })
	out.Candidates = make([]Candidate, 0, len(cands))
	for _, i := range order {
		if dropped[i] {
			continue
		}
		out.Candidates = append(out.Candidates, cands[i])
		cd := &cands[i]
		if root[i] == i && len(cd.Variants) > 0 && inUniverse(cd.State) {
			members := []string{cd.Fingerprint}
			for _, v := range cd.Variants {
				members = append(members, v.Fingerprint)
			}
			sort.Strings(members)
			sig := sigOf[i]
			if sig == nil {
				sig = minhashWith(Tokens(cd.Conds), seedv)
			}
			out.Clusters = append(out.Clusters, Cluster{ID: cd.Fingerprint, Kind: cd.Kind, Representative: cd.Fingerprint, Members: members, MinHash: sig})
		}
	}
	sort.Slice(archive, func(a, b int) bool {
		if archive[a].Fingerprint != archive[b].Fingerprint {
			return archive[a].Fingerprint < archive[b].Fingerprint
		}
		return archive[a].Source < archive[b].Source
	})
	out.Archive = archive
	return out, nil
}

// statsFor：已发布候选不衰减（ADR §5.3），其余按半衰期衰减。
func (c Config) statsFor(rows []Evidence, state State, today int) stats {
	if state == StateReleased {
		c.WeightHalfLife, c.FPHalfLife = math.Inf(1), math.Inf(1)
	}
	return c.aggregate(rows, today)
}

func (c Config) ready(cd *Candidate, st stats, ratio float64, today int) bool {
	need := c.ReadyInstalls
	if cd.Kind == KindWAFExclusion {
		need = c.ReadyInstallsExclusion
	}
	return st.installs30d >= need && st.cust >= c.ReadyCustomers &&
		st.lastSeen > today-c.ReadyRecentDays && ratio <= c.ReadyMaxFPRatio
}

func (c Config) expire(cd *Candidate, reason string, today int) ArchiveItem {
	cd.State, cd.StateDay = StateExpired, today
	return ArchiveItem{
		Source: ArchiveExpired, Kind: cd.Kind, Target: cd.Target, Fingerprint: cd.Fingerprint,
		Conds: cd.Conds, Canonical: cd.Canonical, Reason: reason,
		Weight: cd.Weight, FPWeight: cd.FPWeight, Installs30d: cd.Installs30d, LastSeen: cd.LastSeen,
	}
}

// supersets 返回包含节点 n 全部 token 且更多的节点（真超集）。
func supersets(nodes []node, post map[string][]int, n int) []int {
	toks := nodes[n].tokens
	if len(toks) == 0 {
		return nil
	}
	// 从最短的倒排表起步，逐个检查。
	best := post[toks[0]]
	for _, t := range toks[1:] {
		if len(post[t]) < len(best) {
			best = post[t]
		}
	}
	var out []int
	for _, b := range best {
		if b == n || len(nodes[b].tokens) <= len(toks) {
			continue
		}
		if _, aInB, _ := Jaccard(toks, nodes[b].tokens); aInB {
			out = append(out, b)
		}
	}
	return out
}

// absorb 处理包含关系（ADR §5.2 第 4 步第 1 条）：A ⊊ B，A 的误判率不高于 B 的
// AbsorbFPFactor 倍且 A 的有效安装数 ≥ B（或 A 已发布）→ B 并入 A（取最通用的 A）；否则
// 保留 B，A 标为 B 的通用化候选。返回 mergeTo[n]（-1 = 不合并）。
func (c Config) absorb(cands []Candidate, nodes []node, post map[string][]int) []int {
	mergeTo := make([]int, len(nodes))
	for n := range mergeTo {
		mergeTo[n] = -1
	}
	type gen struct{ a, b int }
	var gens []gen
	for a := range nodes {
		for _, b := range supersets(nodes, post, a) {
			if pinned(cands[nodes[b].idx].State) {
				continue
			}
			ra := fpRatio(nodes[a].pre.weight, nodes[a].pre.fp)
			rb := fpRatio(nodes[b].pre.weight, nodes[b].pre.fp)
			// 已发布的通用规则已经覆盖 B，B 无条件并入（证据累加到已发布代表上）。
			if cands[nodes[a].idx].State == StateReleased || (ra <= c.AbsorbFPFactor*rb && nodes[a].pre.installs30d >= nodes[b].pre.installs30d) {
				if cur := mergeTo[b]; cur < 0 || betterAbsorber(cands, nodes, a, cur) {
					mergeTo[b] = a
				}
			} else {
				gens = append(gens, gen{a, b})
			}
		}
	}
	// 通用化标记：A 未被合并时，指向证据最多、未被合并的 B。
	bestB := map[int]int{}
	for _, g := range gens {
		if mergeTo[g.b] >= 0 {
			continue
		}
		cur, ok := bestB[g.a]
		if !ok || nodes[g.b].pre.installs30d > nodes[cur].pre.installs30d ||
			(nodes[g.b].pre.installs30d == nodes[cur].pre.installs30d && cands[nodes[g.b].idx].Fingerprint < cands[nodes[cur].idx].Fingerprint) {
			bestB[g.a] = g.b
		}
	}
	for a, b := range bestB {
		if mergeTo[a] < 0 {
			cands[nodes[a].idx].GeneralizationOf = cands[nodes[b].idx].Fingerprint
		}
	}
	return mergeTo
}

// betterAbsorber：更通用（token 少）> 已发布 > score 高 > 指纹小。
func betterAbsorber(cands []Candidate, nodes []node, a, b int) bool {
	if la, lb := len(nodes[a].tokens), len(nodes[b].tokens); la != lb {
		return la < lb
	}
	return betterRep(cands, nodes, a, b)
}

// betterRep：已发布 > 草稿 > score 高 > 有效安装多 > token 少 > 指纹小。
func betterRep(cands []Candidate, nodes []node, a, b int) bool {
	rank := func(s State) int {
		switch s {
		case StateReleased:
			return 2
		case StateDrafted:
			return 1
		}
		return 0
	}
	x, y := &cands[nodes[a].idx], &cands[nodes[b].idx]
	if rx, ry := rank(x.State), rank(y.State); rx != ry {
		return rx > ry
	}
	if nodes[a].score != nodes[b].score {
		return nodes[a].score > nodes[b].score
	}
	if nodes[a].pre.installs30d != nodes[b].pre.installs30d {
		return nodes[a].pre.installs30d > nodes[b].pre.installs30d
	}
	if la, lb := len(nodes[a].tokens), len(nodes[b].tokens); la != lb {
		return la < lb
	}
	return x.Fingerprint < y.Fingerprint
}

// nearDup：未被包含合并、未钉住的节点按 LSH + Jaccard 连通分量，代表按
// betterRep，其余成员并入代表。cc_rule_tune 同一官方规则整组一个簇。
func (c Config) nearDup(cands []Candidate, nodes []node, mergeTo []int) {
	var live []int
	for n := range nodes {
		// 钉住（已发布/草稿）的不参与近似合并：近似但不包含的变体并不被已发布规则覆盖。
		if mergeTo[n] < 0 && !pinned(cands[nodes[n].idx].State) {
			live = append(live, n)
		}
	}
	if len(live) < 2 {
		return
	}
	parent := make([]int, len(live))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra < rb {
			parent[rb] = ra
		} else if rb < ra {
			parent[ra] = rb
		}
	}
	if cands[nodes[live[0]].idx].Kind == KindCCRuleTune {
		for i := 1; i < len(live); i++ {
			union(0, i)
		}
	} else {
		toks := make([][]string, len(live))
		sigs := make([][]uint32, len(live))
		for i, n := range live {
			toks[i], sigs[i] = nodes[n].tokens, nodes[n].sig
		}
		for _, e := range similarPairs(toks, sigs, c) {
			union(e[0], e[1])
		}
	}
	rep := map[int]int{}
	for i, n := range live {
		r := find(i)
		if cur, ok := rep[r]; !ok || betterRep(cands, nodes, n, cur) {
			rep[r] = n
		}
	}
	for i, n := range live {
		if r := rep[find(i)]; r != n {
			mergeTo[n] = r
		}
	}
}

// synthesize 为 waf_exclusion 合成类别级排除：同组内 ≥2 个根去掉参数名后
// 条件相同且带 param.class → 生成（或复用已有的）类别级候选。已存在但不在
// 活跃池（过期/驳回/隔离/已并入）或被墓碑挡住的不合成。
func (c Config) synthesize(cands []Candidate, members []int, idx map[string]int, blocked func(string) bool, today int) []Candidate {
	byResidual := map[string][]Cond{}
	count := map[string]int{}
	for _, i := range members {
		var residual []Cond
		named, classed := false, false
		for _, cd := range cands[i].Conds {
			switch cd.Dim {
			case DimParamName, DimParamHash:
				named = true
				continue
			case DimParamClass:
				classed = true
			}
			residual = append(residual, cd)
		}
		if !named || !classed {
			continue
		}
		k := condsKey(residual)
		byResidual[k] = residual
		count[k]++
	}
	keys := make([]string, 0, len(count))
	for k, n := range count {
		if n >= 2 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var out []Candidate
	for _, k := range keys {
		first := cands[members[0]]
		canon, err := finish(first.Kind, first.Target, byResidual[k])
		if err != nil {
			continue
		}
		if _, exists := idx[canon.Fingerprint]; exists || blocked(canon.Fingerprint) {
			continue // 已在池中则作为普通根参与；不在池中的尊重其状态
		}
		out = append(out, Candidate{Canon: canon, State: StateNew, StateDay: today, PoolSince: today, FirstSeen: today, Synthetic: true})
	}
	return out
}

func condsKey(conds []Cond) string {
	var b strings.Builder
	for _, c := range conds {
		b.WriteString(c.Dim)
		b.WriteByte(0)
		b.WriteString(c.Value)
		b.WriteByte(1)
	}
	return b.String()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
