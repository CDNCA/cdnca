package cluster

import (
	"encoding/binary"
	"hash/fnv"
	"sort"
)

// minhashSeed 固定，保证跨进程、跨版本同输入同签名（改动即改变全部簇，禁止随意修改）。
const minhashSeed uint64 = 0x63646e6361524931 // "cdncaRI1"

func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

func seeds(n int) []uint64 {
	s := make([]uint64, n)
	x := minhashSeed
	for i := range s {
		x = splitmix64(x)
		s[i] = x
	}
	return s
}

// Tokens 是候选参与相似度计算的 token 集：每个条件一个 `维度=值`，升序去重。
// （规则号、引擎在 Target 里，聚类只在同 kind + 同 target 内进行。）
func Tokens(conds []Cond) []string {
	out := make([]string, 0, len(conds))
	for _, c := range conds {
		out = append(out, c.Dim+"="+c.Value)
	}
	sort.Strings(out)
	j := 0
	for i, t := range out {
		if i == 0 || t != out[j-1] {
			out[j] = t
			j++
		}
	}
	return out[:j]
}

// MinHash 返回 token 集的 n 个最小哈希（低 32 位，同 rule_intel_clusters.minhash 128×4 字节）。
func MinHash(tokens []string, n int) []uint32 { return minhashWith(tokens, seeds(n)) }

func minhashWith(tokens []string, s []uint64) []uint32 {
	sig := make([]uint32, len(s))
	for i := range sig {
		sig[i] = ^uint32(0)
	}
	for _, t := range tokens {
		h := fnv.New64a()
		h.Write([]byte(t))
		base := h.Sum64()
		for i, seed := range s {
			if v := uint32(splitmix64(base ^ seed)); v < sig[i] {
				sig[i] = v
			}
		}
	}
	return sig
}

// MinHashBytes 是写入 bytea 列的大端编码。
func MinHashBytes(sig []uint32) []byte {
	b := make([]byte, 4*len(sig))
	for i, v := range sig {
		binary.BigEndian.PutUint32(b[4*i:], v)
	}
	return b
}

// BandKeys 把签名切成 bands 段、每段 rows 个值，返回每段的桶键（含段号）。
func BandKeys(sig []uint32, bands, rows int) []uint64 {
	keys := make([]uint64, bands)
	for b := 0; b < bands; b++ {
		h := splitmix64(minhashSeed ^ uint64(b))
		for r := 0; r < rows; r++ {
			h = splitmix64(h ^ uint64(sig[b*rows+r]))
		}
		keys[b] = h
	}
	return keys
}

// Jaccard 计算两个升序 token 集的 Jaccard 系数，并报告 a ⊆ b / b ⊆ a。
func Jaccard(a, b []string) (j float64, aInB, bInA bool) {
	i, k, inter := 0, 0, 0
	for i < len(a) && k < len(b) {
		switch {
		case a[i] == b[k]:
			inter++
			i++
			k++
		case a[i] < b[k]:
			i++
		default:
			k++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 1, true, true
	}
	return float64(inter) / float64(union), inter == len(a), inter == len(b)
}

// similarPairs 在一组候选内用 LSH 找碰撞对，再用精确 Jaccard 过滤：
// J ≥ threshold 才成边（包含关系只在簇内判定，ADR §5.2 第 3、4 步）。返回的边 (i<j) 已升序去重。
func similarPairs(tokens [][]string, sigs [][]uint32, cfg Config) [][2]int {
	buckets := map[uint64][]int{}
	for i, sig := range sigs {
		for _, k := range BandKeys(sig, cfg.Bands, cfg.Rows) {
			buckets[k] = append(buckets[k], i)
		}
	}
	seen := map[[2]int]bool{}
	var edges [][2]int
	for _, members := range buckets {
		for x := 0; x < len(members); x++ {
			for y := x + 1; y < len(members); y++ {
				p := [2]int{members[x], members[y]}
				if p[0] > p[1] {
					p[0], p[1] = p[1], p[0]
				}
				if p[0] == p[1] || seen[p] {
					continue
				}
				seen[p] = true
				if j, _, _ := Jaccard(tokens[p[0]], tokens[p[1]]); j >= cfg.Jaccard {
					edges = append(edges, p)
				}
			}
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i][0] != edges[j][0] {
			return edges[i][0] < edges[j][0]
		}
		return edges[i][1] < edges[j][1]
	})
	return edges
}
