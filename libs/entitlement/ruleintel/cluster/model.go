package cluster

// State 是候选状态（ADR 0011 §5.4）。
type State string

const (
	StateNew         State = "new"
	StateReady       State = "ready"
	StateDrafted     State = "drafted"
	StateReleased    State = "released"
	StateRejected    State = "rejected"
	StateExpired     State = "expired"
	StateQuarantined State = "quarantined"
)

// unpublished 是参与衰减、过期与容量的“未发布候选池”状态。
func (s State) unpublished() bool {
	return s == StateNew || s == StateReady || s == StateDrafted
}

// Candidate 对应 rule_intel_candidates 一行。日期一律是 UTC 天序号
// （Unix 秒 / 86400），由调用方换算；本库不读时钟。
type Candidate struct {
	Canon

	State     State
	StateDay  int // 最近一次状态变化的天
	PoolSince int // 进入（或恢复进入）活跃池的天，过期判定从此起算
	FirstSeen int
	LastSeen  int

	// MergedInto 非空 = 已合并进该指纹（变体），不再计入活跃池。
	MergedInto string
	// ClusterID = 所在簇代表的指纹（Run 输出时填写；独立候选为自身）。
	ClusterID string
	// GeneralizationOf 非空 = 本候选是该指纹的“通用化候选”，证据不足以吸收它，待人工。
	GeneralizationOf string
	// Synthetic = 由同规则多参数合成的类别级候选。
	Synthetic bool

	Weight       float64 // 衰减后证据量（含已合并变体）
	FPWeight     float64 // 衰减后误判证据量
	Confidence   float64
	Score        float64
	Installs7d   int // 有效安装数（每客户最多计 Config.PerCustomerInstallCap 个）
	Installs30d  int
	Customers30d int
	Hits         int64

	// Variants 是并入本候选的全部变体（永久保留，含间接并入的）。
	Variants []Variant
	// Tune 只对 cc_rule_tune：各建议参数在安装间的中位数与四分位距。
	Tune map[string]TuneStat
}

// Variant 是一个被合并变体的规范形式（供归档与页面展示）。
type Variant struct {
	Fingerprint string
	Conds       []Cond
	Canonical   []byte
}

// TuneStat 是 CC 调参建议值的跨安装分布。
type TuneStat struct {
	Median float64
	Q1     float64
	Q3     float64
	N      int
}

// ArchiveSource 对应 rule_intel_corpus.source。
type ArchiveSource string

const (
	ArchiveVariant ArchiveSource = "intel_variant"
	ArchiveExpired ArchiveSource = "intel_expired"
)

// ArchiveItem 是本次运行新产生的、必须永久写入语料库的样本（调用方按
// 规范形式生成合成复现请求后写入）。同一指纹只在状态转换的那次运行输出一次。
type ArchiveItem struct {
	Source      ArchiveSource
	Kind        Kind
	Target      Target
	Fingerprint string
	Conds       []Cond
	Canonical   []byte
	MergedInto  string // 仅 intel_variant
	Reason      string // 仅 intel_expired："decay" / "capacity"
	// 最后证据摘要
	Weight      float64
	FPWeight    float64
	Installs30d int
	LastSeen    int
}

// Tombstone 对应 rule_intel_tombstones；Permanent 时 Until 无意义。
type Tombstone struct {
	Fingerprint string
	Until       int
	Permanent   bool
}

func (t Tombstone) active(today int) bool { return t.Permanent || t.Until >= today }

// Cluster 对应 rule_intel_clusters 一行（成员 ≥ 2 的簇才输出）。
type Cluster struct {
	ID             string // = 代表指纹
	Kind           Kind
	Representative string
	Members        []string // 含代表与变体，按指纹升序
	MinHash        []uint32 // 代表的签名，NumHashes 个
}

// Config 是 §5.2/§5.3 的参数；DefaultConfig 给出 ADR 默认值。
type Config struct {
	NumHashes, Bands, Rows int
	Jaccard                float64

	WeightHalfLife, FPHalfLife float64 // 天
	EvidenceWindow             int     // 天：只看 (today-窗口, today] 的证据

	KindCap, TotalCap int

	ReadyInstalls, ReadyInstallsExclusion, ReadyCustomers, ReadyRecentDays int
	ReadyMaxFPRatio, QuarantineFPRatio                                     float64
	ExpireDays                                                             int
	ExpireWeight                                                           float64

	PerInstallDailyCap, PerCustomerDailyCap float64
	PerCustomerInstallCap                   int

	TombstoneDays, PermanentAfter int

	Z              float64 // Wilson 区间 z 值
	AbsorbFPFactor float64 // 通用候选误判率 ≤ 具体候选 × 该倍数才吸收
}

// DefaultConfig 返回 ADR 0011 §5.2/§5.3 的默认值。
func DefaultConfig() Config {
	return Config{
		NumHashes: 128, Bands: 32, Rows: 4, Jaccard: 0.8,
		WeightHalfLife: 30, FPHalfLife: 90, EvidenceWindow: 90,
		KindCap: 5000, TotalCap: 20000,
		ReadyInstalls: 5, ReadyInstallsExclusion: 10, ReadyCustomers: 2, ReadyRecentDays: 14,
		ReadyMaxFPRatio: 0.01, QuarantineFPRatio: 0.05,
		ExpireDays: 30, ExpireWeight: 0.5,
		PerInstallDailyCap: 1, PerCustomerDailyCap: 2, PerCustomerInstallCap: 2,
		TombstoneDays: 180, PermanentAfter: 3,
		Z: 1.96, AbsorbFPFactor: 1.5,
	}
}

// Reject 生成运营驳回后的墓碑：priorRejects 是该指纹此前被驳回的次数。
// 180 天；累计第 3 次起永久（§5.3）。
func (c Config) Reject(fingerprint string, priorRejects, today int) Tombstone {
	if priorRejects+1 >= c.PermanentAfter {
		return Tombstone{Fingerprint: fingerprint, Permanent: true}
	}
	return Tombstone{Fingerprint: fingerprint, Until: today + c.TombstoneDays}
}
