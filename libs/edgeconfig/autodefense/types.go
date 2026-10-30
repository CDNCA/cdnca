package autodefense

// SiteMode is the plugin mode of one site (ADR 0010 section 9.3; Q5: a new
// site of a licensed installation starts in learning). A site that is off is
// not in the snapshot.
type SiteMode string

const (
	// SiteLearning: collect and learn the baseline only (no verdicts shown).
	SiteLearning SiteMode = "learning"
	// SiteObserve: learn, judge and suggest (verdicts, signatures in shadow),
	// never mitigate.
	SiteObserve SiteMode = "observe"
	// SiteProtect: automatic mitigation (needs Snapshot.AutoMitigation).
	SiteProtect SiteMode = "protect"
)

// Sensitivity selects the band multiplier k (section 4.3: low 8, medium 6,
// high 4).
type Sensitivity string

const (
	SensitivityLow    Sensitivity = "low"
	SensitivityMedium Sensitivity = "medium"
	SensitivityHigh   Sensitivity = "high"
)

// BandK is the MAD multiplier of a sensitivity.
func (s Sensitivity) BandK() int64 {
	switch s {
	case SensitivityLow:
		return 8
	case SensitivityMedium:
		return 6
	case SensitivityHigh:
		return 4
	}
	return 0
}

// Site is the automatic defense state of one site.
type Site struct {
	SiteID      string      `json:"site_id"`
	TenantID    string      `json:"tenant_id"`
	Mode        SiteMode    `json:"mode"`
	Sensitivity Sensitivity `json:"sensitivity"`
	// MaxLevel is the mitigation ceiling as an overlay item (field
	// site.max_level, section 7.1, Q3): unlocked it is LevelXDP (no default
	// ceiling, the ladder may climb to kernel ban and XDP); locked it is the
	// manual level until a person chooses "auto" again.
	MaxLevel Item `json:"max_level"`
	// ObserveUntil: after a one-click release the site only observes until
	// this Unix second (section 7.4); 0 = not held.
	ObserveUntil int64 `json:"observe_until,omitempty"`
	// CrossSite: the tenant federation of section 8.3 (L3 on >= 2 sites of
	// the tenant gives L2 on all of them) applies to this site.
	CrossSite bool `json:"cross_site"`
	// PriorClass: the volume class of the global prior (Snapshot.Prior) a site the node has never learned starts
	// from, chosen by the control plane from the site's traffic; empty = the first class.
	PriorClass string     `json:"prior_class,omitempty"`
	Circuit    Circuit    `json:"circuit"`
	Baseline   Baseline   `json:"baseline"`
	Whitelist  Whitelist  `json:"whitelist"`
	Login      []Endpoint `json:"login,omitempty"`
	// Modules are the site-level modules (cc, waf, scan, bot) in name order;
	// a module that is absent runs on its manual values.
	Modules     []Module     `json:"modules,omitempty"`
	Signatures  []Signature  `json:"signatures,omitempty"`
	Mitigations []Mitigation `json:"mitigations,omitempty"`
	// Releases: single releases of the last MaxMitigationSeconds (section
	// 7.4 单条解除, SEC-CONTROL-RECOVERY-01): the node drops what it holds on
	// its own for the target since before At (its local entry, the JA4 list
	// entry, the kernel ban it wrote); a later attack is mitigated again.
	Releases []Release `json:"releases,omitempty"`
	// WAFAdapt: the adaptive WAF state (ADR 0011 section 3.10); absent = the
	// site has no adaptive WAF (not a dynamic routing managed WAF site, or
	// the waf module is not on).
	WAFAdapt *WAFAdapt `json:"waf_adapt,omitempty"`
}

// CircuitState is the control plane view of the site's circuit breaker
// (section 10.2). A node may also break on its own (agent reasons); it
// reports that and never waits for the control plane to close it.
type CircuitState string

const (
	CircuitClosed CircuitState = "closed"
	CircuitOpen   CircuitState = "open"
)

// Circuit reasons (section 10.2 items 1-5).
const (
	CircuitReasonAgent         = "agent_fault"
	CircuitReasonBaselineStale = "baseline_stale"
	CircuitReasonFalsePositive = "false_positive_limit"
	CircuitReasonWholeSite     = "whole_site_mitigated"
	CircuitReasonDelivery      = "delivery_failure"
)

type Circuit struct {
	State CircuitState `json:"state"`
	// Reason and Since are set when open.
	Reason string `json:"reason,omitempty"`
	Since  int64  `json:"since,omitempty"`
	// ManualResume: the second break within 24 hours (Q6) needs a person
	// to resume; otherwise the control plane closes it 30 minutes after the
	// reason is gone.
	ManualResume bool `json:"manual_resume,omitempty"`
}

// PriorMetrics are the per site numeric metrics of the node's baseline row (agent sketch rows, in this order),
// the features a global prior may set. Rates are per second, ratios are fractions, latencies are milliseconds;
// a prior band carries them x1000.
var PriorMetrics = []string{"request_rate", "byte_rate", "ratio_4xx", "ratio_404", "ratio_5xx", "cache_hit",
	"upstream_error", "latency_p95", "latency_p99", "upstream_timeout"}

// MaxPriorClasses bounds the classes of one prior.
const MaxPriorClasses = 16

// Prior is the global prior file (section 4.3 item 1): classes by site volume, one shared by every site.
type Prior struct {
	// Version grows with every new prior the platform issues.
	Version uint64       `json:"version"`
	Classes []PriorClass `json:"classes"`
}

// PriorClass is one volume class: sites up to MaxRequestMilli requests a second x1000 (0 = no upper bound, the
// last class). Classes ascend by MaxRequestMilli, the unbounded one last.
type PriorClass struct {
	Class           string      `json:"class"`
	MaxRequestMilli int64       `json:"max_request_milli"`
	Bands           []PriorBand `json:"bands"`
}

// PriorBand is one metric (PriorMetrics) of a class: median and MAD x1000.
type PriorBand struct {
	Metric string `json:"metric"`
	P50    int64  `json:"p50"`
	MAD    int64  `json:"mad"`
}

// Maturity is the baseline stage of a site (section 4.3 cold start).
type Maturity string

const (
	// MaturityPrior: layered prior only; bands are 3x wide and verdicts may
	// only challenge.
	MaturityPrior Maturity = "prior"
	MaturityHour  Maturity = "hour"
	MaturityDay   Maturity = "day"
	MaturityWeek  Maturity = "week" // the 168 slot baseline
)

// Baseline is what the node needs to judge a site (section 4.4): the
// current and next weekday x hour slot, with three numbers per feature.
type Baseline struct {
	// Version grows with every baseline computation of the site (a
	// rollback, section 4.3 item 6, issues a new version).
	Version     uint64   `json:"version"`
	GeneratedAt int64    `json:"generated_at"`
	Maturity    Maturity `json:"maturity"`
	// CanBan: the site met the minimum sample (requests >= 1000 and unique
	// IPs >= 20, section 4.3 item 3); false allows only challenge and rate
	// limit.
	CanBan bool `json:"can_ban"`
	// SharePermille is this node's share of the site's requests of the
	// last hour (section 4.4), 0-1000.
	SharePermille int64 `json:"share_permille"`
	// AbsoluteRequestMilli is the hard request rate cap (section 5.1,
	// requests per second x 1000); 0 = none.
	AbsoluteRequestMilli int64  `json:"absolute_request_milli"`
	Slots                []Slot `json:"slots"`
}

// Slot index = weekday (0 = Sunday) * 24 + hour, 0-167, in the site's
// time zone as the control plane computed it.
type Slot struct {
	Slot          int64          `json:"slot"`
	Bands         []Band         `json:"bands"`
	Distributions []Distribution `json:"distributions,omitempty"`
}

// Band carries one numeric feature in milli units (x1000): the node builds
// [P50 - k*1.4826*MAD, max(P99, P50 + k*1.4826*MAD)] (section 4.3).
type Band struct {
	Feature string `json:"feature"`
	P50     int64  `json:"p50"`
	MAD     int64  `json:"mad"`
	P99     int64  `json:"p99"`
	Samples int64  `json:"samples"`
}

// Distribution is the top-K share vector of one distribution feature
// (JSD reference, section 4.2); shares are permille and sum to <= 1000
// (the rest is the tail).
type Distribution struct {
	Feature string  `json:"feature"`
	Values  []Share `json:"values"`
}

type Share struct {
	Value    string `json:"value"`
	Permille int64  `json:"permille"`
}

// Whitelist is the per-site never-mitigate list (section 7.2 items 3 and
// 5; verified crawlers, item 1, are always on and need no entry).
type Whitelist struct {
	Networks []AllowNetwork `json:"networks,omitempty"`
	// JA4 are JA4 fingerprints whitelisted on the site: a 解除并加白 JA4
	// (section 7.4; until 0 = permanent, else the expiry
	// the person chose). The node's own section 7A.6 entries (pass rate >=
	// 50% gives 7 days) stay on the node and are not in the snapshot.
	JA4 []AllowJA4 `json:"ja4,omitempty"`
}

type AllowNetwork struct {
	CIDR string `json:"cidr"`
	// Until 0 = permanent (site settings); admin login source IPs come
	// with 7 days.
	Until  int64  `json:"until,omitempty"`
	Source string `json:"source"` // user | admin_login | release
}

type AllowJA4 struct {
	JA4   string `json:"ja4"`
	Until int64  `json:"until"` // 0 = permanent
}

// Endpoint is a login-like endpoint for credential stuffing (Q10: detected
// automatically, a user may tag or untag).
type Endpoint struct {
	Method       string `json:"method"`
	PathTemplate string `json:"path_template"`
	Source       string `json:"source"` // auto | user
}

// Level is one step of the mitigation ladder (section 7.1).
type Level int64

const (
	LevelObserve   Level = 0 // L0: record only (never a table entry)
	LevelChallenge Level = 1 // L1: CC v2 challenge
	LevelRateLimit Level = 2 // L2: CC v2 reject_429 at RateMilli
	LevelBan       Level = 3 // L3: temporary ban (node Lua dictionary)
	LevelKernel    Level = 4 // L4: kernel ban (inet cdnca_ddos ban set)
	// LevelXDP is the L5 placeholder (Q9): accepted in every contract
	// field; until the XDP task lands a node executes it as LevelKernel and
	// reports the downgrade.
	LevelXDP Level = 5
)

// TargetKind is what a mitigation applies to.
type TargetKind string

const (
	TargetIP   TargetKind = "ip"
	TargetCIDR TargetKind = "cidr" // IPv4 /24 or IPv6 /48 (or narrower)
	TargetJA4  TargetKind = "ja4"  // L1-L2 only (no kernel form)
	TargetSite TargetKind = "site" // whole site, L1 only (severe / protect origin)
)

// Scope is where a mitigation came from (section 8.3).
type Scope string

const (
	ScopeSite   Scope = "site"   // judged on this site (any node)
	ScopeTenant Scope = "tenant" // tenant federation, L2 at most
)

// Mitigation is one entry of the site's mitigation table (section 7.1).
// Single-address L3/L4 bans decided by the control plane also travel on
// the security ban list (source autodefense, ConnectResponse 25); the table
// carries the rest and is what the node Lua gate reads.
type Mitigation struct {
	Kind   TargetKind `json:"kind"`
	Target string     `json:"target"`
	Level  Level      `json:"level"`
	// RateMilli: L2 allowed requests per second x 1000 per target.
	RateMilli int64 `json:"rate_milli,omitempty"`
	Scope     Scope `json:"scope"`
	Since     int64 `json:"since"`
	Until     int64 `json:"until"`
	// Offences counts repeats (the ban doubles per repeat up to 24 hours).
	Offences int64  `json:"offences"`
	Score    int64  `json:"score"`
	Reason   string `json:"reason"`
}

// Stage of a signature (section 6.2).
type Stage string

const (
	StageShadow    Stage = "shadow"
	StageChallenge Stage = "challenge"
	StageBlock     Stage = "block"
	// StageStandby: the attack ended; the signature counts in shadow for 15
	// minutes and resumes Resume on recurrence.
	StageStandby Stage = "standby"
)

// Release is one target a person released on the site (section 7.4): an
// ip, cidr or ja4 mitigation target (kind and target as in Mitigation), At
// the Unix second of the release.
type Release struct {
	Kind   TargetKind `json:"kind"`
	Target string     `json:"target"`
	At     int64      `json:"at"`
	// Retry counts a person's "重试" of the release: a new
	// value makes every node apply and answer it again (ReleaseAck).
	Retry int64 `json:"retry,omitempty"`
}

// MaxReleaseRetry bounds Release.Retry.
const MaxReleaseRetry = 100

// Signature is one mined attack signature (section 6.1 output). Conditions
// are ANDed; the node evaluates them on its own collected features.
type Signature struct {
	// ID is the first 16 hex of SHA-256 over the canonical conditions.
	ID         string      `json:"id"`
	Conditions []Condition `json:"conditions"`
	Stage      Stage       `json:"stage"`
	// Resume is the stage a standby signature returns to.
	Resume        Stage  `json:"resume,omitempty"`
	CooldownUntil int64  `json:"cooldown_until,omitempty"`
	ExpiresAt     int64  `json:"expires_at,omitempty"` // standby end
	CoverPermille int64  `json:"cover_permille"`
	FPRPPM        int64  `json:"fpr_ppm"`
	LiftMilli     int64  `json:"lift_milli"`
	AttackSamples int64  `json:"attack_samples"`
	NormalSamples int64  `json:"normal_samples"`
	Origin        string `json:"origin"` // node | control
	OriginNodeID  string `json:"origin_node_id,omitempty"`
	GeneratedAt   int64  `json:"generated_at"`
	Reason        string `json:"reason"`
}

// Condition is one "dimension = value" item (section 6.1 candidates).
type Condition struct {
	Dim   string `json:"dim"`
	Value string `json:"value"`
}

// WebPortGroup is the ID of the website port group (the TCP ports every
// website of the node shares, often of several tenants). Its layer 4
// mitigation acts on the whole node, so the node only mitigates it when the
// whole node is attacked, not when one site is (that site's attack is
// handled at layer 7 by CC/WAF; ad-16c).
const WebPortGroup = "web-tcp"

// PortGroup is one layer 4 port group of the node (section 7A.4: layer 4
// is judged per node x port group) with its baseline and the l4 module.
type PortGroup struct {
	ID       string      `json:"id"`
	Protocol string      `json:"protocol"` // tcp | udp
	Ports    []PortRange `json:"ports"`
	Baseline Baseline    `json:"baseline"`
	Module   Module      `json:"module"`
}

type PortRange struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// Intel is a platform intelligence entry (section 8.3, Q7): it only adds
// Bonus to a client's score, it never mitigates by itself.
type Intel struct {
	Kind  TargetKind `json:"kind"` // ip | cidr
	Value string     `json:"value"`
	Bonus int64      `json:"bonus"`
	Until int64      `json:"until"`
}
