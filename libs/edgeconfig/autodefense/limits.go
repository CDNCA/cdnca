package autodefense

// Limits are the platform settings of ADR 0010 sections 10.1, 10.2 and 10.4
// a node enforces (系统设置 → 智能自动防御 → 平台设置, fix-adplatwire):
// MaxSites the sites the node defends at a time, BanL3PerMinute /
// BanL4PerMinute the new L3 / L4 bans of one site per minute,
// CircuitResumeMinutes how long after its reason cleared a break resumes,
// CircuitManualAfterBreaks the break of one site within 24 hours from which
// only a person resumes. The two false positive limit settings are not here:
// the node's false positive limit is the challenge pass rate (see the
// agent's breaker.go), the platform settings' two measures are not
// implemented.
type Limits struct {
	MaxSites                 int64 `json:"max_sites"`
	BanL3PerMinute           int64 `json:"ban_l3_per_minute"`
	BanL4PerMinute           int64 `json:"ban_l4_per_minute"`
	CircuitResumeMinutes     int64 `json:"circuit_resume_minutes"`
	CircuitManualAfterBreaks int64 `json:"circuit_manual_after_breaks"`
}

// DefaultLimits are the limits of a snapshot without them (the ADR 0010
// defaults).
func DefaultLimits() Limits {
	return Limits{MaxSites: MaxSites, BanL3PerMinute: 5000, BanL4PerMinute: 2000, CircuitResumeMinutes: 30,
		CircuitManualAfterBreaks: 2}
}

// Limits bounds (the platform settings API validates the same ranges).
const (
	MaxBansPerMinute     = 100000
	MaxResumeMinutes     = 1440
	MaxManualAfterBreaks = 10
)

func validLimits(limits *Limits) bool {
	return limits == nil || limits.MaxSites >= 1 && limits.MaxSites <= MaxSites &&
		limits.BanL3PerMinute >= 1 && limits.BanL3PerMinute <= MaxBansPerMinute &&
		limits.BanL4PerMinute >= 1 && limits.BanL4PerMinute <= MaxBansPerMinute &&
		limits.CircuitResumeMinutes >= 1 && limits.CircuitResumeMinutes <= MaxResumeMinutes &&
		limits.CircuitManualAfterBreaks >= 1 && limits.CircuitManualAfterBreaks <= MaxManualAfterBreaks
}
