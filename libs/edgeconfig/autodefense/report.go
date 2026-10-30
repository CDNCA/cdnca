package autodefense

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
)

// Upstream (node -> control plane, ADR 0010 section 8.1): JSON messages on
// ReportSubjectPrefix.<node> (JetStream, deduplicated by Report.Key). The
// sketch states are opaque to this package; their binary format belongs to
// libs/autodefense/sketch (AD-01) and is named by Sketch.Format.

const (
	ReportSchema = "cdnca.autodefense.report/v1"
	// MaxReportBytes bounds one message (the node budget is 50 KB/s,
	// section 10.4).
	MaxReportBytes = 256 << 10
	MaxTopK        = 64
	MaxSketchBytes = 16 << 10
	MaxVerdicts    = 512
)

// ReportKind is the message type.
type ReportKind string

const (
	ReportMinute    ReportKind = "minute"    // one site minute summary
	ReportState     ReportKind = "state"     // site or port group state change
	ReportCandidate ReportKind = "candidate" // node mined signature candidate
	ReportVerdicts  ReportKind = "verdicts"  // individual verdicts (L2 and above)
	ReportAdjust    ReportKind = "adjust"    // module auto overlay adjustments
	// ReportNodeEvent is a platform node security event (F4): node scoped,
	// no site, tenant or port group (for example a DDoS empty connection ban).
	ReportNodeEvent ReportKind = "node_event"
	// ReportCCStats carries the CC rule statistics of a node: node scoped like node_event, one row per site, CC
	// policy, rule and minute, the counts being what the node saw since its
	// previous report (rows of one key add up). Read by the CC page and by
	// automatic defense.
	ReportCCStats ReportKind = "cc_stats"
	// ReportDrift: the site baseline drifted from its slow reference for
	// days (ADR 0010 section 4.3 item 4, "基线漂移待确认"); site scope only.
	ReportDrift ReportKind = "drift"
	// ReportReleaseAcks answers the single releases of a site the node
	// applied (fix-adwhitelist3, ADR §7.4): one entry per release (and
	// retry), sent when its outcome changes.
	ReportReleaseAcks ReportKind = "release_acks"
)

// BaselineMetrics are the node baseline metrics a drift names (the agent's
// sentinel metric order, frozen with the baseline row).
var BaselineMetrics = []string{"byte_rate", "cache_hit", "latency_p95", "latency_p99", "ratio_404", "ratio_4xx",
	"ratio_5xx", "request_rate", "upstream_error", "upstream_timeout"}

// Drift lists the metrics whose de-weekdayed daily level left the slow
// reference for Days consecutive days (sorted, distinct).
type Drift struct {
	Metrics []string `json:"metrics"`
	Days    int64    `json:"days"`
}

// Site states (section 5.1 and 7.3).
const (
	StateNormal        = "normal"
	StateSurge         = "surge"          // legitimate surge, not an attack
	StateProtectOrigin = "protect_origin" // surge with origin degradation
	StateAttack        = "attack"
	StateCooldown      = "cooldown" // degrading observation
	StateCircuit       = "circuit_open"
	StateBaselineStale = "baseline_stale"
)

// Report is one upstream message. Exactly the field of Kind is set.
type Report struct {
	Schema string     `json:"schema"`
	Kind   ReportKind `json:"kind"`
	NodeID string     `json:"node_id"`
	// SiteID is empty for node / port group messages (PortGroup set).
	SiteID    string `json:"site_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	PortGroup string `json:"port_group,omitempty"`
	// Seq grows per node and subject scope (site or port group); the
	// idempotency key is node_id + site_id (or port group) + seq.
	Seq        uint64       `json:"seq"`
	At         int64        `json:"at"`
	Revision   uint64       `json:"revision"` // snapshot revision in force
	Minute     *Minute      `json:"minute,omitempty"`
	State      *StateChange `json:"state,omitempty"`
	Candidate  *Signature   `json:"candidate,omitempty"`
	Verdicts   []Verdict    `json:"verdicts,omitempty"`
	Adjustment []Adjustment `json:"adjustments,omitempty"`
	NodeEvent  *NodeEvent   `json:"node_event,omitempty"`
	CCStats    []CCStat     `json:"cc_stats,omitempty"`
	Drift      *Drift       `json:"drift,omitempty"`
	// WAFEvidence: kind waf_evidence (ADR 0011 section 4.1).
	WAFEvidence *WAFEvidence `json:"waf_evidence,omitempty"`
	// ReleaseAcks: kind release_acks (fix-adwhitelist3).
	ReleaseAcks []ReleaseAck `json:"release_acks,omitempty"`
}

// ReleaseAck is a node's outcome of one single release (Site.Releases entry,
// kind / target / at / retry as delivered): applied (its local entries are
// gone from the gate and the kernel bans it wrote are deleted) or failed with
// Error. A failed release is retried by the node itself; a later success is
// answered again.
type ReleaseAck struct {
	Kind    TargetKind `json:"kind"`
	Target  string     `json:"target"`
	At      int64      `json:"at"`
	Retry   int64      `json:"retry,omitempty"`
	Applied bool       `json:"applied"`
	Error   string     `json:"error,omitempty"`
}

// ReleaseAck error codes.
const (
	// ReleaseGateWriteFailed: the gate (Lua shared dict) refused the write
	// that drops the local entries.
	ReleaseGateWriteFailed = "gate_write_failed"
	// ReleaseKernelUnbanFailed: a kernel ban the node wrote could not be
	// deleted (it ends with its TTL; the gate already passes the client).
	ReleaseKernelUnbanFailed = "kernel_unban_failed"
)

func validReleaseAcks(acks []ReleaseAck) bool {
	if len(acks) == 0 || len(acks) > MaxReleasesPerSite {
		return false
	}
	for _, ack := range acks {
		if ack.Kind == TargetSite || !validTarget(ack.Kind, ack.Target, LevelChallenge) || !validTime(ack.At, false) ||
			ack.Retry < 0 || ack.Retry > MaxReleaseRetry {
			return false
		}
		if ack.Applied != (ack.Error == "") ||
			(!ack.Applied && ack.Error != ReleaseGateWriteFailed && ack.Error != ReleaseKernelUnbanFailed) {
			return false
		}
	}
	return true
}

// CC rule statistics bounds (one report stays far below MaxReportBytes:
// a row with full top lists is about 1.5 KiB).
const (
	MaxCCStats   = 128
	MaxCCTop     = 10
	MaxCCTopText = 256
	// MaxCCPolicyVersion is the CC v2 engine's bound (MAX_SAFE_INTEGER).
	MaxCCPolicyVersion = 1<<53 - 1
)

// CCStat is the activity of one CC rule of one site in one minute. RuleID is
// empty for site level counts outside any rule (Passed by a valid pass of a
// verify page, Banned by a challenge ban).
type CCStat struct {
	TenantID      string `json:"tenant_id"`
	SiteID        string `json:"site_id"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion uint64 `json:"policy_version"`
	RuleID        string `json:"rule_id,omitempty"`
	Minute        int64  `json:"minute"` // Unix seconds, multiple of 60
	// Matched: requests the rule counted; Triggered: requests over its limit;
	// Challenged: verification pages served; Blocked: 429 / ban responses;
	// Passed: requests let through by a valid pass or a solved verification;
	// JA4Unavailable: requests a ja4 count_by rule skipped.
	Matched        int64 `json:"matched"`
	Triggered      int64 `json:"triggered"`
	Challenged     int64 `json:"challenged"`
	Blocked        int64 `json:"blocked"`
	Passed         int64 `json:"passed"`
	JA4Unavailable int64 `json:"ja4_unavailable"`
	// TopClients / TopPaths: the triggered requests by client address and
	// path (at most MaxCCTop, count descending then value ascending).
	TopClients []Count `json:"top_clients"`
	TopPaths   []Count `json:"top_paths"`
}

// NodeEvent is one platform node security event (F4, ge-ddos 遗留 2).
type NodeEvent struct {
	Source string `json:"source"` // ddos | l4guard | autodefense | xdp
	Kind   string `json:"kind"`   // e.g. empty_connection_ban, rate_ban
	Client string `json:"client,omitempty"`
	Count  int64  `json:"count"`
	// DurationSeconds: the ban length (0 when not a ban).
	DurationSeconds int64  `json:"duration_seconds"`
	Level           Level  `json:"level"`
	Reason          string `json:"reason"`
}

// Minute is a minute summary (section 4.1 agent upload).
type Minute struct {
	Minute int64 `json:"minute"` // Unix seconds, multiple of 60
	// Counts are the exact counters of the minute by feature name
	// (requests, status_2xx ... in plain units, not milli).
	Counts map[string]int64 `json:"counts"`
	// Values are the numeric features in milli units (SiteFeatures /
	// PortGroupFeatures).
	Values   map[string]int64 `json:"values"`
	Sketches []Sketch         `json:"sketches"`
	TopK     []TopK           `json:"top_k"`
	// Dropped counts what the node dropped to stay in budget.
	Dropped int64 `json:"dropped"`
}

type Sketch struct {
	Name   string `json:"name"`   // unique_ip | unique_cidr | unique_path | count_min_ip | count_min_cidr
	Format string `json:"format"` // AD-01 format name, e.g. hll12/v1
	State  []byte `json:"state"`
}

type TopK struct {
	Feature string  `json:"feature"`
	Values  []Count `json:"values"`
	// Tail is the count outside the listed values (error bound input).
	Tail int64 `json:"tail"`
}

type Count struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// StateChange is an immediate state event (section 8.1).
type StateChange struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Level  Level  `json:"level"` // highest level in force after the change
	Reason string `json:"reason"`
}

// Verdict is one individual judgement (only L2 and above are reported).
type Verdict struct {
	Kind   TargetKind `json:"kind"`
	Target string     `json:"target"`
	Score  int64      `json:"score"`
	Level  Level      `json:"level"`
	Until  int64      `json:"until"`
	Reason string     `json:"reason"`
}

// Adjustment is one automatic overlay change (audit
// security.autodefense.module_adjust, section 7A.1).
type Adjustment struct {
	Module ModuleName `json:"module"`
	Field  string     `json:"field"`
	From   int64      `json:"from"`
	To     int64      `json:"to"`
	Reason string     `json:"reason"`
	// Suggest: the value the node would apply while the overlay is not in
	// force (module in suggest mode, or auto without module.autodefense.auto,
	// section 7A.1 / 9.1); never applied, not a module_adjust.
	Suggest bool `json:"suggest,omitempty"`
	// FrozenUntil: this change was the fourth reversal of the field within
	// an hour; the node keeps the value until then (section 7A.1 rhythm).
	FrozenUntil int64 `json:"frozen_until,omitempty"`
}

var sketchNamePattern = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
var sketchFormatPattern = regexp.MustCompile(`^[a-z0-9_]{1,32}/v[0-9]{1,3}$`)

// ValidateReport checks one upstream message.
func ValidateReport(report Report) error {
	if !report.valid() {
		return ErrInvalid
	}
	return nil
}

func (report Report) valid() bool {
	if report.Schema != ReportSchema || !uuidPattern.MatchString(report.NodeID) || report.Seq == 0 || report.Seq > MaxValue ||
		!validTime(report.At, false) || report.Revision > MaxValue {
		return false
	}
	siteScope := report.SiteID != ""
	if report.Kind == ReportNodeEvent {
		event := report.NodeEvent
		if siteScope || report.TenantID != "" || report.PortGroup != "" || event == nil || report.Minute != nil || report.State != nil ||
			report.Candidate != nil || report.Verdicts != nil || report.Adjustment != nil {
			return false
		}
		if event.Client != "" {
			if canonical, ok := CanonicalAddress(event.Client); !ok || canonical != event.Client {
				return false
			}
		}
		return contains([]string{"autodefense", "ddos", "l4guard", "xdp"}, event.Source) && slugPattern.MatchString(event.Kind) &&
			validInt(event.Count) && event.DurationSeconds >= 0 && event.DurationSeconds <= MaxMitigationSeconds &&
			event.Level >= LevelObserve && event.Level <= LevelXDP && validReason(event.Reason)
	}
	if report.Kind == ReportCCStats {
		return !siteScope && report.TenantID == "" && report.PortGroup == "" && report.Minute == nil && report.State == nil &&
			report.Candidate == nil && report.Verdicts == nil && report.Adjustment == nil && report.NodeEvent == nil &&
			validCCStats(report.CCStats, report.At)
	}
	if report.NodeEvent != nil || report.CCStats != nil {
		return false
	}
	if report.Kind == ReportWAFEvidence {
		return siteScope && uuidPattern.MatchString(report.SiteID) && uuidPattern.MatchString(report.TenantID) &&
			report.PortGroup == "" && report.Minute == nil && report.State == nil && report.Candidate == nil &&
			report.Verdicts == nil && report.Adjustment == nil && report.Drift == nil && report.WAFEvidence != nil &&
			validWAFEvidence(*report.WAFEvidence, report.At)
	}
	if report.WAFEvidence != nil {
		return false
	}
	if report.Kind == ReportReleaseAcks {
		return siteScope && uuidPattern.MatchString(report.SiteID) && uuidPattern.MatchString(report.TenantID) &&
			report.PortGroup == "" && report.Minute == nil && report.State == nil && report.Candidate == nil &&
			report.Verdicts == nil && report.Adjustment == nil && report.Drift == nil && validReleaseAcks(report.ReleaseAcks)
	}
	if report.ReleaseAcks != nil {
		return false
	}
	if report.Kind == ReportDrift {
		drift := report.Drift
		if !siteScope || drift == nil || report.Minute != nil || report.State != nil || report.Candidate != nil ||
			report.Verdicts != nil || report.Adjustment != nil || len(drift.Metrics) == 0 ||
			len(drift.Metrics) > len(BaselineMetrics) || drift.Days < 1 || drift.Days > 255 ||
			!uuidPattern.MatchString(report.SiteID) || !uuidPattern.MatchString(report.TenantID) || report.PortGroup != "" {
			return false
		}
		for index, metric := range drift.Metrics {
			if !contains(BaselineMetrics, metric) || (index > 0 && drift.Metrics[index-1] >= metric) {
				return false
			}
		}
		return true
	}
	if report.Drift != nil {
		return false
	}
	if siteScope {
		if !uuidPattern.MatchString(report.SiteID) || !uuidPattern.MatchString(report.TenantID) || report.PortGroup != "" {
			return false
		}
	} else if report.TenantID != "" || !slugPattern.MatchString(report.PortGroup) {
		return false
	}
	set := 0
	for _, present := range []bool{report.Minute != nil, report.State != nil, report.Candidate != nil,
		report.Verdicts != nil, report.Adjustment != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return false
	}
	switch report.Kind {
	case ReportMinute:
		features := SiteFeatures
		if !siteScope {
			features = PortGroupFeatures
		}
		return report.Minute != nil && validMinute(*report.Minute, features)
	case ReportState:
		state := report.State
		return state != nil && validState(state.From) && validState(state.To) && state.From != state.To &&
			state.Level >= LevelObserve && state.Level <= LevelXDP && validReason(state.Reason)
	case ReportCandidate:
		return siteScope && report.Candidate != nil && report.Candidate.Origin == "node" &&
			report.Candidate.OriginNodeID == report.NodeID && report.Candidate.Stage == StageShadow && validSignature(*report.Candidate)
	case ReportVerdicts:
		if len(report.Verdicts) == 0 || len(report.Verdicts) > MaxVerdicts {
			return false
		}
		for _, verdict := range report.Verdicts {
			if verdict.Level < LevelRateLimit || !validTarget(verdict.Kind, verdict.Target, verdict.Level) ||
				verdict.Score < 0 || verdict.Score > 100 || verdict.Until <= report.At ||
				verdict.Until-report.At > MaxMitigationSeconds || !validReason(verdict.Reason) {
				return false
			}
		}
		return true
	case ReportAdjust:
		if len(report.Adjustment) == 0 || len(report.Adjustment) > 64 {
			return false
		}
		for _, adjustment := range report.Adjustment {
			spec, ok := LookupField(adjustment.Field)
			if !ok || spec.Module != adjustment.Module || adjustment.From == adjustment.To ||
				adjustment.From < spec.PlatformMin || adjustment.From > spec.PlatformMax ||
				adjustment.To < spec.PlatformMin || adjustment.To > spec.PlatformMax || !validReason(adjustment.Reason) ||
				(adjustment.FrozenUntil != 0 && (adjustment.Suggest || adjustment.FrozenUntil <= report.At ||
					adjustment.FrozenUntil-report.At > 3600)) {
				return false
			}
			if (adjustment.Module == ModuleL4) == siteScope {
				return false
			}
		}
		return true
	}
	return false
}

func validCCStats(stats []CCStat, at int64) bool {
	if len(stats) == 0 || len(stats) > MaxCCStats {
		return false
	}
	type statKey struct {
		tenant, site, policy, rule string
		version                    uint64
		minute                     int64
	}
	seen := make(map[statKey]bool, len(stats))
	for _, stat := range stats {
		key := statKey{stat.TenantID, stat.SiteID, stat.PolicyID, stat.RuleID, stat.PolicyVersion, stat.Minute}
		if !uuidPattern.MatchString(stat.TenantID) || !uuidPattern.MatchString(stat.SiteID) ||
			!(stat.PolicyID == "legacy-cc" || uuidPattern.MatchString(stat.PolicyID)) ||
			stat.PolicyVersion == 0 || stat.PolicyVersion > MaxCCPolicyVersion ||
			(stat.RuleID != "" && !uuidPattern.MatchString(stat.RuleID)) ||
			!validTime(stat.Minute, false) || stat.Minute%60 != 0 || stat.Minute > at || seen[key] {
			return false
		}
		seen[key] = true
		total := int64(0)
		for _, value := range []int64{stat.Matched, stat.Triggered, stat.Challenged, stat.Blocked, stat.Passed, stat.JA4Unavailable} {
			if !validInt(value) {
				return false
			}
			total += value
		}
		if total == 0 || stat.TopClients == nil || stat.TopPaths == nil {
			return false
		}
		for name, top := range map[string][]Count{"client": stat.TopClients, "path": stat.TopPaths} {
			if len(top) > MaxCCTop {
				return false
			}
			for index, entry := range top {
				if entry.Value == "" || len(entry.Value) > MaxCCTopText || entry.Count <= 0 || !validInt(entry.Count) ||
					entry.Count > stat.Triggered {
					return false
				}
				if name == "client" {
					if canonical, ok := CanonicalAddress(entry.Value); !ok || canonical != entry.Value {
						return false
					}
				} else if entry.Value[0] != '/' {
					return false
				}
				if index > 0 && (top[index-1].Count < entry.Count ||
					top[index-1].Count == entry.Count && top[index-1].Value >= entry.Value) {
					return false
				}
			}
		}
	}
	return true
}

func validState(state string) bool {
	return contains([]string{StateAttack, StateBaselineStale, StateCircuit, StateCooldown, StateNormal, StateProtectOrigin, StateSurge}, state)
}

func validMinute(minute Minute, features []string) bool {
	if !validTime(minute.Minute, false) || minute.Minute%60 != 0 || minute.Counts == nil || minute.Values == nil ||
		minute.Sketches == nil || minute.TopK == nil || !validInt(minute.Dropped) || len(minute.Counts) > 64 {
		return false
	}
	for name, count := range minute.Counts {
		if !sketchNamePattern.MatchString(name) || !validInt(count) {
			return false
		}
	}
	for name, value := range minute.Values {
		if !contains(features, name) || !validInt(value) {
			return false
		}
	}
	for index, sketch := range minute.Sketches {
		if !sketchNamePattern.MatchString(sketch.Name) || !sketchFormatPattern.MatchString(sketch.Format) ||
			len(sketch.State) == 0 || len(sketch.State) > MaxSketchBytes ||
			(index > 0 && minute.Sketches[index-1].Name >= sketch.Name) {
			return false
		}
	}
	for index, top := range minute.TopK {
		if !contains(SiteDistributions, top.Feature) && !contains(PortGroupDistributions, top.Feature) ||
			len(top.Values) > MaxTopK || !validInt(top.Tail) || (index > 0 && minute.TopK[index-1].Feature >= top.Feature) {
			return false
		}
		for v, count := range top.Values {
			if count.Value == "" || len(count.Value) > 128 || !validInt(count.Count) ||
				(v > 0 && top.Values[v-1].Value >= count.Value) {
				return false
			}
		}
	}
	return true
}

// EncodeReport validates and encodes one message (canonical: slices
// sorted by the caller, maps sorted by encoding/json).
func EncodeReport(report Report) ([]byte, error) {
	if !report.valid() {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > reportBytesLimit(report.Kind) {
		return nil, ErrInvalid
	}
	return encoded, nil
}

// DecodeReport strictly decodes one message.
func DecodeReport(encoded []byte) (Report, error) {
	if len(encoded) == 0 || len(encoded) > MaxReportBytes {
		return Report{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF || !report.valid() || len(encoded) > reportBytesLimit(report.Kind) {
		return Report{}, ErrInvalid
	}
	return report, nil
}

// reportBytesLimit is a kind's encoded size bound.
func reportBytesLimit(kind ReportKind) int {
	if kind == ReportWAFEvidence {
		return MaxWAFEvidenceBytes
	}
	return MaxReportBytes
}
