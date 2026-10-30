package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// Supply limits (ADR 0012 §3.1). An offer lists the metrics its seller caps;
// a metric that is not listed is unlimited. Every listed metric carries its
// own cap and the action taken when the subscription reaches it.

type Metric string

const (
	MetricDomains             Metric = "domains"
	MetricBandwidthPeakBPS    Metric = "bandwidth_peak_bps"
	MetricMonthlyTrafficBytes Metric = "monthly_traffic_bytes"
	// MetricConcurrentConnections is the true TCP connections in use (L7
	// per client connection, QUIC not counted; L4 per session);
	// MetricConcurrentRequests is the L7 requests in flight.
	MetricConcurrentConnections   Metric = "concurrent_connections"
	MetricConcurrentRequests      Metric = "concurrent_requests"
	MetricNewConnectionsPerSecond Metric = "new_connections_per_second"
	MetricQPS                     Metric = "qps"
	MetricNodeCPUPercent          Metric = "node_cpu_percent"
	MetricNodeMemoryPercent       Metric = "node_memory_percent"
)

type Action string

const (
	ActionThrottle Action = "throttle"
	ActionPause    Action = "pause"
	ActionStop     Action = "stop"
	// ActionRejectNew is the fixed action of domains: the relay refuses
	// domains beyond the cap (market relaycheck).
	ActionRejectNew Action = "reject_new"
	// ActionRemoveNode is the fixed action of node_*: an overloaded node
	// leaves this supply's DNS records; it is judged per node, never per
	// subscriber.
	ActionRemoveNode Action = "remove_node"
)

const (
	DefaultSustainBuckets = 2
	MaxSustainBuckets     = 12                 // one hour of 5-minute buckets
	MaxBandwidthBPS       = 10_000_000_000_000 // 10 Tbit/s
)

type metricRule struct {
	maxCap   int64
	actions  []Action // first is the default
	realtime bool     // enforced on the node, judged by sustained buckets
}

// metricOrder is the vocabulary and the canonical order of a LimitSet.
var metricOrder = []Metric{
	MetricDomains, MetricBandwidthPeakBPS, MetricMonthlyTrafficBytes, MetricConcurrentConnections,
	MetricConcurrentRequests, MetricNewConnectionsPerSecond, MetricQPS, MetricNodeCPUPercent, MetricNodeMemoryPercent,
}

var metricRules = map[Metric]metricRule{
	MetricDomains:                 {maxCap: 1_000_000, actions: []Action{ActionRejectNew}},
	MetricBandwidthPeakBPS:        {maxCap: MaxBandwidthBPS, actions: []Action{ActionThrottle, ActionPause, ActionStop}, realtime: true},
	MetricMonthlyTrafficBytes:     {maxCap: 1 << 60, actions: []Action{ActionPause, ActionThrottle, ActionStop}},
	MetricConcurrentConnections:   {maxCap: 1_000_000_000, actions: []Action{ActionThrottle, ActionPause, ActionStop}, realtime: true},
	MetricConcurrentRequests:      {maxCap: 1_000_000_000, actions: []Action{ActionThrottle, ActionPause, ActionStop}, realtime: true},
	MetricNewConnectionsPerSecond: {maxCap: 100_000_000, actions: []Action{ActionThrottle, ActionPause, ActionStop}, realtime: true},
	MetricQPS:                     {maxCap: 1_000_000_000, actions: []Action{ActionThrottle, ActionPause, ActionStop}, realtime: true},
	MetricNodeCPUPercent:          {maxCap: 100, actions: []Action{ActionRemoveNode}},
	MetricNodeMemoryPercent:       {maxCap: 100, actions: []Action{ActionRemoveNode}},
}

// Metrics returns the vocabulary in canonical order.
func Metrics() []Metric { return slices.Clone(metricOrder) }

func (m Metric) Known() bool { _, ok := metricRules[m]; return ok }

// Realtime metrics are hard-limited on nodes; pause/stop apply after the
// market sees SustainBuckets consecutive buckets at >= 95% of the cap.
func (m Metric) Realtime() bool { return metricRules[m].realtime }

func (m Metric) MaxCap() int64 { return metricRules[m].maxCap }

// Actions lists the allowed actions, default first.
func (m Metric) Actions() []Action { return slices.Clone(metricRules[m].actions) }

func (m Metric) DefaultAction() Action {
	if r, ok := metricRules[m]; ok {
		return r.actions[0]
	}
	return ""
}

// NodeLoad reports whether m is a node capacity threshold (node_*).
func (m Metric) NodeLoad() bool { return m == MetricNodeCPUPercent || m == MetricNodeMemoryPercent }

// Limit is one selected metric. ThrottleBPS is the bandwidth the subscription
// is throttled to and is set only for monthly_traffic_bytes + throttle.
// SustainBuckets is set only for realtime metrics.
type Limit struct {
	Metric         Metric `json:"metric"`
	Cap            int64  `json:"cap"`
	Action         Action `json:"action"`
	ThrottleBPS    int64  `json:"throttle_bps,omitempty"`
	SustainBuckets int    `json:"sustain_buckets,omitempty"`
}

func (l Limit) Validate() error {
	r, ok := metricRules[l.Metric]
	if !ok {
		return fmt.Errorf("%w: unknown metric %q", ErrInvalid, l.Metric)
	}
	if l.Cap <= 0 || l.Cap > r.maxCap {
		return fmt.Errorf("%w: %s cap must be 1..%d", ErrInvalid, l.Metric, r.maxCap)
	}
	if !slices.Contains(r.actions, l.Action) {
		return fmt.Errorf("%w: %s action %q not allowed", ErrInvalid, l.Metric, l.Action)
	}
	throttles := l.Metric == MetricMonthlyTrafficBytes && l.Action == ActionThrottle
	if throttles != (l.ThrottleBPS != 0) || l.ThrottleBPS < 0 || l.ThrottleBPS > MaxBandwidthBPS {
		return fmt.Errorf("%w: throttle_bps is required only for monthly_traffic_bytes throttle (1..%d)", ErrInvalid, int64(MaxBandwidthBPS))
	}
	if r.realtime != (l.SustainBuckets != 0) || l.SustainBuckets < 0 || l.SustainBuckets > MaxSustainBuckets {
		return fmt.Errorf("%w: sustain_buckets is required only for realtime metrics (1..%d)", ErrInvalid, MaxSustainBuckets)
	}
	return nil
}

// LimitSet is the canonical form: at most one Limit per metric, in Metrics()
// order. An empty set means unlimited. It always encodes as a JSON array.
type LimitSet []Limit

func (s LimitSet) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]Limit(s))
}

// Normalize fills the default action and sustain_buckets, sorts into
// canonical order and validates. Use it on seller input; signed documents
// must already be canonical (Validate).
func (s LimitSet) Normalize() (LimitSet, error) {
	out := make(LimitSet, len(s))
	for i, l := range s {
		if l.Action == "" {
			l.Action = l.Metric.DefaultAction()
		}
		if l.SustainBuckets == 0 && l.Metric.Realtime() {
			l.SustainBuckets = DefaultSustainBuckets
		}
		out[i] = l
	}
	slices.SortStableFunc(out, func(a, b Limit) int { return metricIndex(a.Metric) - metricIndex(b.Metric) })
	return out, out.Validate()
}

func (s LimitSet) Validate() error {
	if len(s) > len(metricOrder) {
		return fmt.Errorf("%w: too many limits", ErrInvalid)
	}
	last := -1
	for _, l := range s {
		if err := l.Validate(); err != nil {
			return err
		}
		i := metricIndex(l.Metric)
		if i <= last {
			return fmt.Errorf("%w: limits must be unique and in canonical order", ErrInvalid)
		}
		last = i
	}
	return nil
}

func (s LimitSet) Get(m Metric) (Limit, bool) {
	for _, l := range s {
		if l.Metric == m {
			return l, true
		}
	}
	return Limit{}, false
}

// Cap returns the cap of m; ok=false means unlimited.
func (s LimitSet) Cap(m Metric) (int64, bool) {
	l, ok := s.Get(m)
	return l.Cap, ok
}

// Min merges two hops of a resale path. A metric capped by only one hop keeps
// that hop's limit; capped by both, the smaller cap wins with its own action
// (on equal caps the stricter action: stop > pause > throttle). Each hop's
// holds are still evaluated against its own offer by the market; Min is what
// the leaf enforces on nodes. Inputs must be valid; the result is canonical.
func (s LimitSet) Min(o LimitSet) LimitSet {
	out := LimitSet{}
	for _, m := range metricOrder {
		a, okA := s.Get(m)
		b, okB := o.Get(m)
		switch {
		case okA && okB:
			if b.Cap < a.Cap || (b.Cap == a.Cap && actionRank(b.Action) > actionRank(a.Action)) {
				a = b
			}
			out = append(out, a)
		case okA:
			out = append(out, a)
		case okB:
			out = append(out, b)
		}
	}
	return out
}

func actionRank(a Action) int {
	switch a {
	case ActionStop:
		return 2
	case ActionPause:
		return 1
	}
	return 0
}

func metricIndex(m Metric) int {
	if i := slices.Index(metricOrder, m); i >= 0 {
		return i
	}
	return len(metricOrder)
}

// LoadThresholds are node capacity thresholds in percent (1..100).
// DefaultLoadFloor is the platform floor of ADR 0012 §3.4; the market policy
// may tighten it.
type LoadThresholds struct {
	CPUPercent    int64 `json:"cpu_percent"`
	MemoryPercent int64 `json:"memory_percent"`
}

var DefaultLoadFloor = LoadThresholds{CPUPercent: 80, MemoryPercent: 70}

func (t LoadThresholds) Validate() error {
	if t.CPUPercent < 1 || t.CPUPercent > 100 || t.MemoryPercent < 1 || t.MemoryPercent > 100 {
		return fmt.Errorf("%w: load thresholds must be 1..100", ErrInvalid)
	}
	return nil
}

// FloorError reports a seller threshold looser than the platform floor.
type FloorError struct {
	Metric Metric
	Floor  int64
}

func (e *FloorError) Error() string {
	return fmt.Sprintf("invalid market spec: %s may not exceed the platform floor %d", e.Metric, e.Floor)
}

func (e *FloorError) Unwrap() error { return ErrInvalid }

// CheckLoadFloor rejects node_* caps above the floor (listing validation).
func (s LimitSet) CheckLoadFloor(floor LoadThresholds) error {
	for m, f := range map[Metric]int64{MetricNodeCPUPercent: floor.CPUPercent, MetricNodeMemoryPercent: floor.MemoryPercent} {
		if c, ok := s.Cap(m); ok && c > f {
			return &FloorError{Metric: m, Floor: f}
		}
	}
	return nil
}

// SplitLoad separates node thresholds from subscription limits. The returned
// thresholds are min(seller cap, floor); a seller that set none gets the
// floor. A floor tightened later therefore applies to existing offers.
func (s LimitSet) SplitLoad(floor LoadThresholds) (LimitSet, LoadThresholds) {
	limits := LimitSet{}
	effective := floor
	for _, l := range s {
		switch l.Metric {
		case MetricNodeCPUPercent:
			effective.CPUPercent = min(effective.CPUPercent, l.Cap)
		case MetricNodeMemoryPercent:
			effective.MemoryPercent = min(effective.MemoryPercent, l.Cap)
		default:
			limits = append(limits, l)
		}
	}
	return limits, effective
}

// PrepaidAction is what happens to all of a subscription's supply when its
// prepaid balance cannot pay the next charge (ADR 0012 §3.1, default pause).
type PrepaidAction string

const (
	PrepaidPause PrepaidAction = "pause"
	PrepaidStop  PrepaidAction = "stop"
)

func (a PrepaidAction) Validate() error {
	if a != PrepaidPause && a != PrepaidStop {
		return fmt.Errorf("%w: prepaid_exhausted_action must be pause or stop", ErrInvalid)
	}
	return nil
}

// DecodeStrict decodes exactly one JSON value and rejects unknown fields, so a
// contract field this build does not understand fails closed instead of being
// silently dropped.
func DecodeStrict(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if decoder.More() {
		return fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	return nil
}
