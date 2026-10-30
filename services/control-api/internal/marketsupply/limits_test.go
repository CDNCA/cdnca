package marketsupply

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	mspec "github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
)

func TestNodeShareSplitsTotalsCeil(t *testing.T) {
	sub := uuid.New()
	totals := LimitTotals{BandwidthBPS: 1_000_000_001, Connections: 10, Requests: 7, NewPerSecond: 5, QPS: 100}
	got := NodeShare(sub, totals, Hold{}, 3)
	want := edgeconfig.PackageConnectionLimit{SubscriptionID: sub.String(), Connections: 3, BandwidthBPS: 333_333_334,
		MaxConnections: 4, NewPerSecond: 2, QPS: 34}
	if got != want {
		t.Fatalf("share %+v want %+v", got, want)
	}
	if got.Validate() != nil || !got.SubscriptionLimitsUsed() {
		t.Fatal("share must be a valid market limit")
	}
	// One node gets the whole total; unselected stays unlimited.
	if one := NodeShare(sub, LimitTotals{QPS: 100}, Hold{}, 1); one.QPS != 100 || one.Connections != -1 ||
		one.BandwidthBPS != 0 || one.MaxConnections != 0 {
		t.Fatalf("one node %+v", one)
	}
	// The node request budget is bounded by the node format.
	if big := NodeShare(sub, LimitTotals{Requests: 1_000_000}, Hold{}, 2); big.Connections != 65535 || big.Validate() != nil {
		t.Fatalf("clamped %+v", big)
	}
}

func TestNodeShareHolds(t *testing.T) {
	sub := uuid.New()
	totals := LimitTotals{BandwidthBPS: 100_000_000}
	if stop := NodeShare(sub, totals, Hold{Action: "stop"}, 2); !stop.Stopped || stop.BandwidthBPS != 50_000_000 {
		t.Fatalf("stop %+v", stop)
	}
	if pause := NodeShare(sub, totals, Hold{Action: "pause"}, 2); pause.Stopped || pause.BandwidthBPS != 50_000_000 {
		t.Fatalf("pause is DNS only %+v", pause)
	}
	// Monthly traffic throttle: throttle_bps split, the stricter of the two.
	if thr := NodeShare(sub, totals, Hold{Action: "throttle", ThrottleBPS: 8_000_001}, 2); thr.BandwidthBPS != 4_000_001 {
		t.Fatalf("throttle %+v", thr)
	}
	if loose := NodeShare(sub, totals, Hold{Action: "throttle", ThrottleBPS: 900_000_000}, 2); loose.BandwidthBPS != 50_000_000 {
		t.Fatalf("a looser throttle keeps the cap %+v", loose)
	}
	if only := NodeShare(sub, LimitTotals{}, Hold{Action: "throttle", ThrottleBPS: 8_000_000}, 4); only.BandwidthBPS != 2_000_000 ||
		only.Validate() != nil {
		t.Fatalf("throttle without a bandwidth cap %+v", only)
	}
}

func TestGrantTotalsAndHoldKey(t *testing.T) {
	g := grant.Grant{SubscriptionPath: []uuid.UUID{uuid.New(), uuid.New()}, NodePoolRef: uuid.NewString(),
		Limits: mspec.LimitSet{
			{Metric: mspec.MetricBandwidthPeakBPS, Cap: 1000, Action: mspec.ActionThrottle, SustainBuckets: 2},
			{Metric: mspec.MetricMonthlyTrafficBytes, Cap: 5, Action: mspec.ActionPause},
			{Metric: mspec.MetricConcurrentConnections, Cap: 20, Action: mspec.ActionThrottle, SustainBuckets: 2},
			{Metric: mspec.MetricQPS, Cap: 30, Action: mspec.ActionStop, SustainBuckets: 2},
		}}
	if got := grantTotals(g); got != (LimitTotals{BandwidthBPS: 1000, Connections: 20, QPS: 30}) {
		t.Fatalf("totals %+v", got)
	}
	if HoldKey(g.SubscriptionPath, g.NodePoolRef) != Key(g) {
		t.Fatal("hold key must match the grant key")
	}
}
