package edgeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Real user monitoring. A site with rum has the node inject
// the same-origin script into its HTML documents; the node's collect
// endpoint folds the beacons into per (site, minute) histograms
// (cdnca_rum.lua), the agent takes the finished minutes from the control
// socket (GET /rum-minutes) and sends each as one rum_minute.v1 telemetry
// record (TELEMETRY_KIND_RUM_MINUTE_V1) bound to its site; the control plane
// stores them in ClickHouse rum_minutes_v1 / rum_errors_v1 (034). No record
// carries a visitor address, identifier or query string.
const (
	RUMMinuteType = "rum_minute.v1"
	// RUMMinuteNodeSchema is what cdnca_rum answers on GET /rum-minutes.
	RUMMinuteNodeSchema = "cdnca.edge.rum-minute/v1"

	RUMDefaultSamplePercent = 10
	// RUMMaxBucket is the last histogram bucket (§3.4: 1.08^200 ~ 4.8e6).
	RUMMaxBucket = 200
	// Node limits per site and minute (§5.4): pages and countries beyond
	// these fold into RUMOther; errors beyond RUMMaxErrors, buckets beyond
	// RUMMaxBuckets and refused beacons are counted in Dropped.
	RUMMaxPages     = 50
	RUMMaxCountries = 30
	RUMMaxErrors    = 100
	RUMMaxSeries    = 1 + 3 + RUMMaxPages + 1 + RUMMaxCountries + 1
	RUMMaxBuckets   = 4000
	RUMMaxValue     = 1<<53 - 1
	// RUMOther is the folded page / country value.
	RUMOther = "(other)"
	// RUMNoCountry is the country of a client the IP library has no entry for.
	RUMNoCountry = "--"
)

// RUMMetrics are the histogram names (cls is the score times 1000).
var RUMMetrics = []string{"lcp", "inp", "cls", "fcp", "ttfb"}

// SiteRUM is the site object field (edgesite.Site.RUM).
type SiteRUM struct {
	SamplePercent int `json:"sample_percent"`
}

func (rum SiteRUM) Valid() bool { return rum.SamplePercent >= 1 && rum.SamplePercent <= 100 }

// RUMBucket is the node's histogram bucket of v (cdnca_rum.bucket):
// 0 for v <= 0, else floor(ln v / ln 1.08) + 1, at most RUMMaxBucket.
func RUMBucket(v int64) int {
	if v <= 0 {
		return 0
	}
	return min(RUMMaxBucket, int(math.Floor(math.Log(float64(v))/math.Log(1.08)))+1)
}

// RUMBucketValue is the value a bucket stands for: the geometric middle of
// [1.08^(k-1), 1.08^k) (within 4% of any value in it); 0 for bucket 0.
func RUMBucketValue(bucket int) float64 {
	if bucket <= 0 {
		return 0
	}
	return math.Pow(1.08, float64(bucket)-0.5)
}

// RUMHistogram is bucket -> count (JSON object keys are the bucket numbers).
type RUMHistogram map[uint16]int64

// Count is the number of values in the histogram.
func (histogram RUMHistogram) Count() int64 {
	var total int64
	for _, count := range histogram {
		total += count
	}
	return total
}

// Quantile is the value of the q-th quantile (0 < q <= 1), false when the
// histogram is empty.
func (histogram RUMHistogram) Quantile(q float64) (float64, bool) {
	total := histogram.Count()
	if total <= 0 || q <= 0 || q > 1 {
		return 0, false
	}
	buckets := make([]int, 0, len(histogram))
	for bucket := range histogram {
		buckets = append(buckets, int(bucket))
	}
	sort.Ints(buckets)
	target := int64(math.Ceil(q * float64(total)))
	var seen int64
	for _, bucket := range buckets {
		seen += histogram[uint16(bucket)]
		if seen >= target {
			return RUMBucketValue(bucket), true
		}
	}
	return RUMBucketValue(buckets[len(buckets)-1]), true
}

// Merge adds other into histogram.
func (histogram RUMHistogram) Merge(other RUMHistogram) {
	for bucket, count := range other {
		histogram[bucket] += count
	}
}

// RUMSeries is one (dimension, value) of a site minute: the page views
// counted and one histogram per metric that was measured.
type RUMSeries struct {
	Dimension  string                  `json:"dimension"` // all, page, country, device
	Value      string                  `json:"value"`
	Views      int64                   `json:"views"`
	Histograms map[string]RUMHistogram `json:"histograms"`
}

// RUMError is one error group of a site minute.
type RUMError struct {
	Kind    string `json:"kind"`    // resource, navigation, fetch, xhr
	Element string `json:"element"` // img, script, link, iframe, video, audio or ""
	Target  string `json:"target"`  // normalised same-origin path or a cross-origin host
	Status  int    `json:"status"`  // 0 network failure, else 400-599
	Count   int64  `json:"count"`
}

// RUMMinuteData is what the node hands out per site and minute.
type RUMMinuteData struct {
	Series  []RUMSeries `json:"series"`
	Errors  []RUMError  `json:"errors"`
	Dropped int64       `json:"dropped"`
}

// RUMMinuteEvent is one record: the site minute of one node. InstallationID
// (and PackageSubscriptionID when the site has one) are the gateway's.
type RUMMinuteEvent struct {
	MetricVersion         uint16    `json:"metric_version"`
	EventID               string    `json:"event_id"`
	Minute                time.Time `json:"minute"`
	TenantID              string    `json:"tenant_id"`
	SiteID                string    `json:"site_id"`
	NodeID                string    `json:"node_id"`
	ConfigVersionID       string    `json:"config_version_id"`
	InstallationID        string    `json:"installation_id"`
	PackageSubscriptionID string    `json:"package_subscription_id"`
	RUMMinuteData
}

type RUMMinuteEnvelope struct {
	SchemaVersion         uint16           `json:"schema_version"`
	Type                  string           `json:"type"`
	MessageID             string           `json:"message_id"`
	ProducedAt            time.Time        `json:"produced_at"`
	TenantID              string           `json:"tenant_id"`
	InstallationID        string           `json:"installation_id"`
	NodeID                string           `json:"node_id"`
	PackageSubscriptionID string           `json:"package_subscription_id"`
	Events                []RUMMinuteEvent `json:"events"`
}

// RUMMinuteEventID is deterministic per (node, site, minute).
func RUMMinuteEventID(nodeID, siteID string, minute time.Time) string {
	encoded, _ := json.Marshal([]any{strings.ToLower(nodeID), strings.ToLower(siteID), minute.UTC().Unix()})
	digest := sha256.Sum256(append([]byte("cdnca.rum-minute.event/v1\x00"), encoded...))
	return "rum_minute_" + hex.EncodeToString(digest[:])
}

// RUMMinuteMessageID covers everything but the gateway's binding.
func RUMMinuteMessageID(envelope RUMMinuteEnvelope) string {
	envelope.MessageID, envelope.InstallationID, envelope.PackageSubscriptionID = "", "", ""
	envelope.Events = append([]RUMMinuteEvent(nil), envelope.Events...)
	for i := range envelope.Events {
		envelope.Events[i].InstallationID, envelope.Events[i].PackageSubscriptionID = "", ""
	}
	encoded, _ := json.Marshal(envelope)
	digest := sha256.Sum256(append([]byte("cdnca.rum-minute.message/v1\x00"), encoded...))
	return "rum_minute_message_" + hex.EncodeToString(digest[:])
}

var (
	rumPagePattern    = regexp.MustCompile(`^/[\x21-\x7e]{0,127}$`)
	rumHostPattern    = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$`)
	rumCountryPattern = regexp.MustCompile(`^([A-Z]{2}|--)$`)
	rumElements       = map[string]bool{"": true, "img": true, "script": true, "link": true, "iframe": true, "video": true, "audio": true}
	rumKinds          = map[string]bool{"resource": true, "navigation": true, "fetch": true, "xhr": true}
	rumDevices        = map[string]bool{"desktop": true, "mobile": true, "tablet": true}
	rumMetricSet      = map[string]bool{"lcp": true, "inp": true, "cls": true, "fcp": true, "ttfb": true}
)

func rumCount(value int64) bool { return value >= 0 && value <= RUMMaxValue }

func validRUMSeries(series RUMSeries) bool {
	switch series.Dimension {
	case "all":
		if series.Value != "" {
			return false
		}
	case "page":
		if series.Value != RUMOther && !rumPagePattern.MatchString(series.Value) {
			return false
		}
	case "country":
		if series.Value != RUMOther && !rumCountryPattern.MatchString(series.Value) {
			return false
		}
	case "device":
		if !rumDevices[series.Value] {
			return false
		}
	default:
		return false
	}
	if !rumCount(series.Views) || series.Histograms == nil {
		return false
	}
	for metric, histogram := range series.Histograms {
		if !rumMetricSet[metric] || len(histogram) == 0 {
			return false
		}
		for bucket, count := range histogram {
			if int(bucket) > RUMMaxBucket || count <= 0 || count > RUMMaxValue {
				return false
			}
		}
	}
	return true
}

// ValidRUMError checks one error group.
func ValidRUMError(e RUMError) bool {
	if !rumKinds[e.Kind] || !rumElements[e.Element] || (e.Status != 0 && (e.Status < 400 || e.Status > 599)) ||
		e.Count <= 0 || e.Count > RUMMaxValue {
		return false
	}
	return rumPagePattern.MatchString(e.Target) || rumHostPattern.MatchString(e.Target)
}

// Valid checks the node's data: bounded, every series and error valid,
// each (dimension, value) and each error group once.
func (data RUMMinuteData) Valid() bool {
	if len(data.Series) == 0 || len(data.Series) > RUMMaxSeries || len(data.Errors) > RUMMaxErrors || !rumCount(data.Dropped) {
		return false
	}
	seen := map[[2]string]bool{}
	buckets := 0
	for _, series := range data.Series {
		key := [2]string{series.Dimension, series.Value}
		if seen[key] || !validRUMSeries(series) {
			return false
		}
		seen[key] = true
		for _, histogram := range series.Histograms {
			buckets += len(histogram)
		}
	}
	if buckets > RUMMaxBuckets || !seen[[2]string{"all", ""}] {
		return false
	}
	groups := map[RUMError]bool{}
	for _, e := range data.Errors {
		key := e
		key.Count = 0
		if groups[key] || !ValidRUMError(e) {
			return false
		}
		groups[key] = true
	}
	return true
}

// ValidRUMMinuteEvent checks the node's fields (not the binding).
func ValidRUMMinuteEvent(event RUMMinuteEvent) bool {
	if event.MetricVersion != 1 || event.Minute.IsZero() || event.Minute.Location() != time.UTC ||
		!event.Minute.Equal(event.Minute.Truncate(time.Minute)) ||
		event.EventID != RUMMinuteEventID(event.NodeID, event.SiteID, event.Minute) {
		return false
	}
	for _, value := range []string{event.TenantID, event.SiteID, event.NodeID, event.ConfigVersionID} {
		if !uuidPattern.MatchString(value) || value == "00000000-0000-0000-0000-000000000000" || value != strings.ToLower(value) {
			return false
		}
	}
	return event.RUMMinuteData.Valid()
}
