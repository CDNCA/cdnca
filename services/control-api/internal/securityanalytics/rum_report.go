package securityanalytics

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

// The 真实用户体验 report: rum_minutes_v1 / rum_errors_v1
// (ClickHouse 034) read with the query identity, like the CC statistics.
// p75 and the good / needs improvement / poor shares come from the merged
// histograms (edgeconfig.RUMHistogram, within 4%).

const (
	RUMMinuteTable = "rum_minutes_v1"
	RUMErrorTable  = "rum_errors_v1"
	RUMReportTop   = 50
)

// RUMThresholds are the Web Vitals thresholds (good <= [0], poor > [1]);
// cls in score units.
var RUMThresholds = map[string][2]float64{
	"lcp": {2500, 4000}, "inp": {200, 500}, "cls": {0.1, 0.25}, "fcp": {1800, 3000}, "ttfb": {800, 1800},
}

// RUMMetricSummary is one metric over the range.
type RUMMetricSummary struct {
	P75              float64 `json:"p75"`
	Samples          int64   `json:"samples"`
	Good             float64 `json:"good"`
	NeedsImprovement float64 `json:"needs_improvement"`
	Poor             float64 `json:"poor"`
}

// RUMPoint is one step of the trend (P75 has only the measured metrics).
type RUMPoint struct {
	At    time.Time          `json:"at"`
	Views int64              `json:"views"`
	P75   map[string]float64 `json:"p75"`
}

// RUMBreakdown is one page, country or device.
type RUMBreakdown struct {
	Value string             `json:"value"`
	Views int64              `json:"views"`
	P75   map[string]float64 `json:"p75"`
}

// RUMErrorTotal is one error group over the range.
type RUMErrorTotal struct {
	Kind    string `json:"kind"`
	Element string `json:"element"`
	Target  string `json:"target"`
	Status  int    `json:"status"`
	Count   int64  `json:"count"`
}

// RUMSiteReport is a site's report over [From, To).
type RUMSiteReport struct {
	SiteID      uuid.UUID                   `json:"site_id"`
	From        time.Time                   `json:"from"`
	To          time.Time                   `json:"to"`
	StepSeconds int64                       `json:"step_seconds"`
	Views       int64                       `json:"views"`
	Dropped     int64                       `json:"dropped"`
	Thresholds  map[string][2]float64       `json:"thresholds"`
	Summary     map[string]RUMMetricSummary `json:"summary"`
	Series      []RUMPoint                  `json:"series"`
	Pages       []RUMBreakdown              `json:"pages"`
	Countries   []RUMBreakdown              `json:"countries"`
	Devices     []RUMBreakdown              `json:"devices"`
	Errors      []RUMErrorTotal             `json:"errors"`
}

func rumValue(metric string, bucketValue float64) float64 {
	if metric == "cls" {
		return math.Round(bucketValue) / 1000
	}
	return math.Round(bucketValue)
}

func rumP75(histograms map[string]edgeconfig.RUMHistogram) map[string]float64 {
	out := map[string]float64{}
	for _, metric := range edgeconfig.RUMMetrics {
		if value, ok := histograms[metric].Quantile(0.75); ok {
			out[metric] = rumValue(metric, value)
		}
	}
	return out
}

func rumSummary(metric string, histogram edgeconfig.RUMHistogram) (RUMMetricSummary, bool) {
	p75, ok := histogram.Quantile(0.75)
	if !ok {
		return RUMMetricSummary{}, false
	}
	total := histogram.Count()
	summary := RUMMetricSummary{P75: rumValue(metric, p75), Samples: total}
	limits := RUMThresholds[metric]
	for bucket, count := range histogram {
		value := rumValue(metric, edgeconfig.RUMBucketValue(int(bucket)))
		share := float64(count) / float64(total)
		switch {
		case value <= limits[0]:
			summary.Good += share
		case value <= limits[1]:
			summary.NeedsImprovement += share
		default:
			summary.Poor += share
		}
	}
	return summary, true
}

const rumSums = `sum(views) AS out_views, sumMap(lcp) AS out_lcp, sumMap(inp) AS out_inp, sumMap(cls) AS out_cls,
	sumMap(fcp) AS out_fcp, sumMap(ttfb) AS out_ttfb`

const rumRange = `tenant_id = {tenant:UUID} AND site_id = {site:UUID}
	AND minute >= {from:DateTime('UTC')} AND minute < {to:DateTime('UTC')}`

type rumRow struct {
	At        int64                   `json:"out_at"`
	Dimension string                  `json:"dimension"`
	Value     string                  `json:"value"`
	Views     int64                   `json:"out_views"`
	Dropped   int64                   `json:"out_dropped"`
	LCP       edgeconfig.RUMHistogram `json:"out_lcp"`
	INP       edgeconfig.RUMHistogram `json:"out_inp"`
	CLS       edgeconfig.RUMHistogram `json:"out_cls"`
	FCP       edgeconfig.RUMHistogram `json:"out_fcp"`
	TTFB      edgeconfig.RUMHistogram `json:"out_ttfb"`
}

func (row rumRow) histograms() map[string]edgeconfig.RUMHistogram {
	return map[string]edgeconfig.RUMHistogram{"lcp": row.LCP, "inp": row.INP, "cls": row.CLS, "fcp": row.FCP, "ttfb": row.TTFB}
}

// SiteRUMReport reads a site's report; step is a whole number of minutes.
func (ch *ClickHouse) SiteRUMReport(ctx context.Context, tenant, site uuid.UUID, from, to time.Time, step time.Duration) (RUMSiteReport, error) {
	seconds := int64(step / time.Second)
	if seconds < 60 || seconds%60 != 0 || !to.After(from) {
		return RUMSiteReport{}, ErrInvalidConfig
	}
	params := map[string]string{"tenant": tenant.String(), "site": site.String(), "step": strconv.FormatInt(seconds, 10),
		"from": from.UTC().Format(time.DateTime), "to": to.UTC().Format(time.DateTime), "top": strconv.Itoa(RUMReportTop)}
	out := RUMSiteReport{SiteID: site, From: from.UTC(), To: to.UTC(), StepSeconds: seconds, Thresholds: RUMThresholds,
		Summary: map[string]RUMMetricSummary{}, Series: []RUMPoint{}, Pages: []RUMBreakdown{}, Countries: []RUMBreakdown{},
		Devices: []RUMBreakdown{}, Errors: []RUMErrorTotal{}}
	decode := func(line []byte) (rumRow, error) {
		var row rumRow
		err := json.Unmarshal(line, &row)
		return row, err
	}

	if err := ch.queryRows(ctx, `SELECT toUnixTimestamp(toStartOfInterval(minute, toIntervalSecond({step:UInt32}))) AS out_at, `+
		rumSums+` FROM `+RUMMinuteTable+` FINAL WHERE `+rumRange+` AND dimension = 'all' GROUP BY out_at ORDER BY out_at`,
		params, func(line []byte) error {
			row, err := decode(line)
			if err == nil {
				out.Series = append(out.Series, RUMPoint{At: time.Unix(row.At, 0).UTC(), Views: row.Views, P75: rumP75(row.histograms())})
			}
			return err
		}); err != nil {
		return RUMSiteReport{}, err
	}

	if err := ch.queryRows(ctx, `SELECT `+rumSums+`, sum(dropped) AS out_dropped FROM `+RUMMinuteTable+` FINAL WHERE `+rumRange+
		` AND dimension = 'all'`, params, func(line []byte) error {
		row, err := decode(line)
		if err != nil {
			return err
		}
		out.Views, out.Dropped = row.Views, row.Dropped
		for metric, histogram := range row.histograms() {
			if summary, ok := rumSummary(metric, histogram); ok {
				out.Summary[metric] = summary
			}
		}
		return nil
	}); err != nil {
		return RUMSiteReport{}, err
	}

	if err := ch.queryRows(ctx, `SELECT dimension, value, `+rumSums+` FROM `+RUMMinuteTable+` FINAL WHERE `+rumRange+
		` AND dimension IN ('page', 'country', 'device') GROUP BY dimension, value
		ORDER BY dimension, out_views DESC, value LIMIT {top:UInt32} BY dimension`, params, func(line []byte) error {
		row, err := decode(line)
		if err != nil {
			return err
		}
		item := RUMBreakdown{Value: row.Value, Views: row.Views, P75: rumP75(row.histograms())}
		switch row.Dimension {
		case "page":
			out.Pages = append(out.Pages, item)
		case "country":
			out.Countries = append(out.Countries, item)
		case "device":
			out.Devices = append(out.Devices, item)
		}
		return nil
	}); err != nil {
		return RUMSiteReport{}, err
	}

	if err := ch.queryRows(ctx, `SELECT kind, element, target, status, sum(count) AS count FROM `+RUMErrorTable+` FINAL WHERE `+
		rumRange+` GROUP BY kind, element, target, status ORDER BY count DESC, kind, target LIMIT {top:UInt32}`,
		params, func(line []byte) error {
			var row RUMErrorTotal
			if err := json.Unmarshal(line, &row); err != nil {
				return err
			}
			out.Errors = append(out.Errors, row)
			return nil
		}); err != nil {
		return RUMSiteReport{}, err
	}
	return out, nil
}
