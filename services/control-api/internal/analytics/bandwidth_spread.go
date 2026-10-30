package analytics

import (
	"fmt"
	"time"
)

// Bandwidth peak and 95th percentile spread every request's response bytes
// evenly over its transfer, [occurred_at-duration_us, occurred_at] (the node
// logs $request_time as duration_us), instead of putting the whole response in
// the second the request finished: a 1 GB download that took 100 seconds is
// 80 Mbit/s for 100 seconds, not 8 Gbit/s for one second.
//
//   - peak: the busiest 1-second sample.
//   - 95th: the 95th percentile of the 5-minute samples of the whole window,
//     idle samples included (the usual CDN billing basis).
//
// Arithmetic is integer (milli-bytes, Int128) so the same rows always give
// the same value and evidence digest.
const (
	bandwidthPeakSampleMS = int64(time.Second / time.Millisecond)
	bandwidth95SampleMS   = int64(5 * time.Minute / time.Millisecond)
	// bandwidthSpreadMaxDuration caps one request's transfer time. It bounds
	// how far after a window a request that still sent bytes inside it can
	// finish, which is how far window queries scan past their end.
	bandwidthSpreadMaxDuration = 24 * time.Hour
	bandwidthSpreadMaxMS       = int64(bandwidthSpreadMaxDuration / time.Millisecond)
)

// bandwidthSpreadScanSQL is the occurred_at/duration predicate of facts that
// sent bytes inside [{from}, {to}) (named DateTime64(3,'UTC') parameters).
func bandwidthSpreadScanSQL(from, to string) string {
	return fmt.Sprintf(`occurred_at>={%[1]s:DateTime64(3,'UTC')}
      AND occurred_at<{%[2]s:DateTime64(3,'UTC')}+INTERVAL %[3]d SECOND
      AND toInt64(toUnixTimestamp64Milli(occurred_at))-least(toInt64(intDiv(duration_us,1000)),%[4]d)<toInt64(toUnixTimestamp64Milli({%[2]s:DateTime64(3,'UTC')}))`,
		from, to, int64(bandwidthSpreadMaxDuration/time.Second), bandwidthSpreadMaxMS)
}

// bandwidthSpreadSamplesSQL returns a SELECT of (v UInt64 milli-bytes per
// sample, w UInt64 sample count) covering every unitMS sample of [{from},
// {to}). facts must yield e (Int64 end, epoch ms), d (Int64 duration ms,
// already capped) and b (Int128 bytes).
func bandwidthSpreadSamplesSQL(facts, from, to string, unitMS int64) string {
	return fmt.Sprintf(`SELECT v, w FROM (
WITH
    toInt64(toUnixTimestamp64Milli({%[2]s:DateTime64(3,'UTC')})) AS from_ms,
    toInt64(toUnixTimestamp64Milli({%[3]s:DateTime64(3,'UTC')})) AS to_ms,
    toInt64(%[4]d) AS unit_ms,
    intDiv(from_ms, unit_ms) AS from_bucket,
    intDiv(to_ms - 1, unit_ms) + 1 AS to_bucket,
    parts AS (
        SELECT intDiv(e - d, unit_ms) AS a, intDiv(if(d = 0, e, e - 1), unit_ms) AS z, e, d, b * 1000 AS m
        FROM (%[1]s)
    ),
    changes AS (
        SELECT k, sum(mass) AS mass, sum(delta) AS delta FROM (
            SELECT a AS k, if(a = z, m, intDiv(m * ((a + 1) * unit_ms - (e - d)), d)) AS mass, toInt128(0) AS delta
            FROM parts WHERE a >= from_bucket
            UNION ALL
            SELECT z, intDiv(m * (e - z * unit_ms), d), toInt128(0) FROM parts WHERE a < z AND z >= from_bucket
            UNION ALL
            SELECT greatest(a + 1, from_bucket), toInt128(0), intDiv(m * unit_ms, d) FROM parts WHERE greatest(a + 1, from_bucket) < z
            UNION ALL
            SELECT z, toInt128(0), -intDiv(m * unit_ms, d) FROM parts WHERE greatest(a + 1, from_bucket) < z
        ) GROUP BY k HAVING k >= from_bucket AND k < to_bucket
    ),
    levels AS (
        SELECT k, mass,
            sum(delta) OVER (ORDER BY k ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS rate,
            leadInFrame(k, 1, to_bucket) OVER (ORDER BY k ROWS BETWEEN CURRENT ROW AND 1 FOLLOWING) AS next_k
        FROM changes
    )
SELECT toUInt64(greatest(mass + rate, toInt128(0))) AS v, toUInt64(1) AS w FROM levels
UNION ALL
SELECT toUInt64(greatest(rate, toInt128(0))), toUInt64(next_k - k - 1) FROM levels WHERE next_k - k > 1
UNION ALL
SELECT toUInt64(0), toUInt64(greatest(coalesce((SELECT min(k) FROM changes), to_bucket) - from_bucket, 0))
) WHERE w > 0`, facts, from, to, unitMS)
}

// bandwidthSpreadFactsSQL turns a facts query's occurred_at, duration_us and
// response_bytes into the e/d/b columns bandwidthSpreadSamplesSQL reads.
const bandwidthSpreadFactsColumns = `toInt64(toUnixTimestamp64Milli(occurred_at)) AS e,
           least(toInt64(intDiv(duration_us, 1000)), toInt64(%d)) AS d,
           toInt128(response_bytes) AS b`

func bandwidthSpreadColumns() string {
	return fmt.Sprintf(bandwidthSpreadFactsColumns, bandwidthSpreadMaxMS)
}

// bandwidthSpreadBPSSQL converts a sample value (milli-bytes per unitMS) to
// bit/s: v/1000 bytes * 8 / (unitMS/1000 s).
func bandwidthSpreadBPSSQL(value string, unitMS int64) string {
	return fmt.Sprintf("toUInt64(intDiv(toUInt128(%s) * 8, %d))", value, unitMS)
}

// clickHouseTime formats a UTC instant for a {name:DateTime64(3,'UTC')}
// query parameter. ClickHouse does not parse RFC 3339's trailing "Z" in query
// parameters (BAD_QUERY_PARAMETER), whatever date_time_input_format says.
func clickHouseTime(value time.Time) string {
	return value.UTC().Format("2006-01-02 15:04:05.000")
}
