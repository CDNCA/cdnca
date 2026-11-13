package nodemetrics

import (
	"context"
	"errors"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
)

const defaultMonthlyTrafficTimezone = "Asia/Shanghai"

type trafficPeriod struct {
	start, end    time.Time
	key, timezone string
}

type monthlyTrafficPoint struct {
	observedAt time.Time
	rxBytes    uint64
	txBytes    uint64
}

func (reader *PostgresReader) monthlyTraffic(ctx context.Context, scopeID uuid.UUID, nodeIDs []uuid.UUID, now time.Time) (map[uuid.UUID]MonthlyTraffic, error) {
	if reader == nil || reader.pool == nil || ctx == nil || scopeID == uuid.Nil || len(nodeIDs) == 0 || now.IsZero() {
		return nil, ErrInvalidConfiguration
	}
	rows, err := reader.pool.Query(ctx, `
		SELECT node.id,COALESCE(policy.timezone,$3)
		FROM unnest($2::uuid[]) requested(id)
		JOIN nodes node ON node.id=requested.id AND node.scope_id=$1
		LEFT JOIN node_traffic_policies policy ON policy.scope_id=node.scope_id AND policy.node_id=node.id
		ORDER BY node.id`, scopeID, nodeIDs, defaultMonthlyTrafficTimezone)
	if err != nil {
		return nil, err
	}
	timezones := make(map[uuid.UUID]string, len(nodeIDs))
	for rows.Next() {
		var nodeID uuid.UUID
		var timezone string
		if err := rows.Scan(&nodeID, &timezone); err != nil {
			rows.Close()
			return nil, err
		}
		if timezone == "" {
			timezone = defaultMonthlyTrafficTimezone
		}
		timezones[nodeID] = timezone
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(timezones) != len(nodeIDs) {
		return nil, ErrNotFound
	}

	result := make(map[uuid.UUID]MonthlyTraffic, len(nodeIDs))
	periods := make(map[uuid.UUID]trafficPeriod, len(nodeIDs))
	minimumStart := now.Add(-33 * 24 * time.Hour)
	scanIDs := make([]uuid.UUID, 0, len(nodeIDs))
	bucketIDs := make([]uuid.UUID, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		timezone := timezones[nodeID]
		location, loadErr := time.LoadLocation(timezone)
		if loadErr != nil {
			return nil, errors.Join(ErrInvalidSample, loadErr)
		}
		local := now.In(location)
		start := time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, location).UTC()
		end := time.Date(local.Year(), local.Month()+1, 1, 0, 0, 0, 0, location).UTC()
		periods[nodeID] = trafficPeriod{start: start, end: end, key: local.Format("2006-01"), timezone: timezone}
		result[nodeID] = MonthlyTraffic{State: "insufficient_data", PeriodKey: local.Format("2006-01"),
			PeriodStart: start, PeriodEnd: end, Timezone: timezone}
		if start.Before(minimumStart) {
			minimumStart = start
		}
		// Hour buckets are cut on UTC hours; a month that starts or ends
		// inside an hour (half-hour time zones) is scanned from raw samples.
		if start.Truncate(time.Hour).Equal(start) && end.Truncate(time.Hour).Equal(end) {
			bucketIDs = append(bucketIDs, nodeID)
		} else {
			scanIDs = append(scanIDs, nodeID)
		}
	}
	if len(bucketIDs) > 0 {
		if err := reader.bucketedTraffic(ctx, bucketIDs, periods, result, now); err != nil {
			return nil, err
		}
	}
	if len(scanIDs) == 0 {
		return result, nil
	}

	if err := reader.scanTraffic(ctx, scopeID, scanIDs, periods, result, minimumStart, now); err != nil {
		return nil, err
	}
	return result, nil
}

// scanTraffic computes the month from the raw samples: every sample of the
// period is read and its telemetry decoded. It serves months that do not start
// on a whole UTC hour and is the reference the hour buckets are tested against.
func (reader *PostgresReader) scanTraffic(ctx context.Context, scopeID uuid.UUID, scanIDs []uuid.UUID,
	periods map[uuid.UUID]trafficPeriod, result map[uuid.UUID]MonthlyTraffic, minimumStart, now time.Time) error {
	points := make(map[uuid.UUID][]monthlyTrafficPoint, len(scanIDs))
	rows, err := reader.pool.Query(ctx, `
		SELECT metric.node_id,metric.observed_at,metric.telemetry_json
		FROM node_metric_samples metric
		JOIN nodes node ON node.id=metric.node_id AND node.scope_id=$1
		WHERE metric.node_id = ANY($2::uuid[]) AND metric.record_kind IN ('metric','host_metric')
		  AND metric.telemetry_json IS NOT NULL AND metric.observed_at >= $3 AND metric.observed_at <= $4
		ORDER BY metric.node_id,metric.observed_at,metric.publication_sequence`, scopeID, scanIDs, minimumStart, now)
	if err != nil {
		return err
	}
	for rows.Next() {
		var nodeID uuid.UUID
		var observedAt time.Time
		var telemetryJSON []byte
		if err := rows.Scan(&nodeID, &observedAt, &telemetryJSON); err != nil {
			rows.Close()
			return err
		}
		period, ok := periods[nodeID]
		if !ok || observedAt.Before(period.start) || !observedAt.Before(period.end) {
			continue
		}
		var telemetry *Telemetry
		if err := decodeStoredTelemetry(telemetryJSON, &telemetry); err != nil {
			rows.Close()
			return err
		}
		rxBytes, txBytes, ok := selectedCounterTotals(telemetry)
		if !ok {
			continue
		}
		points[nodeID] = append(points[nodeID], monthlyTrafficPoint{observedAt: observedAt.UTC(), rxBytes: rxBytes, txBytes: txBytes})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, nodeID := range scanIDs {
		item := result[nodeID]
		values := points[nodeID]
		if len(values) < 2 {
			if len(values) == 1 {
				finalized := values[0].observedAt
				item.SourceFinalizedThrough = &finalized
				item.Samples = 1
				item.State = "insufficient_data"
			}
			result[nodeID] = item
			continue
		}
		summarized, err := summarizeMonthlyTraffic(item, values, now)
		if err != nil {
			return err
		}
		item = summarized
		result[nodeID] = item
	}
	return nil
}

// summarizeMonthlyTraffic sums the period's counter increments (at least
// two points).
func summarizeMonthlyTraffic(item MonthlyTraffic, values []monthlyTrafficPoint, now time.Time) (MonthlyTraffic, error) {
	sort.SliceStable(values, func(left, right int) bool { return values[left].observedAt.Before(values[right].observedAt) })
	item.Samples = len(values)
	finalized := values[len(values)-1].observedAt
	item.SourceFinalizedThrough = &finalized
	var usage uint64
	state := "available"
	for index := 1; index < len(values); index++ {
		previous, current := values[index-1], values[index]
		// A counter that went down restarted from zero (node reboot,
		// interface re-created): its reading is the traffic since then, so
		// the month keeps accumulating instead of stopping at the restart.
		rxDelta, txDelta := current.rxBytes-previous.rxBytes, current.txBytes-previous.txBytes
		if current.rxBytes < previous.rxBytes || current.txBytes < previous.txBytes {
			item.CounterResets++
			if current.rxBytes < previous.rxBytes {
				rxDelta = current.rxBytes
			}
			if current.txBytes < previous.txBytes {
				txDelta = current.txBytes
			}
		}
		if math.MaxUint64-usage < rxDelta || math.MaxUint64-usage-rxDelta < txDelta {
			return MonthlyTraffic{}, ErrInvalidSample
		}
		usage += rxDelta + txDelta
		if current.observedAt.Sub(previous.observedAt) > 5*time.Minute && state == "available" {
			state = "incomplete"
		}
	}
	if now.Sub(*item.SourceFinalizedThrough) > 2*time.Minute && state == "available" {
		state = "stale"
	}
	item.UsageBytes = usage
	item.State = state
	return item, nil
}

func selectedCounterTotals(telemetry *Telemetry) (uint64, uint64, bool) {
	if telemetry == nil || telemetry.NetworkSelection == nil || telemetry.NetworkSelection.Source != "default_route" || len(telemetry.NetworkSelection.Interfaces) == 0 {
		return 0, 0, false
	}
	interfaces := make(map[string]NetworkInterface, len(telemetry.NetworkInterfaces))
	for _, network := range telemetry.NetworkInterfaces {
		interfaces[network.Name] = network
	}
	var rx, tx uint64
	for _, name := range telemetry.NetworkSelection.Interfaces {
		network, ok := interfaces[name]
		if !ok || math.MaxUint64-rx < network.RXBytes || math.MaxUint64-tx < network.TXBytes {
			return 0, 0, false
		}
		rx += network.RXBytes
		tx += network.TXBytes
	}
	return rx, tx, true
}

// bucketedTraffic fills result from node_traffic_hourly: the buckets of the
// node's month plus the step between each bucket's last reading and the next
// bucket's first, which follows the same rules as a step inside a bucket.
func (reader *PostgresReader) bucketedTraffic(ctx context.Context, nodeIDs []uuid.UUID,
	periods map[uuid.UUID]trafficPeriod, result map[uuid.UUID]MonthlyTraffic, now time.Time) error {
	starts := make([]time.Time, len(nodeIDs))
	ends := make([]time.Time, len(nodeIDs))
	for index, nodeID := range nodeIDs {
		starts[index], ends[index] = periods[nodeID].start, periods[nodeID].end
	}
	rows, err := reader.pool.Query(ctx, `
		WITH req AS (
			SELECT * FROM unnest($1::uuid[],$2::timestamptz[],$3::timestamptz[]) AS r(node_id,pstart,pend)
		), b AS (
			SELECT h.*,
			       lag(h.last_observed_at) OVER w AS prev_at, lag(h.last_rx) OVER w AS prev_rx, lag(h.last_tx) OVER w AS prev_tx
			FROM node_traffic_hourly h JOIN req ON req.node_id=h.node_id
			WHERE h.hour_start >= req.pstart AND h.hour_start < req.pend AND h.hour_start <= $4
			WINDOW w AS (PARTITION BY h.node_id ORDER BY h.hour_start)
		)
		SELECT node_id, sum(samples)::bigint, max(last_observed_at),
		       (sum(usage_bytes) + COALESCE(sum(CASE WHEN prev_at IS NULL THEN 0 ELSE
		            (CASE WHEN first_rx < prev_rx THEN first_rx ELSE first_rx - prev_rx END) +
		            (CASE WHEN first_tx < prev_tx THEN first_tx ELSE first_tx - prev_tx END) END),0))::text,
		       (sum(counter_resets) + count(*) FILTER (WHERE prev_at IS NOT NULL AND (first_rx < prev_rx OR first_tx < prev_tx)))::bigint,
		       bool_or(has_gap OR (prev_at IS NOT NULL AND first_observed_at - prev_at > interval '5 minutes'))
		FROM b GROUP BY node_id`, nodeIDs, starts, ends, now)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID uuid.UUID
		var samples, resets int64
		var finalized time.Time
		var usageText string
		var gap bool
		if err := rows.Scan(&nodeID, &samples, &finalized, &usageText, &resets, &gap); err != nil {
			return err
		}
		item := result[nodeID]
		finalized = finalized.UTC()
		item.SourceFinalizedThrough = &finalized
		item.Samples = int(samples)
		if samples < 2 {
			result[nodeID] = item
			continue
		}
		usage, err := strconv.ParseUint(usageText, 10, 64)
		if err != nil {
			return ErrInvalidSample
		}
		item.UsageBytes, item.CounterResets = usage, int(resets)
		item.State = "available"
		if gap {
			item.State = "incomplete"
		} else if now.Sub(finalized) > 2*time.Minute {
			item.State = "stale"
		}
		result[nodeID] = item
	}
	return rows.Err()
}
