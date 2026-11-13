package nodemetrics

import (
	"context"
	"math"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// trafficBucket is one node's samples inside one UTC hour, reduced to what the
// monthly total needs: the first and last counter reading, the traffic added
// inside the hour, the counter resets and whether any gap exceeded 5 minutes.
// It is built with the same per-pair rule as summarizeMonthlyTraffic.
type trafficBucket struct {
	samples          int
	firstAt, lastAt  time.Time
	firstRX, firstTX uint64
	lastRX, lastTX   uint64
	usage            uint64
	resets           int
	gap              bool
}

// pointDelta is the traffic between two consecutive readings; a counter that
// went down restarted from zero, so its reading is the traffic since then.
func pointDelta(previous, current monthlyTrafficPoint) (delta uint64, reset bool, ok bool) {
	rxDelta, txDelta := current.rxBytes-previous.rxBytes, current.txBytes-previous.txBytes
	if current.rxBytes < previous.rxBytes || current.txBytes < previous.txBytes {
		reset = true
		if current.rxBytes < previous.rxBytes {
			rxDelta = current.rxBytes
		}
		if current.txBytes < previous.txBytes {
			txDelta = current.txBytes
		}
	}
	if math.MaxUint64-rxDelta < txDelta {
		return 0, reset, false
	}
	return rxDelta + txDelta, reset, true
}

// add appends a reading that is not earlier than the bucket's last one.
func (bucket *trafficBucket) add(point monthlyTrafficPoint) error {
	if bucket.samples == 0 {
		*bucket = trafficBucket{samples: 1, firstAt: point.observedAt, lastAt: point.observedAt,
			firstRX: point.rxBytes, firstTX: point.txBytes, lastRX: point.rxBytes, lastTX: point.txBytes}
		return nil
	}
	previous := monthlyTrafficPoint{observedAt: bucket.lastAt, rxBytes: bucket.lastRX, txBytes: bucket.lastTX}
	delta, reset, ok := pointDelta(previous, point)
	if !ok || math.MaxUint64-bucket.usage < delta {
		return ErrInvalidSample
	}
	bucket.usage += delta
	if reset {
		bucket.resets++
	}
	if point.observedAt.Sub(previous.observedAt) > 5*time.Minute {
		bucket.gap = true
	}
	bucket.samples++
	bucket.lastAt, bucket.lastRX, bucket.lastTX = point.observedAt, point.rxBytes, point.txBytes
	return nil
}

func hourOf(at time.Time) time.Time { return at.UTC().Truncate(time.Hour) }

// recordTrafficHour folds one stored sample into its hour bucket. Samples arrive
// almost always in time order, which is a constant-time update; a sample that
// ties or precedes the bucket's last one rebuilds the hour from the raw rows so
// the result stays identical to the full scan.
func recordTrafficHour(ctx context.Context, tx pgx.Tx, nodeID string, point monthlyTrafficPoint) error {
	point.observedAt = point.observedAt.UTC().Truncate(time.Microsecond)
	hour := hourOf(point.observedAt)
	var bucket trafficBucket
	var firstRX, firstTX, lastRX, lastTX, usage string
	err := tx.QueryRow(ctx, `
		SELECT samples,first_observed_at,first_rx::text,first_tx::text,last_observed_at,last_rx::text,last_tx::text,
		       usage_bytes::text,counter_resets,has_gap
		FROM node_traffic_hourly WHERE node_id=$1::uuid AND hour_start=$2 FOR UPDATE`, nodeID, hour).Scan(
		&bucket.samples, &bucket.firstAt, &firstRX, &firstTX, &bucket.lastAt, &lastRX, &lastTX,
		&usage, &bucket.resets, &bucket.gap)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == pgx.ErrNoRows {
		bucket = trafficBucket{}
	} else {
		for index, target := range []*uint64{&bucket.firstRX, &bucket.firstTX, &bucket.lastRX, &bucket.lastTX, &bucket.usage} {
			if *target, err = strconv.ParseUint([]string{firstRX, firstTX, lastRX, lastTX, usage}[index], 10, 64); err != nil {
				return ErrInvalidSample
			}
		}
		bucket.firstAt, bucket.lastAt = bucket.firstAt.UTC(), bucket.lastAt.UTC()
	}
	if bucket.samples == 0 || point.observedAt.After(bucket.lastAt) {
		if err := bucket.add(point); err != nil {
			return err
		}
	} else if bucket, err = rebuildTrafficHour(ctx, tx, nodeID, hour); err != nil {
		return err
	}
	return saveTrafficBucket(ctx, tx, nodeID, hour, bucket)
}

func u64(value uint64) string { return strconv.FormatUint(value, 10) }

// rebuildTrafficHour recomputes one hour bucket from the raw samples, in the
// order the full scan uses.
func rebuildTrafficHour(ctx context.Context, tx pgx.Tx, nodeID string, hour time.Time) (trafficBucket, error) {
	rows, err := tx.Query(ctx, `
		SELECT observed_at,telemetry_json FROM node_metric_samples
		WHERE node_id=$1::uuid AND record_kind IN ('metric','host_metric') AND telemetry_json IS NOT NULL
		  AND observed_at >= $2 AND observed_at < $3
		ORDER BY observed_at,publication_sequence`, nodeID, hour, hour.Add(time.Hour))
	if err != nil {
		return trafficBucket{}, err
	}
	defer rows.Close()
	var bucket trafficBucket
	for rows.Next() {
		var observedAt time.Time
		var payload []byte
		if err := rows.Scan(&observedAt, &payload); err != nil {
			return trafficBucket{}, err
		}
		var telemetry *Telemetry
		if err := decodeStoredTelemetry(payload, &telemetry); err != nil {
			return trafficBucket{}, err
		}
		rx, txBytes, ok := selectedCounterTotals(telemetry)
		if !ok {
			continue
		}
		if err := bucket.add(monthlyTrafficPoint{observedAt: observedAt.UTC(), rxBytes: rx, txBytes: txBytes}); err != nil {
			return trafficBucket{}, err
		}
	}
	return bucket, rows.Err()
}

func saveTrafficBucket(ctx context.Context, tx pgx.Tx, nodeID string, hour time.Time, bucket trafficBucket) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO node_traffic_hourly(node_id,hour_start,samples,first_observed_at,first_rx,first_tx,
			last_observed_at,last_rx,last_tx,usage_bytes,counter_resets,has_gap)
		VALUES($1::uuid,$2,$3,$4,$5::numeric,$6::numeric,$7,$8::numeric,$9::numeric,$10::numeric,$11,$12)
		ON CONFLICT (node_id,hour_start) DO UPDATE SET samples=EXCLUDED.samples,
			first_observed_at=EXCLUDED.first_observed_at,first_rx=EXCLUDED.first_rx,first_tx=EXCLUDED.first_tx,
			last_observed_at=EXCLUDED.last_observed_at,last_rx=EXCLUDED.last_rx,last_tx=EXCLUDED.last_tx,
			usage_bytes=EXCLUDED.usage_bytes,counter_resets=EXCLUDED.counter_resets,has_gap=EXCLUDED.has_gap`,
		nodeID, hour, bucket.samples, bucket.firstAt, u64(bucket.firstRX), u64(bucket.firstTX), bucket.lastAt,
		u64(bucket.lastRX), u64(bucket.lastTX), u64(bucket.usage), bucket.resets, bucket.gap)
	return err
}

// trafficRepairWindow is how far back RepairRecentTraffic looks. A hot upgrade
// runs the migration first and swaps the binary some seconds to minutes later;
// samples the old binary stored in between never reached the hour buckets.
const trafficRepairWindow = 3 * time.Hour

// RepairRecentTraffic rebuilds, from the raw samples, every hour bucket that has
// a sample in the last three hours. It is idempotent and takes the same per-node
// lock as the insert guard, so it can run while samples are being stored.
func (store *PostgresStore) RepairRecentTraffic(ctx context.Context, now time.Time) error {
	if store == nil || store.pool == nil || ctx == nil || now.IsZero() {
		return ErrInvalidConfiguration
	}
	rows, err := store.pool.Query(ctx, `
		SELECT DISTINCT node_id::text, date_trunc('hour', observed_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
		FROM node_metric_samples
		WHERE record_kind IN ('metric','host_metric') AND telemetry_json IS NOT NULL AND observed_at >= $1
		ORDER BY 1,2`, hourOf(now.Add(-trafficRepairWindow)))
	if err != nil {
		return err
	}
	type hourKey struct {
		node string
		hour time.Time
	}
	var keys []hourKey
	for rows.Next() {
		var key hourKey
		if err := rows.Scan(&key.node, &key.hour); err != nil {
			rows.Close()
			return err
		}
		key.hour = key.hour.UTC()
		keys = append(keys, key)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 150))`, key.node); err != nil {
				return err
			}
			bucket, err := rebuildTrafficHour(ctx, tx, key.node, key.hour)
			if err != nil {
				return err
			}
			if bucket.samples == 0 {
				_, err = tx.Exec(ctx, `DELETE FROM node_traffic_hourly WHERE node_id=$1::uuid AND hour_start=$2`, key.node, key.hour)
				return err
			}
			return saveTrafficBucket(ctx, tx, key.node, key.hour, bucket)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
