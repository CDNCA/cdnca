package nodeserving

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	autoDisableBatch           = 2000
	defaultAutoDisableTimezone = "Asia/Shanghai"
)

// China Standard Time has no DST; it backs Asia/Shanghai on hosts without
// a zoneinfo database.
var chinaStandardTime = time.FixedZone("CST", 8*3600)

func loadLocation(name string) *time.Location {
	if location, err := time.LoadLocation(name); err == nil {
		return location
	}
	return chinaStandardTime
}

type autoDisableCandidate struct {
	nodeID, scopeID uuid.UUID
	active          bool
	settings        AutoDisableSettings
	timezone        string
	held            bool
	reason          string
	revision        int64
	heldSince       *time.Time
	usage           *UsageState
}

func (store *Store) autoDisableCandidates(ctx context.Context) ([]autoDisableCandidate, time.Time, error) {
	var now time.Time
	if err := store.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, time.Time{}, err
	}
	rows, err := store.pool.Query(ctx, `SELECT node.id,node.scope_id,node.admin_state='active',node.management_settings->'auto_disable',
			COALESCE(NULLIF(policy.timezone,''),$2),COALESCE(hold.held,false),COALESCE(hold.reason_code,''),
			COALESCE(hold.revision,0),hold.held_since,usage.period_start,usage.period_end,usage.settings_digest,
			usage.last_sequence,usage.counters,usage.usage_bytes,usage.over_streak,usage.under_streak,usage.last_bandwidth_bps
		FROM nodes node
		LEFT JOIN node_traffic_policies policy ON policy.scope_id=node.scope_id AND policy.node_id=node.id
		LEFT JOIN node_serving_holds hold ON hold.node_id=node.id AND hold.source=$1
		LEFT JOIN node_auto_disable_usage usage ON usage.node_id=node.id
		WHERE node.admin_state<>'retired' OR hold.held
		ORDER BY node.id`, SourceAutoDisable, defaultAutoDisableTimezone)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer rows.Close()
	var result []autoDisableCandidate
	for rows.Next() {
		var item autoDisableCandidate
		var raw []byte
		var start, end *time.Time
		var digest *string
		var last, usageBytes, bandwidth *int64
		var counters []byte
		var over, under *int32
		if err := rows.Scan(&item.nodeID, &item.scopeID, &item.active, &raw, &item.timezone, &item.held, &item.reason,
			&item.revision, &item.heldSince, &start, &end, &digest, &last, &counters, &usageBytes, &over, &under, &bandwidth); err != nil {
			return nil, time.Time{}, err
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &item.settings); err != nil {
				return nil, time.Time{}, fmt.Errorf("decode auto-disable settings of node %s: %w", item.nodeID, err)
			}
		}
		if start != nil && end != nil && digest != nil && last != nil && usageBytes != nil && over != nil && under != nil && bandwidth != nil {
			state := &UsageState{PeriodStart: start.UTC(), PeriodEnd: end.UTC(), Digest: *digest, LastSequence: *last,
				UsageBytes: uint64(*usageBytes), OverStreak: int(*over), UnderStreak: int(*under), LastBandwidthBPS: uint64(*bandwidth)}
			if err := json.Unmarshal(counters, &state.Counters); err != nil {
				return nil, time.Time{}, err
			}
			item.usage = state
		}
		if item.settings.Active() || item.held {
			result = append(result, item)
		}
	}
	return result, now, rows.Err()
}

// sequenceBefore is the newest telemetry sequence observed before start, so
// accounting replays exactly the period's samples. It walks this node's
// samples newest first and stops at the first older one.
func (store *Store) sequenceBefore(ctx context.Context, nodeID uuid.UUID, start time.Time) (int64, error) {
	var sequence int64
	err := store.pool.QueryRow(ctx, `SELECT publication_sequence FROM node_metric_samples
		WHERE node_id=$1 AND observed_at<$2 ORDER BY publication_sequence DESC LIMIT 1`, nodeID, start).Scan(&sequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return sequence, err
}

func (store *Store) networkSamples(ctx context.Context, nodeID uuid.UUID, after int64, end time.Time) ([]NetworkSample, error) {
	rows, err := store.pool.Query(ctx, `SELECT publication_sequence,observed_at,
			COALESCE(telemetry_json->'network_interfaces','[]'::jsonb)
		FROM node_metric_samples
		WHERE node_id=$1 AND publication_sequence>$2 AND telemetry_json IS NOT NULL AND observed_at<$3
		ORDER BY publication_sequence LIMIT $4`, nodeID, after, end, autoDisableBatch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []NetworkSample
	for rows.Next() {
		var sample NetworkSample
		var interfaces []byte
		if err := rows.Scan(&sample.Sequence, &sample.ObservedAt, &interfaces); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(interfaces, &sample.Interfaces); err != nil {
			return nil, fmt.Errorf("decode telemetry interfaces of node %s: %w", nodeID, err)
		}
		result = append(result, sample)
	}
	return result, rows.Err()
}

func (store *Store) saveUsage(ctx context.Context, nodeID uuid.UUID, state UsageState) error {
	counters, err := json.Marshal(state.Counters)
	if err != nil {
		return err
	}
	_, err = store.pool.Exec(ctx, `INSERT INTO node_auto_disable_usage(node_id,period_start,period_end,settings_digest,
			last_sequence,counters,usage_bytes,over_streak,under_streak,last_bandwidth_bps,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp())
		ON CONFLICT (node_id) DO UPDATE SET period_start=EXCLUDED.period_start,period_end=EXCLUDED.period_end,
			settings_digest=EXCLUDED.settings_digest,last_sequence=EXCLUDED.last_sequence,counters=EXCLUDED.counters,
			usage_bytes=EXCLUDED.usage_bytes,over_streak=EXCLUDED.over_streak,under_streak=EXCLUDED.under_streak,
			last_bandwidth_bps=EXCLUDED.last_bandwidth_bps,updated_at=EXCLUDED.updated_at`,
		nodeID, state.PeriodStart, state.PeriodEnd, state.Digest, state.LastSequence, counters,
		int64(min(state.UsageBytes, math.MaxInt64)), state.OverStreak, state.UnderStreak,
		int64(min(state.LastBandwidthBPS, math.MaxInt64)))
	return err
}

// bandwidthThreshold is the platform's "consecutive bandwidth over-limit"
// count from the active node monitoring policy.
func (store *Store) bandwidthThreshold(ctx context.Context, scopeID uuid.UUID) (int, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	configuration, value, err := systemconfig.ReadActiveNodeMonitoring(ctx, tx, scopeID)
	if errors.Is(err, systemconfig.ErrPermissionDenied) {
		return DefaultBandwidthOverLimit, nil
	}
	if err != nil {
		return 0, err
	}
	if configuration.State != "active" || value.BandwidthOverLimit == nil || *value.BandwidthOverLimit == 0 {
		return DefaultBandwidthOverLimit, nil
	}
	return int(*value.BandwidthOverLimit), nil
}

// AutoDisableEvaluator enforces nodes.management_settings.auto_disable.
type AutoDisableEvaluator struct {
	store *Store
}

func NewAutoDisableEvaluator(store *Store) *AutoDisableEvaluator {
	return &AutoDisableEvaluator{store: store}
}

func (evaluator *AutoDisableEvaluator) Evaluate(ctx context.Context) error {
	candidates, now, err := evaluator.store.autoDisableCandidates(ctx)
	if err != nil {
		return err
	}
	thresholds := map[uuid.UUID]int{}
	var first error
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := evaluator.evaluate(ctx, candidate, now, thresholds); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (evaluator *AutoDisableEvaluator) evaluate(ctx context.Context, candidate autoDisableCandidate, now time.Time,
	thresholds map[uuid.UUID]int) error {
	store := evaluator.store
	location := loadLocation(candidate.timezone)
	settings := candidate.settings
	start, end := settings.Period(now, location)
	var state UsageState
	if candidate.usage != nil {
		state = *candidate.usage
	}
	state, periodRestarted, settingsRestarted := state.Restart(settings, start, end)
	if periodRestarted || settingsRestarted {
		sequence, err := store.sequenceBefore(ctx, candidate.nodeID, start)
		if err != nil {
			return err
		}
		state.LastSequence = sequence
	}
	samples, err := store.networkSamples(ctx, candidate.nodeID, state.LastSequence, end)
	if err != nil {
		return err
	}
	state.Accumulate(settings, samples, now)
	if err := store.saveUsage(ctx, candidate.nodeID, state); err != nil {
		return err
	}
	threshold, ok := thresholds[candidate.scopeID]
	if !ok {
		if threshold, err = store.bandwidthThreshold(ctx, candidate.scopeID); err != nil {
			return err
		}
		thresholds[candidate.scopeID] = threshold
	}
	decision := DecideAutoDisable(AutoDisableInput{
		NodeActive: candidate.active, Settings: settings, Usage: state, Threshold: threshold,
		InDisabledPeriod: settings.InDisabledPeriod(now, location), Now: now,
		Held: candidate.held, Reason: candidate.reason, HeldSince: candidate.heldSince,
		PeriodRestarted: periodRestarted, SettingsRestarted: settingsRestarted,
		CatchingUp: len(samples) == autoDisableBatch,
	})
	if decision.Held == candidate.held && (!decision.Held || decision.Reason == candidate.reason) {
		return nil
	}
	_, err = store.Apply(ctx, candidate.nodeID, candidate.scopeID, SourceAutoDisable, candidate.revision, decision)
	return err
}
