package dnspupprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// ActionPurposes audits a purposes change.
const ActionPurposes = "system.probe_dnspup.purposes"

// ErrBudgetStopped: the purpose is disabled, at its monthly cap or stopped
// for the account budget; callers fall back to their next source.
var ErrBudgetStopped = errors.New("dnspup: purpose stopped by its budget")

var purposeOrder = []string{PurposeNodeAvailability, PurposeOriginFailover, PurposeEdgeHealth, PurposePlugin, PurposeDiagnose}

// PurposeStatus is one purpose on the page.
type PurposeStatus struct {
	Purpose         string `json:"purpose"`
	Class           int    `json:"class"`
	Enabled         bool   `json:"enabled"`
	MonthlyCap      int64  `json:"monthly_cap"`
	IntervalSeconds int    `json:"interval_seconds"`
	// ProbeType is set for edge_health only (tcping / https).
	ProbeType     string `json:"probe_type,omitempty"`
	UsedThisMonth int64  `json:"used_this_month"`
	Gate          Gate   `json:"gate"`
}

// PurposesView is GET /v1/admin/probe-dnspup/purposes.
type PurposesView struct {
	Purposes     []PurposeStatus `json:"purposes"`
	MonthlyLimit int64           `json:"monthly_limit"`
	MonthlyUsed  int64           `json:"monthly_used"`
	// ProjectedMonthly is the sum of the purposes' projections.
	ProjectedMonthly int64 `json:"projected_monthly"`
}

// PurposeInput is one row of PUT /v1/admin/probe-dnspup/purposes.
type PurposeInput struct {
	Purpose         string `json:"purpose"`
	Enabled         *bool  `json:"enabled"`
	MonthlyCap      *int64 `json:"monthly_cap"`
	IntervalSeconds *int   `json:"interval_seconds"`
	// ProbeType: edge_health only, tcping / https; omitted keeps the stored type.
	ProbeType *string `json:"probe_type,omitempty"`
}

// EdgeProbeTypes are the probe types the edge_health purpose may use.
var EdgeProbeTypes = []string{"tcping", "https"}

func monthOf(now time.Time) time.Time {
	now = now.UTC()
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// readPurposes reads the purposes, this month's usage and the account, and
// plans the gates.
func readPurposes(ctx context.Context, db queryRower, now time.Time) (PurposesView, error) {
	view := PurposesView{}
	querier, ok := db.(interface {
		Query(context.Context, string, ...any) (pgx.Rows, error)
	})
	if !ok {
		return view, errors.New("dnspup purposes: querier required")
	}
	rows, err := querier.Query(ctx, `SELECT purpose.purpose,purpose.enabled,purpose.monthly_cap,purpose.interval_seconds,
		COALESCE(purpose.probe_type,''),COALESCE(usage.requests,0) FROM probe_dnspup_purposes purpose
		LEFT JOIN probe_dnspup_usage usage ON usage.purpose=purpose.purpose AND usage.month=$1`, monthOf(now))
	if err != nil {
		return view, err
	}
	byName := map[string]PurposeStatus{}
	for rows.Next() {
		var item PurposeStatus
		if err := rows.Scan(&item.Purpose, &item.Enabled, &item.MonthlyCap, &item.IntervalSeconds, &item.ProbeType,
			&item.UsedThisMonth); err != nil {
			rows.Close()
			return view, err
		}
		item.Class = PurposeClasses[item.Purpose]
		byName[item.Purpose] = item
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return view, err
	}
	if err := db.QueryRow(ctx, `SELECT monthly_limit,monthly_used FROM probe_dnspup_state WHERE singleton`).Scan(
		&view.MonthlyLimit, &view.MonthlyUsed); err != nil {
		return view, err
	}
	var inputs []Purpose
	for _, name := range purposeOrder {
		if item, ok := byName[name]; ok {
			inputs = append(inputs, Purpose{Name: name, Class: item.Class, Enabled: item.Enabled,
				MonthlyCap: item.MonthlyCap, Used: item.UsedThisMonth})
		}
	}
	plan := PlanBudget(inputs, view.MonthlyLimit, view.MonthlyUsed, now)
	for _, name := range purposeOrder {
		item, ok := byName[name]
		if !ok {
			continue
		}
		item.Gate = plan[name]
		view.ProjectedMonthly += item.Gate.ProjectedMonthly
		view.Purposes = append(view.Purposes, item)
	}
	return view, nil
}

// gates are the runtime's per-purpose gate, minimum interval and probe type.
func gates(view PurposesView) (map[string]Gate, map[string]time.Duration, map[string]string) {
	out, intervals, types := map[string]Gate{}, map[string]time.Duration{}, map[string]string{}
	for _, item := range view.Purposes {
		out[item.Purpose] = item.Gate
		intervals[item.Purpose] = time.Duration(item.IntervalSeconds) * time.Second
		if item.ProbeType != "" {
			types[item.Purpose] = item.ProbeType
		}
	}
	return out, intervals, types
}

// ProbeTypeFor is consumer's configured probe type, fallback when unset.
func (runtime Runtime) ProbeTypeFor(consumer, fallback string) string {
	if value := runtime.ProbeTypes[ConsumerPurposes[consumer]]; value != "" {
		return value
	}
	return fallback
}

// RoundFor is consumer's dnspup round: the runner's interval, raised to the
// purpose's minimum interval and stretched by its degrade factor. A round
// already delivered answers ErrDelivered, so a longer round probes less.
func (runtime Runtime) RoundFor(consumer string, now time.Time, interval time.Duration) int64 {
	return Round(now, runtime.IntervalFor(consumer, interval))
}

// IntervalFor is the effective interval behind RoundFor.
func (runtime Runtime) IntervalFor(consumer string, interval time.Duration) time.Duration {
	purpose := ConsumerPurposes[consumer]
	interval = max(interval, runtime.Intervals[purpose])
	if gate, ok := runtime.Gates[purpose]; ok && gate.Factor > 1 {
		interval *= time.Duration(gate.Factor)
	}
	return interval
}

// Stopped reports whether consumer's purpose may not create jobs now.
func (runtime Runtime) Stopped(consumer string) bool {
	gate, ok := runtime.Gates[ConsumerPurposes[consumer]]
	return ok && gate.Stopped
}

// meter counts one charged job under consumer's purpose.
func (service *Service) meter(consumer string) {
	purpose, ok := ConsumerPurposes[consumer]
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := service.config.Pool.Exec(ctx, `INSERT INTO probe_dnspup_usage(month,purpose,requests) VALUES($1,$2,1)
		ON CONFLICT (month,purpose) DO UPDATE SET requests=probe_dnspup_usage.requests+1`, monthOf(service.now()), purpose); err != nil {
		service.config.Logger.Warn("dnspup probe usage not recorded", "purpose", purpose, "error", err)
	}
}

// Purposes reads the page view (dnspup manage permission).
func (service *Service) Purposes(ctx context.Context, actor Actor) (PurposesView, error) {
	var view PurposesView
	err := pgx.BeginTxFunc(ctx, service.config.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, service.now()); err != nil {
			return err
		}
		var err error
		view, err = readPurposes(ctx, tx, service.now())
		return err
	})
	return view, err
}

// UpdatePurposes saves enabled / cap / interval of the listed purposes
// (idempotent per session + key), audits the change and answers the view.
// Availability purposes cannot be disabled here (node probing has its own
// interval switch; origin failover falls back to the other sources).
func (service *Service) UpdatePurposes(ctx context.Context, actor Actor, key string, inputs []PurposeInput) (PurposesView, error) {
	view, err := service.updatePurposes(ctx, actor, key, inputs)
	if err != nil {
		service.recordFailure(ctx, actor, ActionPurposes, err, map[string]any{})
	}
	return view, err
}

func (service *Service) updatePurposes(ctx context.Context, actor Actor, key string, inputs []PurposeInput) (PurposesView, error) {
	if !validKey(key) || len(inputs) == 0 || len(inputs) > len(purposeOrder) {
		return PurposesView{}, ErrInvalidInput
	}
	seen := map[string]bool{}
	for _, input := range inputs {
		if !slices.Contains(purposeOrder, input.Purpose) || seen[input.Purpose] || input.Enabled == nil ||
			input.MonthlyCap == nil || input.IntervalSeconds == nil || *input.MonthlyCap < 0 || *input.MonthlyCap > 1_000_000_000 ||
			*input.IntervalSeconds < 0 || *input.IntervalSeconds > 86400 ||
			!*input.Enabled && PurposeClasses[input.Purpose] == ClassAvailability ||
			input.ProbeType != nil && (input.Purpose != PurposeEdgeHealth || !slices.Contains(EdgeProbeTypes, *input.ProbeType)) {
			return PurposesView{}, ErrInvalidInput
		}
		seen[input.Purpose] = true
	}
	digest := requestDigest("purposes", inputs)
	now := service.now()
	var body []byte
	err := pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, now); err != nil {
			return err
		}
		stored, found, err := replay(ctx, tx, actor, key, digest)
		if err != nil || found {
			body = stored
			return err
		}
		before, err := readPurposes(ctx, tx, now)
		if err != nil {
			return err
		}
		changes := map[string]any{}
		for _, input := range inputs {
			if _, err := tx.Exec(ctx, `UPDATE probe_dnspup_purposes SET enabled=$2,monthly_cap=$3,interval_seconds=$4,
				probe_type=COALESCE($7,probe_type),updated_by_user_id=$5,updated_at=$6 WHERE purpose=$1`, input.Purpose,
				*input.Enabled, *input.MonthlyCap, *input.IntervalSeconds, actor.UserID, now, input.ProbeType); err != nil {
				return err
			}
			for _, item := range before.Purposes {
				if item.Purpose != input.Purpose {
					continue
				}
				probeType := item.ProbeType
				if input.ProbeType != nil {
					probeType = *input.ProbeType
				}
				left, _ := json.Marshal([]any{item.Enabled, item.MonthlyCap, item.IntervalSeconds, item.ProbeType})
				right, _ := json.Marshal([]any{*input.Enabled, *input.MonthlyCap, *input.IntervalSeconds, probeType})
				if !bytes.Equal(left, right) {
					before := map[string]any{"enabled": item.Enabled, "monthly_cap": item.MonthlyCap, "interval_seconds": item.IntervalSeconds}
					after := map[string]any{"enabled": *input.Enabled, "monthly_cap": *input.MonthlyCap, "interval_seconds": *input.IntervalSeconds}
					if input.Purpose == PurposeEdgeHealth {
						before["probe_type"], after["probe_type"] = item.ProbeType, probeType
					}
					changes[input.Purpose] = map[string]any{"before": before, "after": after}
				}
			}
		}
		if err := service.appendAudit(ctx, tx, &actor, ActionPurposes, "success", map[string]any{"changes": changes}); err != nil {
			return err
		}
		view, err := readPurposes(ctx, tx, now)
		if err != nil {
			return err
		}
		if body, err = json.Marshal(view); err != nil {
			return err
		}
		return recordWrite(ctx, tx, actor, key, "purposes", digest, body, now)
	})
	if err != nil {
		return PurposesView{}, err
	}
	var view PurposesView
	return view, json.Unmarshal(body, &view)
}
