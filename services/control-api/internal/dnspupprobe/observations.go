package dnspupprobe

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ObservationRetention keeps edge / diagnose results as long as the node
// availability log (8 days).
const ObservationRetention = 8 * 24 * time.Hour

// CheckpointView is one checkpoint's answer as stored in result rows
// (node_dnspup_probe_results / probe_dnspup_observations checkpoints) and
// returned by the plugin API. Carrier keeps the marketprobe code smart
// scheduling reads; Line is the finer PlaceOf carrier (edu / bgp / other).
type CheckpointView struct {
	ID         string   `json:"id"`
	Area       string   `json:"area,omitempty"`
	Carrier    string   `json:"carrier,omitempty"`
	Line       string   `json:"line,omitempty"`
	Region     string   `json:"region,omitempty"`
	Province   string   `json:"province,omitempty"`
	Location   string   `json:"location,omitempty"`
	OK         bool     `json:"ok"`
	Failure    string   `json:"failure,omitempty"`
	Latency    int      `json:"latency_ms,omitempty"`
	LossRate   int      `json:"loss_rate,omitempty"`
	HTTPStatus int      `json:"http_status,omitempty"`
	Values     []string `json:"values,omitempty"`
}

// ViewsOf judges results of a kind probe (checkpoints that did not answer are
// left out).
func ViewsOf(kind string, results []Result, expect []string) (views []CheckpointView, failed int) {
	for _, result := range results {
		voted, ok, failure := Judge(kind, result, expect)
		if !voted {
			continue
		}
		place := PlaceOf(result.Region, result.Location, result.ISP)
		vote := tag(result)
		view := CheckpointView{ID: result.NodeID, Area: place.Area, Carrier: vote.Carrier, Line: place.Carrier,
			Region: vote.Region, Location: result.Location, OK: ok, Failure: failure, Latency: Latency(result),
			LossRate: result.LossRate, HTTPStatus: result.HTTPStatus, Values: result.Values}
		if place.Area == AreaMainland {
			view.Province = place.Province
		}
		if !ok {
			failed++
		}
		views = append(views, view)
	}
	return views, failed
}

// observe records one edge job's checkpoints for the matrix view (a
// recording failure only logs: the verdict path does not depend on it).
func (service *Service) observe(ctx context.Context, consumer string, request ProbeRequest, results []Result) {
	kind := request.Type
	if kind == "http" && strings.HasPrefix(request.Target, "https://") {
		kind = "https"
	}
	views, failed := ViewsOf(kind, results, nil)
	if views == nil {
		views = []CheckpointView{}
	}
	raw, err := json.Marshal(views)
	if err != nil {
		return
	}
	subject := request.Target
	if len(subject) > 300 {
		subject = subject[:300]
	}
	ctx = context.WithoutCancel(ctx)
	now := service.now()
	if _, err := service.config.Pool.Exec(ctx, `INSERT INTO probe_dnspup_observations(consumer,subject,probe_type,observed_at,
		total_checks,failed_checks,checkpoints) VALUES($1,$2,$3,$4,$5,$6,$7)`, consumer, subject, kind, now, len(views),
		failed, raw); err != nil {
		service.config.Logger.Warn("dnspup observation not recorded", "consumer", consumer, "error", err)
		return
	}
	if _, err := service.config.Pool.Exec(ctx, `DELETE FROM probe_dnspup_observations WHERE observed_at<$1`,
		now.Add(-ObservationRetention)); err != nil {
		service.config.Logger.Warn("dnspup observation retention failed", "error", err)
	}
}

// Matrix subjects.
const (
	SubjectNode = "node"
	SubjectEdge = "edge"
)

// MatrixCell is one area × carrier cell. Area is the mainland province, a
// region code (hk, us, …) elsewhere, "" when unknown.
type MatrixCell struct {
	Area         string  `json:"area"`
	Carrier      string  `json:"carrier"`
	Total        int     `json:"total"`
	OK           int     `json:"ok"`
	Availability float64 `json:"availability"`
	AvgLatencyMS int     `json:"avg_latency_ms"`
	TopFailure   string  `json:"top_failure,omitempty"`
}

// MatrixPoint is one time bucket of the history curve.
type MatrixPoint struct {
	At           time.Time `json:"at"`
	Total        int       `json:"total"`
	Availability float64   `json:"availability"`
	AvgLatencyMS int       `json:"avg_latency_ms"`
}

// Matrix is GET /v1/admin/probe-dnspup/matrix.
type Matrix struct {
	Subject string        `json:"subject"`
	ID      string        `json:"id"`
	Window  string        `json:"window"`
	Cells   []MatrixCell  `json:"cells"`
	Series  []MatrixPoint `json:"series"`
}

// MatrixWindows are the allowed windows and their bucket sizes.
var MatrixWindows = map[string][2]time.Duration{
	"1h": {time.Hour, 5 * time.Minute}, "6h": {6 * time.Hour, 30 * time.Minute},
	"24h": {24 * time.Hour, time.Hour}, "7d": {7 * 24 * time.Hour, 6 * time.Hour},
}

// ErrMatrixSubject: unknown subject, id or window.
var ErrMatrixSubject = errors.New("dnspup matrix: invalid subject, id or window")

const matrixCheckpoints = `CROSS JOIN LATERAL jsonb_array_elements(source.checkpoints) point
	WHERE source.observed_at>$2`

// ReadMatrix aggregates the checkpoints of subject id in window (dnspup
// manage permission): node = a node's availability rows (every probed
// address), edge = a third-party CDN candidate host's rows.
func (service *Service) ReadMatrix(ctx context.Context, actor Actor, subject, id, window string) (Matrix, error) {
	span, ok := MatrixWindows[window]
	matrix := Matrix{Subject: subject, ID: id, Window: window, Cells: []MatrixCell{}, Series: []MatrixPoint{}}
	var from, filter string
	var key any
	switch {
	case !ok:
		return matrix, ErrMatrixSubject
	case subject == SubjectNode:
		node, err := uuid.Parse(id)
		if err != nil {
			return matrix, ErrMatrixSubject
		}
		from, filter, key = "node_dnspup_probe_results source", "source.node_id=$1", node
	case subject == SubjectEdge && id != "" && len(id) <= 300:
		from, filter, key = "probe_dnspup_observations source", "source.consumer='edge' AND source.subject=$1", id
	default:
		return matrix, ErrMatrixSubject
	}
	now := service.now()
	statement := `SELECT to_timestamp(floor(extract(epoch FROM source.observed_at)/$3)*$3) AS bucket,
		CASE WHEN point->>'region'='cn' THEN COALESCE(point->>'province','') ELSE COALESCE(point->>'region','') END AS area,
		COALESCE(NULLIF(point->>'line',''),NULLIF(point->>'carrier',''),'other') AS carrier,
		COALESCE((point->>'ok')::boolean,false) AS ok, COALESCE(point->>'failure','') AS failure,
		COALESCE((point->>'latency_ms')::int,0) AS latency
		FROM ` + from + ` ` + matrixCheckpoints + ` AND ` + filter + ` LIMIT 200000`
	type cellKey struct{ area, carrier string }
	type accumulator struct {
		total, ok, latencySum, latencyCount int
		failures                            map[string]int
	}
	cells := map[cellKey]*accumulator{}
	buckets := map[time.Time]*accumulator{}
	err := pgx.BeginTxFunc(ctx, service.config.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, statement, key, now.Add(-span[0]), int64(span[1]/time.Second))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var bucket time.Time
			var area, carrier, failure string
			var passed bool
			var latency int
			if err := rows.Scan(&bucket, &area, &carrier, &passed, &failure, &latency); err != nil {
				return err
			}
			for _, item := range []*accumulator{lookup(cells, cellKey{area, carrier}), lookup(buckets, bucket.UTC())} {
				item.total++
				if passed {
					item.ok++
					if latency > 0 {
						item.latencySum += latency
						item.latencyCount++
					}
				} else if failure != "" && failure != FailureOK {
					if item.failures == nil {
						item.failures = map[string]int{}
					}
					item.failures[failure]++
				}
			}
		}
		return rows.Err()
	})
	if err != nil {
		return matrix, err
	}
	summary := func(item *accumulator) (float64, int, string) {
		availability := float64(item.ok) / float64(max(item.total, 1))
		average := item.latencySum / max(item.latencyCount, 1)
		top, count := "", 0
		for failure, seen := range item.failures {
			if seen > count || seen == count && failure < top {
				top, count = failure, seen
			}
		}
		return availability, average, top
	}
	for key, item := range cells {
		availability, average, top := summary(item)
		matrix.Cells = append(matrix.Cells, MatrixCell{Area: key.area, Carrier: key.carrier, Total: item.total, OK: item.ok,
			Availability: availability, AvgLatencyMS: average, TopFailure: top})
	}
	sort.Slice(matrix.Cells, func(i, j int) bool {
		left, right := matrix.Cells[i], matrix.Cells[j]
		return left.Area < right.Area || left.Area == right.Area && left.Carrier < right.Carrier
	})
	for at, item := range buckets {
		availability, average, _ := summary(item)
		matrix.Series = append(matrix.Series, MatrixPoint{At: at, Total: item.total, Availability: availability, AvgLatencyMS: average})
	}
	sort.Slice(matrix.Series, func(i, j int) bool { return matrix.Series[i].At.Before(matrix.Series[j].At) })
	return matrix, nil
}

func lookup[K comparable, V any](values map[K]*V, key K) *V {
	value := values[key]
	if value == nil {
		value = new(V)
		values[key] = value
	}
	return value
}

// EdgeSubjects are the candidate hosts with observations in the last day
// (the matrix page's picker).
func (service *Service) EdgeSubjects(ctx context.Context, actor Actor) ([]string, error) {
	subjects := []string{}
	now := service.now()
	err := pgx.BeginTxFunc(ctx, service.config.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT subject FROM probe_dnspup_observations WHERE consumer='edge'
			AND observed_at>$1 ORDER BY subject LIMIT 500`, now.Add(-24*time.Hour))
		if err != nil {
			return err
		}
		subjects, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	return subjects, err
}
