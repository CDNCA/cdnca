package smartsched

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnamelines"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// SampleRetention keeps latency minutes past the largest window (60).
	SampleRetention = 2 * time.Hour
	// SelectionFreshFor: an older selection is ignored by the DNS writer
	// (the selector stopped): the line falls back to today's static set.
	SelectionFreshFor = 10 * time.Minute
	// LoadFreshFor: an older metric is unknown load.
	LoadFreshFor = 5 * time.Minute
	maxPerBucket = 256
	maxLatencyMS = 60000
	sourceDNSPup = "dnspup"
	sourcePeer   = "peer"
)

// Worker ingests probe latency and refreshes each enabled line group's
// selections.
type Worker struct {
	pool   *pgxpool.Pool
	now    func() time.Time
	logger *slog.Logger
}

func NewWorker(pool *pgxpool.Pool, now func() time.Time, logger *slog.Logger) (*Worker, error) {
	if pool == nil {
		return nil, errors.New("smart schedule worker requires a pool")
	}
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{pool: pool, now: now, logger: logger}, nil
}

// Run ticks until ctx ends.
func (worker *Worker) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := worker.Tick(ctx); err != nil && ctx.Err() == nil {
			worker.logger.Warn("smart schedule tick failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Tick ingests new probe rows, prunes old samples and reselects.
func (worker *Worker) Tick(ctx context.Context) error {
	now := worker.now().UTC().Truncate(time.Second)
	if err := worker.Ingest(ctx, now); err != nil {
		return err
	}
	if _, err := worker.pool.Exec(ctx, `DELETE FROM node_line_latency_samples WHERE bucket<$1`,
		now.Add(-SampleRetention)); err != nil {
		return err
	}
	return worker.Reselect(ctx, now)
}

// endpointRef is one current-revision endpoint a probed node address is.
type endpointRef struct {
	scopeID, groupID, endpointID uuid.UUID
	address                      string
}

type sampleKey struct {
	scopeID, groupID, endpointID uuid.UUID
	address, province, carrier   string
	source                       string
	bucket                       time.Time
}

type sampleValue struct {
	latencies []int
	last      time.Time
}

// Ingest maps the dnspup and peer availability log rows observed since the
// cursors onto the line groups' current endpoints and adds their OK
// latencies to the minute buckets.
func (worker *Worker) Ingest(ctx context.Context, now time.Time) error {
	refs, provinces, err := worker.endpointRefs(ctx)
	if err != nil {
		return err
	}
	samples := map[sampleKey]*sampleValue{}
	add := func(nodeID uuid.UUID, address string, observed time.Time, province, carrier, source string, latency int) {
		if latency < 1 || latency > maxLatencyMS || !slices.Contains(Carriers, carrier) {
			return
		}
		for _, ref := range refs[nodeID.String()+"|"+address] {
			key := sampleKey{ref.scopeID, ref.groupID, ref.endpointID, ref.address, province, carrier, source,
				observed.Truncate(time.Minute)}
			value := samples[key]
			if value == nil {
				value = &sampleValue{}
				samples[key] = value
			}
			if len(value.latencies) < maxPerBucket {
				value.latencies = append(value.latencies, latency)
			}
			if observed.After(value.last) {
				value.last = observed
			}
		}
	}
	cursors := map[string]time.Time{}
	for _, source := range []struct {
		name, table string
		read        func(nodeID uuid.UUID, address string, observed time.Time, raw []byte)
	}{
		{sourceDNSPup, "node_dnspup_probe_results", func(nodeID uuid.UUID, address string, observed time.Time, raw []byte) {
			var checkpoints []struct {
				Carrier  string `json:"carrier"`
				Province string `json:"province"`
				OK       bool   `json:"ok"`
				Latency  int    `json:"latency_ms"`
			}
			if json.Unmarshal(raw, &checkpoints) != nil {
				return
			}
			for _, checkpoint := range checkpoints {
				if checkpoint.OK {
					province, _ := marketprobe.Province(checkpoint.Province)
					add(nodeID, address, observed, province, checkpoint.Carrier, sourceDNSPup, checkpoint.Latency)
				}
			}
		}},
		{sourcePeer, "node_peer_probe_results", func(nodeID uuid.UUID, address string, observed time.Time, raw []byte) {
			var checkpoints []struct {
				ID      string   `json:"id"`
				Groups  []string `json:"groups"`
				OK      bool     `json:"ok"`
				Latency int      `json:"latency_ms"`
			}
			if json.Unmarshal(raw, &checkpoints) != nil {
				return
			}
			for _, checkpoint := range checkpoints {
				if !checkpoint.OK {
					continue
				}
				// The controller votes without a carrier; peers vote for the
				// carrier and province of their own endpoint.
				for _, group := range checkpoint.Groups {
					if slices.Contains(Carriers, group) {
						add(nodeID, address, observed, provinces[checkpoint.ID], group, sourcePeer, checkpoint.Latency)
						break
					}
				}
			}
		}},
	} {
		var cursor time.Time
		err := worker.pool.QueryRow(ctx, `SELECT observed_until FROM smart_schedule_ingest_cursors WHERE source=$1`,
			source.name).Scan(&cursor)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if floor := now.Add(-time.Hour); cursor.Before(floor) {
			cursor = floor
		}
		rows, err := worker.pool.Query(ctx, `SELECT node_id,host(address),observed_at,checkpoints FROM `+source.table+`
			WHERE observed_at>$1 AND observed_at<=$2 ORDER BY observed_at`, cursor, now)
		if err != nil {
			return err
		}
		latest := cursor
		for rows.Next() {
			var nodeID uuid.UUID
			var address string
			var observed time.Time
			var raw []byte
			if err := rows.Scan(&nodeID, &address, &observed, &raw); err != nil {
				rows.Close()
				return err
			}
			source.read(nodeID, address, observed.UTC(), raw)
			if observed.After(latest) {
				latest = observed
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		cursors[source.name] = latest
	}
	return pgx.BeginFunc(ctx, worker.pool, func(tx pgx.Tx) error {
		batch := &pgx.Batch{}
		for key, value := range samples {
			batch.Queue(`INSERT INTO node_line_latency_samples(tenant_scope_id,line_group_id,endpoint_id,address,province,
					carrier,source,bucket,latencies_ms,last_at)
				SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
				WHERE EXISTS (SELECT 1 FROM node_line_groups WHERE tenant_scope_id=$1 AND id=$2)
				ON CONFLICT (tenant_scope_id,line_group_id,endpoint_id,province,carrier,source,bucket) DO UPDATE SET
					latencies_ms=(node_line_latency_samples.latencies_ms || EXCLUDED.latencies_ms)[1:256],
					last_at=greatest(node_line_latency_samples.last_at,EXCLUDED.last_at)`,
				key.scopeID, key.groupID, key.endpointID, key.address, key.province, key.carrier, key.source, key.bucket,
				value.latencies, value.last)
		}
		for source, until := range cursors {
			batch.Queue(`INSERT INTO smart_schedule_ingest_cursors(source,observed_until,updated_at) VALUES($1,$2,$3)
				ON CONFLICT (source) DO UPDATE SET observed_until=EXCLUDED.observed_until,updated_at=EXCLUDED.updated_at`,
				source, until, now)
		}
		return tx.SendBatch(ctx, batch).Close()
	})
}

// endpointRefs maps node|address to the current-revision endpoints with that
// node and address, and node ID to the province of its endpoints (peers).
func (worker *Worker) endpointRefs(ctx context.Context) (map[string][]endpointRef, map[string]string, error) {
	rows, err := worker.pool.Query(ctx, `SELECT endpoint.tenant_scope_id,endpoint.line_group_id,endpoint.id,
			endpoint.node_id,host(endpoint.address),endpoint.region
		FROM node_line_endpoints endpoint
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=endpoint.tenant_scope_id
		 AND line_group.id=endpoint.line_group_id AND line_group.current_revision=endpoint.config_revision
		 AND line_group.deleted_at IS NULL
		WHERE endpoint.node_id IS NOT NULL
		ORDER BY endpoint.node_id,endpoint.address`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	refs := map[string][]endpointRef{}
	provinces := map[string]string{}
	for rows.Next() {
		var ref endpointRef
		var nodeID uuid.UUID
		var region string
		if err := rows.Scan(&ref.scopeID, &ref.groupID, &ref.endpointID, &nodeID, &ref.address, &region); err != nil {
			return nil, nil, err
		}
		key := nodeID.String() + "|" + ref.address
		refs[key] = append(refs[key], ref)
		if province, ok := marketprobe.Province(region); ok {
			if _, seen := provinces[nodeID.String()]; !seen {
				provinces[nodeID.String()] = province
			}
		}
	}
	return refs, provinces, rows.Err()
}

type group struct {
	scopeID, groupID uuid.UUID
	revision         int64
	settings         Settings
}

// Reselect recomputes the lines of every enabled line group and drops the
// selections of disabled ones.
func (worker *Worker) Reselect(ctx context.Context, now time.Time) error {
	if _, err := worker.pool.Exec(ctx, `DELETE FROM node_line_smart_selections selection
		USING node_line_group_smart_schedules schedule
		WHERE schedule.tenant_scope_id=selection.tenant_scope_id AND schedule.line_group_id=selection.line_group_id
		  AND NOT schedule.enabled`); err != nil {
		return err
	}
	rows, err := worker.pool.Query(ctx, `SELECT schedule.tenant_scope_id,schedule.line_group_id,line_group.current_revision,
			schedule.top_n,schedule.granularity,schedule.latency_window_minutes,schedule.max_load_percent,schedule.fallback
		FROM node_line_group_smart_schedules schedule
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=schedule.tenant_scope_id
		 AND line_group.id=schedule.line_group_id AND line_group.deleted_at IS NULL
		WHERE schedule.enabled ORDER BY schedule.tenant_scope_id,schedule.line_group_id`)
	if err != nil {
		return err
	}
	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (group, error) {
		value := group{settings: Settings{Enabled: true}}
		var topN, window, maxLoad int16
		err := row.Scan(&value.scopeID, &value.groupID, &value.revision, &topN, &value.settings.Granularity, &window,
			&maxLoad, &value.settings.Fallback)
		value.settings.TopN, value.settings.LatencyWindowMinutes, value.settings.MaxLoadPercent =
			int(topN), int(window), int(maxLoad)
		return value, err
	})
	if err != nil {
		return err
	}
	var first error
	for _, item := range groups {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := worker.reselectGroup(ctx, item, now); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (worker *Worker) reselectGroup(ctx context.Context, item group, now time.Time) error {
	candidates, err := Candidates(ctx, worker.pool, item.scopeID, item.groupID, item.revision, now)
	if err != nil {
		return err
	}
	latency, err := windowLatency(ctx, worker.pool, item.scopeID, item.groupID, now, item.settings.LatencyWindowMinutes)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, worker.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT line_scope,source,selected,selection_digest,group_revision
			FROM node_line_smart_selections WHERE tenant_scope_id=$1 AND line_group_id=$2 FOR UPDATE`,
			item.scopeID, item.groupID)
		if err != nil {
			return err
		}
		type stored struct {
			digest   string
			revision int64
		}
		existing := map[string]stored{}
		previous := map[string][]string{}
		for rows.Next() {
			var scope, source, digest string
			var raw []byte
			var revision int64
			if err := rows.Scan(&scope, &source, &raw, &digest, &revision); err != nil {
				rows.Close()
				return err
			}
			existing[scope] = stored{digest, revision}
			var picks []Pick
			if source == SourceLatency && json.Unmarshal(raw, &picks) == nil {
				previous[scope] = Selection{Selected: picks}.Addresses()
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		selections := Select(Input{Settings: item.settings, Candidates: candidates, Latency: latency, Previous: previous})
		wanted := map[string]bool{}
		for _, selection := range selections {
			wanted[selection.Scope] = true
			encoded, err := json.Marshal(selection.Selected)
			if err != nil {
				return err
			}
			digest := selection.Digest()
			before, ok := existing[selection.Scope]
			changed := !ok || before.digest != digest || before.revision != item.revision
			if changed && ok {
				worker.logger.Info("smart schedule selection changed", "line_group_id", item.groupID,
					"line", selection.Scope, "source", selection.Source, "fallback_from", selection.FallbackFrom)
			}
			// changed_at moves only with the address set; refreshed_at every tick.
			if _, err := tx.Exec(ctx, `INSERT INTO node_line_smart_selections(tenant_scope_id,line_group_id,line_scope,
					group_revision,source,fallback_from,selected,selection_digest,changed_at,refreshed_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)
				ON CONFLICT (tenant_scope_id,line_group_id,line_scope) DO UPDATE SET group_revision=EXCLUDED.group_revision,
					source=EXCLUDED.source,fallback_from=EXCLUDED.fallback_from,selected=EXCLUDED.selected,
					changed_at=CASE WHEN node_line_smart_selections.selection_digest=EXCLUDED.selection_digest AND
						node_line_smart_selections.group_revision=EXCLUDED.group_revision
						THEN node_line_smart_selections.changed_at ELSE EXCLUDED.changed_at END,
					selection_digest=EXCLUDED.selection_digest,refreshed_at=EXCLUDED.refreshed_at`,
				item.scopeID, item.groupID, selection.Scope, item.revision, selection.Source, selection.FallbackFrom,
				encoded, digest, now); err != nil {
				return err
			}
		}
		var stale []string
		for scope := range existing {
			if !wanted[scope] {
				stale = append(stale, scope)
			}
		}
		if len(stale) > 0 {
			_, err := tx.Exec(ctx, `DELETE FROM node_line_smart_selections WHERE tenant_scope_id=$1 AND line_group_id=$2
				AND line_scope = ANY($3::text[])`, item.scopeID, item.groupID, stale)
			return err
		}
		return nil
	})
}

type querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// Candidates are the published endpoints of a line group revision: healthy
// unless the line group health or a fresh dnspup verdict says otherwise;
// load is the larger of CPU and memory of a recent metric.
func Candidates(ctx context.Context, database querier, scopeID, groupID uuid.UUID, revision int64,
	now time.Time) ([]Candidate, error) {
	rows, err := database.Query(ctx, `SELECT published.endpoint_id,host(published.address),endpoint.region,endpoint.carrier,
			COALESCE(health.status,'unknown')<>'unhealthy' AND NOT COALESCE(dnspup.failing AND dnspup.fresh_until>$4,false),
			CASE WHEN metric.observed_at>$5 THEN greatest(metric.cpu_percent,
				metric.memory_used_bytes::float8*100/NULLIF(metric.memory_total_bytes,0)) END
		FROM node_line_endpoint_published published
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=published.tenant_scope_id
		 AND endpoint.line_group_id=published.line_group_id AND endpoint.config_revision=published.config_revision
		 AND endpoint.id=published.endpoint_id
		LEFT JOIN node_line_endpoint_health health ON health.tenant_scope_id=published.tenant_scope_id
		 AND health.line_group_id=published.line_group_id AND health.config_revision=published.config_revision
		 AND health.endpoint_id=published.endpoint_id
		LEFT JOIN node_dnspup_probe_states dnspup ON dnspup.node_id=published.node_id
		LEFT JOIN node_metric_latest metric ON metric.node_id=published.node_id AND metric.metrics_known
		WHERE published.tenant_scope_id=$1 AND published.line_group_id=$2 AND published.config_revision=$3
		  AND published.published
		ORDER BY published.address`, scopeID, groupID, revision, now, now.Add(-LoadFreshFor))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Candidate, error) {
		var value Candidate
		var region, carrier string
		if err := row.Scan(&value.EndpointID, &value.Address, &region, &carrier, &value.Healthy, &value.LoadPercent); err != nil {
			return value, err
		}
		if address, err := netip.ParseAddr(value.Address); err == nil {
			value.Address = address.String()
		}
		value.Scope = cnamelines.EndpointScope(region, carrier)
		if value.LoadPercent != nil {
			load := max(0, min(100, *value.LoadPercent))
			value.LoadPercent = &load
		}
		return value, nil
	})
}

// windowLatency is the p50 of every endpoint per province+carrier line and
// per carrier (all provinces) over the last window minutes.
func windowLatency(ctx context.Context, database querier, scopeID, groupID uuid.UUID, now time.Time,
	window int) (map[LineKey]map[uuid.UUID]Latency, error) {
	rows, err := database.Query(ctx, `SELECT province,carrier,endpoint_id,
			percentile_disc(0.5) WITHIN GROUP (ORDER BY value),count(*)
		FROM node_line_latency_samples sample, unnest(sample.latencies_ms) value
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND bucket>=$3
		GROUP BY GROUPING SETS ((province,carrier,endpoint_id),(carrier,endpoint_id))
		HAVING NOT (GROUPING(province)=0 AND province='')`, scopeID, groupID,
		now.Add(-time.Duration(window)*time.Minute).Truncate(time.Minute))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[LineKey]map[uuid.UUID]Latency{}
	for rows.Next() {
		var province *string
		var carrier string
		var endpointID uuid.UUID
		var value Latency
		if err := rows.Scan(&province, &carrier, &endpointID, &value.P50MS, &value.Samples); err != nil {
			return nil, err
		}
		key := LineKey{Carrier: carrier}
		if province != nil {
			key.Province = *province
		}
		if out[key] == nil {
			out[key] = map[uuid.UUID]Latency{}
		}
		out[key][endpointID] = value
	}
	return out, rows.Err()
}

// MatrixRow is one row of the latency matrix.
type MatrixRow struct {
	Province   string    `json:"province"`
	Carrier    string    `json:"carrier"`
	EndpointID uuid.UUID `json:"endpoint_id"`
	Address    string    `json:"address"`
	P50MS      int       `json:"p50_ms"`
	Samples    int       `json:"samples"`
	LastAt     time.Time `json:"last_at"`
}

// Matrix reads the latency matrix (province "" = checkpoints of unknown province).
func Matrix(ctx context.Context, database querier, scopeID, groupID uuid.UUID, now time.Time, window int) ([]MatrixRow, error) {
	rows, err := database.Query(ctx, `SELECT province,carrier,endpoint_id,host(min(address)),
			percentile_disc(0.5) WITHIN GROUP (ORDER BY value),count(*),max(last_at)
		FROM node_line_latency_samples sample, unnest(sample.latencies_ms) value
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND bucket>=$3
		GROUP BY province,carrier,endpoint_id`, scopeID, groupID,
		now.Add(-time.Duration(window)*time.Minute).Truncate(time.Minute))
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (MatrixRow, error) {
		var value MatrixRow
		err := row.Scan(&value.Province, &value.Carrier, &value.EndpointID, &value.Address, &value.P50MS, &value.Samples,
			&value.LastAt)
		value.LastAt = value.LastAt.UTC()
		return value, err
	})
	if err != nil {
		return nil, err
	}
	order := map[string]int{}
	for index, carrier := range Carriers {
		order[carrier] = index
	}
	sort.Slice(out, func(left, right int) bool {
		a, b := out[left], out[right]
		switch {
		case a.Province != b.Province:
			return a.Province < b.Province
		case a.Carrier != b.Carrier:
			return order[a.Carrier] < order[b.Carrier]
		case a.P50MS != b.P50MS:
			return a.P50MS < b.P50MS
		}
		return a.Address < b.Address
	})
	return out, nil
}
