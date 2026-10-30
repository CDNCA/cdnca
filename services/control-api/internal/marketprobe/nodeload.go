package marketprobe

import (
	"context"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/nodeload"
	"github.com/google/uuid"
)

// ReportLoad sends the load of every node last reported in a pool for the
// minute that closed at minuteEnd (ADR 0012 §6.1): the mean CPU and memory
// ((total − available) / total, as the agent samples it) of the node's
// samples in (minuteEnd − 60s, minuteEnd]. Nodes without a sample in that
// minute are left out; the market turns them unknown after five minutes and
// does not remove them. It returns the number of items sent.
func (s *Service) ReportLoad(ctx context.Context, minuteEnd time.Time) (int, error) {
	if s.cfg.Identity == nil {
		return 0, nil
	}
	self := s.cfg.Identity()
	if self.MemberID == uuid.Nil {
		return 0, nil
	}
	s.mu.Lock()
	pools := s.pools
	s.mu.Unlock()
	end := minuteEnd.UTC().Truncate(time.Minute)
	var items []nodeload.Item
	for _, ref := range sortedKeys(pools) {
		ids := make([]uuid.UUID, 0, len(pools[ref]))
		for _, id := range pools[ref] {
			if parsed, err := uuid.Parse(id); err == nil {
				ids = append(ids, parsed)
			}
		}
		if len(ids) == 0 {
			continue
		}
		rows, err := s.pool.Query(ctx, `SELECT node_id, avg(cpu_percent),
				avg(memory_used_bytes::float8 * 100 / memory_total_bytes), count(*)
			FROM node_metric_samples
			WHERE node_id = ANY($1) AND observed_at > $2 AND observed_at <= $3
			  AND record_kind IN ('metric','host_metric') AND metrics_known
			GROUP BY node_id ORDER BY node_id`, ids, end.Add(-time.Minute), end)
		if err != nil {
			return 0, err
		}
		for rows.Next() {
			it := nodeload.Item{NodePoolRef: ref, ObservedAt: end.Unix()}
			if err := rows.Scan(&it.NodeID, &it.CPUPercent, &it.MemoryPercent, &it.SampleCount); err != nil {
				rows.Close()
				return 0, err
			}
			it.CPUPercent = clampPercent(it.CPUPercent)
			it.MemoryPercent = clampPercent(it.MemoryPercent)
			it.SampleCount = min(it.SampleCount, nodeload.MaxSamples)
			items = append(items, it)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, err
		}
	}
	if len(items) == 0 {
		return 0, nil
	}
	sent := 0
	for i := 0; i < len(items); i += nodeload.MaxItems {
		chunk := items[i:min(i+nodeload.MaxItems, len(items))]
		// Deterministic per member, minute and chunk: a retried report is
		// dropped by the market as a replay.
		id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("cdnca-market-nodeload/"+self.MemberID.String()+"/"+
			strconv.FormatInt(end.Unix(), 10)+"/"+strconv.Itoa(i)))
		result, err := s.market.ReportNodeLoad(ctx, self, nodeload.Report{Schema: nodeload.SchemaV1, ReportID: id,
			LeafMemberID: self.MemberID, CreatedAt: s.cfg.Now().Unix(), Items: chunk})
		if err != nil {
			return sent, err
		}
		if result.Rejected > 0 {
			s.skip("node_load", "items_rejected", "rejected", result.Rejected)
		}
		sent += len(chunk)
	}
	return sent, nil
}

// clampPercent keeps averages of in-range samples in range despite rounding.
func clampPercent(v float64) float64 { return max(0, min(100, v)) }
