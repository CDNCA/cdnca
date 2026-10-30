package nodeprobe

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	// LogEvery: an all-good round of an endpoint is logged at most this often;
	// a round with any failed vote is always logged.
	LogEvery = 5 * time.Minute
	// LogRetention matches the dnspup availability log.
	LogRetention = 8 * 24 * time.Hour
)

// LogCheckpoint is one vote in node_peer_probe_results.checkpoints.
type LogCheckpoint struct {
	// ID is "controller" or the peer node ID.
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"`
	Address   string   `json:"address,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	OK        bool     `json:"ok"`
	LatencyMS int      `json:"latency_ms,omitempty"`
}

type logEntry struct {
	point   endpoint
	verdict Verdict
	votes   []Vote
}

// writeLog stores the decided endpoints of one round and prunes old rows.
// The throttle reads the newest stored row, so it survives restarts and
// several control-api instances.
func (runner *Runner) writeLog(ctx context.Context, entries []logEntry) error {
	now := runner.now().UTC().Truncate(time.Second)
	batch := &pgx.Batch{}
	for _, entry := range entries {
		checkpoints := make([]LogCheckpoint, 0, len(entry.votes))
		for _, vote := range entry.votes {
			item := LogCheckpoint{ID: vote.Prober, Name: vote.Name, Address: vote.Address, Groups: vote.Groups,
				OK: vote.OK, LatencyMS: vote.LatencyMS}
			if vote.Prober == ControllerProberID {
				item.Groups = nil
			}
			checkpoints = append(checkpoints, item)
		}
		encoded, err := json.Marshal(checkpoints)
		if err != nil {
			return err
		}
		var controller *bool
		if entry.verdict.Controller != nil {
			value := *entry.verdict.Controller
			controller = &value
		}
		failed := entry.verdict.Failed()
		// INSERT ... SELECT WHERE: skipped when all votes passed and a row of
		// this address is younger than LogEvery.
		batch.Queue(`INSERT INTO node_peer_probe_results(node_id,address,port,observed_at,controller_ok,
				failed_checks,total_checks,failed,checkpoints)
			SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9
			WHERE $6>0 OR NOT EXISTS (SELECT 1 FROM node_peer_probe_results previous
				WHERE previous.node_id=$1 AND previous.address=$2 AND previous.port=$3 AND previous.observed_at>$10)
			ON CONFLICT DO NOTHING`, entry.point.nodeID, entry.point.address.String(), int(entry.point.port), now, controller,
			failed, entry.verdict.Total(), !entry.verdict.Healthy, encoded, now.Add(-LogEvery))
	}
	batch.Queue(`DELETE FROM node_peer_probe_results WHERE observed_at<$1`, now.Add(-LogRetention))
	return runner.pool.SendBatch(ctx, batch).Close()
}
