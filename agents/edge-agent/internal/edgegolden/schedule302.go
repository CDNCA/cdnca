package edgegolden

import (
	"encoding/json"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/sched302runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
)

// InstallSchedule302Table writes a scenario's HTTP 302 scheduling table
// (Node.Schedule302Table, revision 1, generated now) under root, where the
// node's sched302runtime puts it (root/schedule302/table.json).
func InstallSchedule302Table(root string, raw json.RawMessage) error {
	var table sched302.Table
	if err := json.Unmarshal(raw, &table); err != nil {
		return err
	}
	table.Revision, table.GeneratedAt = 1, time.Now().Unix()
	runtime, err := sched302runtime.New(root, table.NodeID)
	if err != nil {
		return err
	}
	encoded, err := sched302.Encode(table)
	if err != nil {
		return err
	}
	return runtime.Apply(table, encoded)
}
