//go:build integration

package nodemetrics

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestMonitoringHistoryPagesActualProbeReports(t *testing.T) {
	pool := monitoringSnapshotPool(t)
	admin, err := identity.NewStore(pool).BootstrapPlatformUser(t.Context(), "monitoringhistory", "Monitoring history", "synthetic-not-login-hash", "monitoring-history-test")
	if err != nil {
		t.Fatal(err)
	}
	nodeID, otherNode, foreignNode, foreignScope := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		VALUES($1,$3,'history-node','active',$4,1),($2,$3,'other-node','active',$4,2)`, nodeID, otherNode, admin.ScopeID, admin.UserID); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`INSERT INTO tenants(id,display_name) VALUES($1,'foreign')`,
		`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`} {
		if _, err := pool.Exec(t.Context(), statement, foreignScope); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,created_by_user_id,display_id) VALUES($1,$2,'foreign',$3,3)`,
		foreignNode, foreignScope, admin.UserID); err != nil {
		t.Fatal(err)
	}
	store, _ := NewPostgresStore(pool)
	base := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Microsecond)
	sequence := uint64(0)
	put := func(sample Sample) {
		t.Helper()
		if _, err := store.Put(t.Context(), sample); err != nil {
			t.Fatal(err)
		}
	}
	// Twelve probes for the node, one failing; plus a host-only record, an
	// out-of-window probe and another node's probe that must not be counted.
	for index := range 12 {
		sequence++
		sample := monitoringStoredProbe(nodeID, sequence, base.Add(time.Duration(index)*time.Minute))
		sample.Healthy, sample.ProbeSucceeded, sample.ConsecutiveSuccesses = true, true, 1
		if index == 11 {
			sample.Healthy, sample.ProbeSucceeded, sample.ConsecutiveSuccesses, sample.ConsecutiveFailures = false, false, 0, 1
			sample.ProbeFailuresTotal = 1
		}
		put(sample)
	}
	sequence++
	host := monitoringStoredProbe(nodeID, sequence, base.Add(5*time.Minute+time.Second))
	host.Kind, host.ConfigRevision, host.ActiveConfigRevision, host.ProbePort = RecordHostMetric, 0, 0, 0
	host.Known, host.MemoryUsedBytes, host.MemoryTotalBytes, host.ProbesTotal = true, 1, 2, 0
	put(host)
	sequence++
	put(monitoringStoredProbe(nodeID, sequence, base.Add(-2*time.Hour)))
	sequence++
	put(monitoringStoredProbe(otherNode, sequence, base))

	reader, _ := NewPostgresReader(pool)
	from, to := base.Add(-time.Minute), base.Add(time.Hour)
	first, err := reader.MonitoringHistory(t.Context(), admin.ScopeID, nodeID, from, to, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != 12 || len(first.Items) != 10 || first.Page != 1 || first.Limit != 10 || first.SchemaVersion != 1 {
		t.Fatalf("first page total=%d items=%d", first.Total, len(first.Items))
	}
	newest := first.Items[0]
	if !newest.ObservedAt.Equal(base.Add(11*time.Minute)) || newest.ProbeSucceeded || newest.FailedChecks != 1 || newest.TotalChecks != 1 ||
		newest.ProbePort != 80 || newest.ConfigRevision != 1 {
		t.Fatalf("newest probe row = %+v", newest)
	}
	for index, item := range first.Items[1:] {
		if item.FailedChecks != 0 || item.TotalChecks != 1 || !item.ProbeSucceeded || !item.ObservedAt.Before(first.Items[index].ObservedAt) {
			t.Fatalf("row %d is not a newer-first successful probe: %+v", index+1, item)
		}
	}
	second, err := reader.MonitoringHistory(t.Context(), admin.ScopeID, nodeID, from, to, 2, 10)
	if err != nil || second.Total != 12 || len(second.Items) != 2 || !second.Items[1].ObservedAt.Equal(base) {
		t.Fatalf("second page = %+v err=%v", second, err)
	}
	if empty, err := reader.MonitoringHistory(t.Context(), admin.ScopeID, nodeID, from, to, 3, 10); err != nil || empty.Total != 12 || len(empty.Items) != 0 {
		t.Fatalf("past-end page = %+v err=%v", empty, err)
	}
	for name, target := range map[string]uuid.UUID{"foreign": foreignNode, "missing": uuid.New()} {
		if _, err := reader.MonitoringHistory(t.Context(), admin.ScopeID, target, from, to, 1, 10); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s node history err=%v, want not found", name, err)
		}
	}
	for name, call := range map[string]func() error{
		"reversed": func() error {
			_, err := reader.MonitoringHistory(t.Context(), admin.ScopeID, nodeID, to, from, 1, 10)
			return err
		},
		"too wide": func() error {
			_, err := reader.MonitoringHistory(t.Context(), admin.ScopeID, nodeID, to.Add(-MaxMonitoringHistoryWindow-time.Second), to, 1, 10)
			return err
		},
		"page zero": func() error {
			_, err := reader.MonitoringHistory(t.Context(), admin.ScopeID, nodeID, from, to, 0, 10)
			return err
		},
		"over limit": func() error {
			_, err := reader.MonitoringHistory(t.Context(), admin.ScopeID, nodeID, from, to, 1, 101)
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("%s window err=%v, want invalid", name, err)
		}
	}
}
