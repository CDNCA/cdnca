package retentioncleanup

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// cleanup_cache_days 此前没有执行者。两类历史都由它驱动。
func TestTargetsCoverCleanupCacheDays(t *testing.T) {
	want := map[string]bool{"cache_operations": false, "security_ban_entries": false}
	for _, item := range targets {
		if _, ok := want[item.table]; !ok {
			continue
		}
		want[item.table] = true
		if item.setting != "cleanup_cache_days" || !strings.Contains(item.cutoffSQL, "retention_cleanup_cutoff_566") {
			t.Errorf("%s: setting=%q cutoff=%q", item.table, item.setting, item.cutoffSQL)
		}
	}
	for table, found := range want {
		if !found {
			t.Errorf("no retention target for %s", table)
		}
	}
}

type recordingTx struct {
	ids      []uuid.UUID
	executed []string
	affected map[string]int64
}

func (tx *recordingTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	tx.executed = append(tx.executed, sql)
	count := tx.affected[sql]
	return pgconn.NewCommandTag("DELETE " + strconv.FormatInt(count, 10)), nil
}

func (tx *recordingTx) QueryRow(context.Context, string, ...any) pgx.Row { return idsRow{tx.ids} }

type idsRow struct{ ids []uuid.UUID }

func (row idsRow) Scan(dest ...any) error {
	*(dest[0].(*[]uuid.UUID)) = row.ids
	return nil
}

func cacheTarget(t *testing.T) target {
	t.Helper()
	for _, item := range targets {
		if item.table == "cache_operations" {
			return item
		}
	}
	t.Fatal("cache_operations target missing")
	return target{}
}

// 子表先于其引用的表删除，后续操作先于父操作删除；返回值只数 cache_operations 行。
func TestDeleteExpiredCacheOperationsChildFirst(t *testing.T) {
	item := cacheTarget(t)
	tx := &recordingTx{ids: []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}, affected: map[string]int64{
		item.deleteSQL: 1, item.finalSQL: 2, cacheOperationChildren[0]: 9,
	}}
	deleted, err := deleteExpired(context.Background(), tx, item, 10)
	if err != nil || deleted != 3 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	order := []string{"cache_operation_target_results", "cache_operation_cancel_deliveries",
		"cache_operation_node_attempts", "cache_operation_node_targets", "cache_operation_nodes",
		"cache_operation_targets", "cache_operation_commands"}
	if len(tx.executed) != len(order)+2 {
		t.Fatalf("executed %d statements: %q", len(tx.executed), tx.executed)
	}
	for index, table := range order {
		if !strings.Contains(tx.executed[index], "DELETE FROM "+table+" ") {
			t.Errorf("statement %d = %q, want %s", index, tx.executed[index], table)
		}
	}
	if !strings.Contains(tx.executed[len(order)], "parent_operation_id IS NOT NULL") ||
		tx.executed[len(order)+1] != item.finalSQL {
		t.Errorf("parents not last: %q", tx.executed[len(order):])
	}
}

func TestDeleteExpiredNothingSelected(t *testing.T) {
	tx := &recordingTx{}
	deleted, err := deleteExpired(context.Background(), tx, cacheTarget(t), 10)
	if err != nil || deleted != 0 || len(tx.executed) != 0 {
		t.Fatalf("deleted=%d err=%v executed=%q", deleted, err, tx.executed)
	}
}

// 解锁 IP 历史：已解除的记录必须出了 7 天释放下发窗口才删。
func TestSecurityBanTargetKeepsReleaseWindow(t *testing.T) {
	for _, item := range targets {
		if item.table != "security_ban_entries" {
			continue
		}
		if item.selectSQL != "" || !strings.Contains(item.deleteSQL, "transaction_timestamp() - interval '7 days'") ||
			!strings.Contains(item.deleteSQL, "entry.released_at IS NULL AND entry.banned_until <") {
			t.Fatalf("security ban delete = %q", item.deleteSQL)
		}
		tx := &recordingTx{affected: map[string]int64{item.deleteSQL: 4}}
		if deleted, err := deleteExpired(context.Background(), tx, item, 10); err != nil || deleted != 4 {
			t.Fatalf("deleted=%d err=%v", deleted, err)
		}
		return
	}
	t.Fatal("security_ban_entries target missing")
}
