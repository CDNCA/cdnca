package nodescheduler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type backupStateRows struct {
	items []LineBackupState
	index int
}

func (rows *backupStateRows) Next() bool                                   { rows.index++; return rows.index <= len(rows.items) }
func (rows *backupStateRows) Close()                                       {}
func (rows *backupStateRows) Err() error                                   { return nil }
func (rows *backupStateRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (rows *backupStateRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *backupStateRows) Values() ([]any, error)                       { return nil, nil }
func (rows *backupStateRows) RawValues() [][]byte                          { return nil }
func (rows *backupStateRows) Conn() *pgx.Conn                              { return nil }
func (rows *backupStateRows) Scan(dest ...any) error {
	item := rows.items[rows.index-1]
	*dest[0].(*int) = item.AddressFamily
	*dest[1].(*string) = item.State
	*dest[2].(*[]string) = item.BackupAddresses
	*dest[3].(*time.Time) = item.ChangedAt
	return nil
}

type backupStateQuerier struct {
	rows []LineBackupState
	sql  string
	args []any
}

func (querier *backupStateQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return nil }
func (querier *backupStateQuerier) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	querier.sql, querier.args = sql, args
	return &backupStateRows{items: querier.rows}, nil
}

// fix-backupnotify：线路组读取带出迁移 571 记录的备用 IP 状态（每地址族一行，未迁移过的地址族不返回）。
func TestAttachBackupStatesReadsMigration560Table(t *testing.T) {
	scopeID, groupID := uuid.New(), uuid.New()
	changed := time.Date(2026, 10, 27, 14, 0, 0, 0, time.UTC)
	querier := &backupStateQuerier{rows: []LineBackupState{
		{AddressFamily: 4, State: "backup_active", BackupAddresses: []string{"192.0.2.20"}, ChangedAt: changed},
		{AddressFamily: 6, State: "normal", BackupAddresses: []string{}, ChangedAt: changed},
	}}
	group := LineGroupRevision{TenantScopeID: scopeID, GroupID: groupID}
	if err := attachBackupStates(context.Background(), querier, &group); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(querier.sql, "FROM node_line_group_backup_states") || len(querier.args) != 2 ||
		querier.args[0] != scopeID || querier.args[1] != groupID {
		t.Fatalf("sql=%s args=%v", querier.sql, querier.args)
	}
	if len(group.BackupStates) != 2 || group.BackupStates[0].State != "backup_active" ||
		group.BackupStates[0].BackupAddresses[0] != "192.0.2.20" || group.BackupStates[1].AddressFamily != 6 {
		t.Fatalf("backup states = %+v", group.BackupStates)
	}
	empty := LineGroupRevision{TenantScopeID: scopeID, GroupID: groupID}
	if err := attachBackupStates(context.Background(), &backupStateQuerier{}, &empty); err != nil ||
		empty.BackupStates == nil || len(empty.BackupStates) != 0 {
		t.Fatalf("no rows must load an empty list: %+v %v", empty.BackupStates, err)
	}
}
