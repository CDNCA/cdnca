package notificationcontrol

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// authorizeFakeTx answers the queries of authorizeAny without a database:
// IAM locks succeed, the session row is an active platform session, and the
// permission query reports granted when any requested name is held.
type authorizeFakeTx struct {
	pgx.Tx
	scopeID   uuid.UUID
	held      []string
	requested []string
}

func (tx *authorizeFakeTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (tx *authorizeFakeTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "iam_scope_locks_v1"):
		return authorizeFakeRow(func(dest ...any) { *dest[0].(*[]uuid.UUID) = []uuid.UUID{tx.scopeID} })
	case strings.Contains(sql, "FROM auth_sessions session"):
		return authorizeFakeRow(func(dest ...any) {
			*dest[0].(*string) = "platform"
			*dest[2].(*string) = "active"
			*dest[3].(*string) = "active"
			*dest[5].(*time.Time) = time.Now().Add(time.Hour)
		})
	case strings.Contains(sql, "FROM role_assignments assignment"):
		tx.requested = args[2].([]string)
		granted := slices.ContainsFunc(tx.requested, func(name string) bool { return slices.Contains(tx.held, name) })
		return authorizeFakeRow(func(dest ...any) { *dest[0].(*bool) = granted })
	}
	panic("unexpected query: " + sql)
}

type authorizeFakeRow func(dest ...any)

func (row authorizeFakeRow) Scan(dest ...any) error { row(dest...); return nil }

// TestDeliveryHistoryReadPermissions: 发送记录接口与前端
// SystemSentLogPanel 一致，platform.admin 或 system_configuration.read 任一放行，
// 两者都没有拒绝；其他读取接口仍只认 system_configuration.read。
func TestDeliveryHistoryReadPermissions(t *testing.T) {
	actor := Actor{ScopeID: uuid.New(), UserID: uuid.New(), SessionID: uuid.New(), ScopeKind: "platform"}
	for _, test := range []struct {
		held []string
		want error
	}{
		{[]string{permissionPlatformAdmin}, nil},
		{[]string{permissionRead}, nil},
		{[]string{permissionPlatformAdmin, permissionRead}, nil},
		{[]string{permissionManage}, ErrPermissionDenied},
		{nil, ErrPermissionDenied},
	} {
		tx := &authorizeFakeTx{scopeID: actor.ScopeID, held: test.held}
		if err := authorizeAny(t.Context(), tx, actor, deliveryHistoryReadPermissions, time.Now(), identityLockRead); err != test.want {
			t.Fatalf("held=%v err=%v want=%v", test.held, err, test.want)
		}
		if !slices.Equal(tx.requested, []string{"system_configuration.read", "platform.admin"}) {
			t.Fatalf("requested=%v", tx.requested)
		}
	}
	tx := &authorizeFakeTx{scopeID: actor.ScopeID, held: []string{permissionPlatformAdmin}}
	if err := authorize(t.Context(), tx, actor, permissionRead, time.Now()); err != ErrPermissionDenied {
		t.Fatalf("single-permission read with only platform.admin err=%v", err)
	}
	if !slices.Equal(tx.requested, []string{permissionRead}) {
		t.Fatalf("single-permission requested=%v", tx.requested)
	}
}
