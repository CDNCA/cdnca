//go:build integration

package identitysessionhttp

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// E1: in production pgx scans timestamptz in time.Local (Asia/Shanghai on the
// control host). The pool here scans in UTC+8 the same way, and every page
// boundary must still produce a cursor the next request accepts.
func TestListPagesThroughSessionFamiliesWhenPGTimesAreNotUTC(t *testing.T) {
	shanghai := time.FixedZone("UTC+8", 8*60*60)
	pool := databasetest.MigratedPool(t, func(config *pgxpool.Config) {
		config.ConnConfig.RuntimeParams["timezone"] = "Asia/Shanghai"
		config.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
			conn.TypeMap().RegisterType(&pgtype.Type{Name: "timestamptz", OID: pgtype.TimestamptzOID,
				Codec: &pgtype.TimestamptzCodec{ScanLocation: shanghai}})
			return nil
		}
	})
	ctx := context.Background()
	now := time.Date(2036, 7, 23, 8, 0, 0, 0, time.UTC)
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'session paging tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$2,'test-password-hash')`, userID, "paging-"+uuid.NewString()[:8])
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	const families = 5
	var callerSession uuid.UUID
	for index := 0; index < families; index++ {
		sessionID := uuid.New()
		hash := sha256.Sum256(sessionID[:])
		mustExec(t, pool, `INSERT INTO auth_sessions(
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
		) VALUES($1,$1,$2,$3,$4,$5,$6)`, sessionID, userID, scopeID, hash[:],
			now.Add(-time.Duration(index+1)*time.Hour), now.Add(24*time.Hour))
		if index == 0 {
			callerSession = sessionID
		}
	}
	store, err := NewStoreWithDependencies(pool, audit.New(pool), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{SessionID: callerSession, ScopeID: scopeID, UserID: userID, ScopeKind: "tenant"}
	seen := map[uuid.UUID]bool{}
	cursor, pages := "", 0
	for {
		page, err := store.List(ctx, ListRequest{Actor: actor, Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatalf("page %d List error=%v", pages+1, err)
		}
		pages++
		for _, item := range page.Items {
			if item.CreatedAt.Location() == time.UTC {
				t.Fatalf("fixture did not scan in a non-UTC location: %v", item.CreatedAt)
			}
			if seen[item.FamilyID] {
				t.Fatalf("family %s returned twice", item.FamilyID)
			}
			seen[item.FamilyID] = true
		}
		if page.NextCursor == "" {
			break
		}
		if pages > families {
			t.Fatal("pagination did not terminate")
		}
		cursor = page.NextCursor
	}
	if pages != 3 || len(seen) != families {
		t.Fatalf("pages=%d families=%d, want 3 and %d", pages, len(seen), families)
	}
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}
