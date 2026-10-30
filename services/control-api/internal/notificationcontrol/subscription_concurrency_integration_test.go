//go:build integration

package notificationcontrol

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// notif-sub：订阅页对同一会话并发 23 个 GET（公告 + 22 个事件），
// 同时浏览器可能刷新令牌。生产连接池上限 20（database/pool.go）。
// 要求全部 GET 成功、刷新成功，任何一项都不能变成未分类错误（HTTP 500）。
func TestSubscriptionConcurrentReadsWithRefreshPostgreSQL(t *testing.T) {
	pool := notificationControlPool(t)
	if pool.Config().MaxConns != 20 {
		t.Fatalf("测试连接池须对齐生产上限 20（database.Open），当前 %d", pool.Config().MaxConns)
	}
	now := time.Now().UTC()
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, func() time.Time { return now }),
		func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	store.WithChannelTransports(ChannelTransports{SMS: true, Email: true})
	identities := identity.NewStore(pool)
	events := supportedEventTypes[:23]

	const rounds = 30
	failures := map[string]int{}
	for round := range rounds {
		actor := seedControlActor(t, pool, "tenant")
		if os.Getenv("NOTIF_SUB_FRESH_POOL") != "" {
			// 生产池 MinConns=1、空闲 15 分钟回收：页面并发时大多数请求要新建后端连接。
			pool.Reset()
		}
		// seedControlActor 用固定测试时钟建会话，这里改成当前时间有效。
		refreshToken := fmt.Sprintf("notif-sub-refresh-%d-%s", round, uuid.NewString())
		digest := sha256.Sum256([]byte(refreshToken))
		if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET refresh_token_hash=$2,created_at=$3,expires_at=$4 WHERE id=$1`,
			actor.SessionID, digest[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wait sync.WaitGroup
		var mu sync.Mutex
		record := func(label string, err error) {
			if err == nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			key := label + ": " + describeConcurrencyError(err)
			failures[key]++
		}
		for _, event := range events {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				_, err := store.GetSubscription(t.Context(), actor, event)
				record("GET", err)
			}()
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			newHash := sha256.Sum256([]byte(refreshToken + "-next"))
			_, _, err := identities.RotateSession(t.Context(), digest[:], uuid.New(), newHash[:],
				now.Add(2*time.Hour), "notif-sub-refresh", "test", "127.0.0.1")
			record("refresh", err)
		}()
		close(start)
		wait.Wait()
	}
	if len(failures) > 0 {
		t.Fatalf("%d 轮并发后出现失败：%v", rounds, failures)
	}
}

func describeConcurrencyError(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return "SQLSTATE " + pgErr.Code + " " + pgErr.Message
	}
	return err.Error()
}

// 候选 2 的对照：池里一条连接残留会话级 advisory 锁（例如解锁失败后照样 Release），
// 之后落到这条连接上的 IAM 协议事务都会被 iam_global_lock_shared_v1 以 P6902 拒绝，
// 表现为同一页面上随机几个 GET 500。这里只确认这一形态，不代表线上发生过。
func TestSubscriptionReadOnConnectionWithLeakedSessionAdvisoryLockPostgreSQL(t *testing.T) {
	pool := notificationControlPool(t)
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, func() time.Time { return controlTestNow }),
		func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	actor := seedControlActor(t, pool, "tenant")
	pool.Reset()
	leaked, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaked.Exec(t.Context(), `SELECT pg_advisory_lock(424242)`); err != nil {
		t.Fatal(err)
	}
	leaked.Release() // 只剩这一条连接，下一次 GET 必然复用它
	_, err = store.GetSubscription(t.Context(), actor, EventTypeAnnouncementPublished)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) && err != nil {
		t.Logf("GET on leaked connection: %v", err)
	}
	if err == nil {
		t.Fatal("GET on a connection holding a session advisory lock succeeded; candidate 2 shape does not hold")
	}
	t.Logf("GET on leaked connection = %s", describeConcurrencyError(err))
}

// notif-sub 修复约束：同一会话的读取鉴权互不排队（FOR SHARE），
// 但停用账号等状态写入仍要等正在进行的读取结束（与修复前同样的栅栏）。
func TestSubscriptionReadAuthorizationSharesIdentityRowsPostgreSQL(t *testing.T) {
	pool := notificationControlPool(t)
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, func() time.Time { return controlTestNow }),
		func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	actor := seedControlActor(t, pool, "tenant")
	reader, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback(t.Context())
	if err := authorizeRead(t.Context(), reader, actor, "", controlTestNow); err != nil {
		t.Fatalf("open read authorization: %v", err)
	}

	second, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback(t.Context())
	if _, err := second.Exec(t.Context(), `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	if err := authorizeRead(t.Context(), second, actor, "", controlTestNow); err != nil {
		t.Fatalf("second read waited on the first: %v", describeConcurrencyError(err))
	}
	if err := second.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	suspender, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer suspender.Rollback(t.Context())
	if _, err := suspender.Exec(t.Context(), `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = suspender.Exec(t.Context(), `UPDATE users SET status='disabled' WHERE id=$1`, actor.UserID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("disable user during open read = %v, want lock timeout", err)
	}
	_ = suspender.Rollback(t.Context())
	if err := reader.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSubscription(t.Context(), actor, EventTypeAnnouncementPublished); err != nil {
		t.Fatalf("GET after read committed: %v", err)
	}
}
