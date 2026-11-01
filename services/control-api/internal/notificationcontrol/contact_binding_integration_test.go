package notificationcontrol

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// GET/PUT 订阅带出本人邮箱/手机号绑定状态，随资料当前值变化，不进写入回执。
func TestSubscriptionReportsOwnContactBindingPostgreSQL(t *testing.T) {
	pool := notificationControlPool(t)
	tenant := seedControlActor(t, pool, "tenant")
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, func() time.Time { return controlTestNow }),
		func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	bound := func(label string, value Subscription, email, phone bool) {
		t.Helper()
		if value.EmailBound == nil || value.PhoneBound == nil || *value.EmailBound != email || *value.PhoneBound != phone {
			t.Fatalf("%s: email_bound=%v phone_bound=%v, want %v/%v", label, value.EmailBound, value.PhoneBound, email, phone)
		}
	}
	if _, err := pool.Exec(t.Context(), `UPDATE users SET email=NULL,phone=NULL WHERE id=$1`, tenant.UserID); err != nil {
		t.Fatal(err)
	}
	value, err := store.GetSubscription(t.Context(), tenant, EventTypeAnnouncementPublished)
	if err != nil {
		t.Fatal(err)
	}
	bound("unbound", value, false, false)
	if _, err := pool.Exec(t.Context(), `UPDATE users SET email='owner@example.test',phone='13800000000' WHERE id=$1`, tenant.UserID); err != nil {
		t.Fatal(err)
	}
	if value, err = store.GetSubscription(t.Context(), tenant, EventTypeAnnouncementPublished); err != nil {
		t.Fatal(err)
	}
	bound("bound", value, true, true)
	write := UpdateSubscriptionRequest{ExpectedRevision: value.Revision, SMSEnabled: value.SMSEnabled, EmailEnabled: !value.EmailEnabled,
		RequestID: "contact-binding-put"}
	updated, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, write)
	if err != nil {
		t.Fatal(err)
	}
	bound("put", updated, true, true)
	// 重放同一请求：绑定状态取当前资料，不是回执里的旧值。
	if _, err := pool.Exec(t.Context(), `UPDATE users SET email=NULL WHERE id=$1`, tenant.UserID); err != nil {
		t.Fatal(err)
	}
	replayed, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, write)
	if err != nil {
		t.Fatal(err)
	}
	bound("replay", replayed, false, true)
}
