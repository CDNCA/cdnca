//go:build integration

package notificationcontrol

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

func TestDeliveryPolicyRejectsUntrustedConfiguration(t *testing.T) {
	pool := deliveryPolicyMigrationPool(t, 251)
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, func() time.Time { return controlTestNow }), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	actor := seedControlActor(t, pool, "platform", permissionRead, permissionManage)
	cases := []struct {
		name string
		edit func(*UpdateDeliveryPolicyRequest)
	}{
		{"unknown event", func(r *UpdateDeliveryPolicyRequest) {
			r.Events = append(r.Events, DeliveryPolicyEvent{EventType: "unknown.event", RepeatCount: 1, IntervalHours: 24})
		}},
		{"unknown replacement", func(r *UpdateDeliveryPolicyRequest) { r.Events[0].EventType = "unknown.event" }},
		{"missing supported event", func(r *UpdateDeliveryPolicyRequest) {
			r.Events = slices.DeleteFunc(r.Events, func(e DeliveryPolicyEvent) bool { return e.EventType == EventTypeAnnouncementPublished })
		}},
		{"missing unsupported event", func(r *UpdateDeliveryPolicyRequest) {
			r.Events = slices.DeleteFunc(r.Events, func(e DeliveryPolicyEvent) bool { return e.EventType == "certificate.expiring" })
		}},
		{"duplicate event", func(r *UpdateDeliveryPolicyRequest) { r.Events = append(r.Events, r.Events[0]) }},
		{"forged supported capability", func(r *UpdateDeliveryPolicyRequest) {
			for i := range r.Events {
				if r.Events[i].EventType == "certificate.expiring" {
					r.Events[i].Supported, r.Events[i].Enabled, r.Events[i].SMSEnabled, r.Events[i].EmailEnabled = true, true, true, true
				}
			}
		}},
		{"forged supported flag alone", func(r *UpdateDeliveryPolicyRequest) {
			for i := range r.Events {
				if r.Events[i].EventType == "certificate.expiring" {
					r.Events[i].Supported = true
				}
			}
		}},
		{"forged unsupported capability", func(r *UpdateDeliveryPolicyRequest) {
			for i := range r.Events {
				if r.Events[i].EventType == EventTypeAnnouncementPublished {
					r.Events[i].Supported, r.Events[i].Enabled, r.Events[i].SMSEnabled, r.Events[i].EmailEnabled = false, false, false, false
				}
			}
		}},
		{"unsupported channel", func(r *UpdateDeliveryPolicyRequest) {
			for i := range r.Events {
				if r.Events[i].EventType == "certificate.expiring" {
					r.Events[i].SMSEnabled = true
				}
			}
		}},
		{"invalid timezone", func(r *UpdateDeliveryPolicyRequest) { r.Timezone = "Mars/Olympus" }},
		{"timezone whitespace", func(r *UpdateDeliveryPolicyRequest) { r.Timezone = "Asia/Shanghai " }},
		{"timezone control", func(r *UpdateDeliveryPolicyRequest) { r.Timezone = "Asia/Shanghai\n" }},
		{"host dependent timezone", func(r *UpdateDeliveryPolicyRequest) { r.Timezone = "Local" }},
		{"timezone file path", func(r *UpdateDeliveryPolicyRequest) { r.Timezone = "/etc/localtime" }},
	}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current, err := store.GetDeliveryPolicy(t.Context(), actor)
			if err != nil {
				t.Fatal(err)
			}
			request := UpdateDeliveryPolicyRequest{ExpectedRevision: current.Revision, WindowMode: current.WindowMode, WindowStart: current.WindowStart, WindowEnd: current.WindowEnd, Timezone: current.Timezone, Events: slices.Clone(current.Events), RequestID: fmt.Sprintf("policy-invalid-%d", index)}
			tc.edit(&request)
			before := deliveryPolicyPersistenceSnapshot(t, pool)
			if _, err := store.UpdateDeliveryPolicy(t.Context(), actor, request); !errors.Is(err, ErrInvalidInput) {
				t.Errorf("untrusted policy error = %v, want invalid input", err)
			}
			if after := deliveryPolicyPersistenceSnapshot(t, pool); after != before {
				t.Fatal("invalid request changed policy, event capabilities, receipts, audit or migrations")
			}
		})
	}
}

func TestDeliveryPolicyValidationPreservesFullCatalogAndReplay(t *testing.T) {
	pool := deliveryPolicyMigrationPool(t, 251)
	now := func() time.Time { return controlTestNow }
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, now), now)
	if err != nil {
		t.Fatal(err)
	}
	actor := seedControlActor(t, pool, "platform", permissionRead, permissionManage)
	for index, timezone := range []string{"UTC", "America/New_York", "Asia/Shanghai"} {
		current, err := store.GetDeliveryPolicy(t.Context(), actor)
		if err != nil {
			t.Fatal(err)
		}
		request := UpdateDeliveryPolicyRequest{ExpectedRevision: current.Revision, WindowMode: "custom", WindowStart: "22:30", WindowEnd: "08:15", Timezone: timezone, Events: current.Events, RequestID: fmt.Sprintf("policy-zone-%d", index)}
		updated, err := store.UpdateDeliveryPolicy(t.Context(), actor, request)
		if err != nil || !updated.Changed || updated.Revision != current.Revision+1 || updated.Timezone != timezone || !reflect.DeepEqual(updated.Events, current.Events) {
			t.Fatalf("complete policy write = %+v, %v", updated, err)
		}
		replay, err := store.UpdateDeliveryPolicy(t.Context(), actor, request)
		if err != nil || !reflect.DeepEqual(replay, updated) {
			t.Fatalf("exact replay = %+v, %v", replay, err)
		}
		request.ExpectedRevision, request.RequestID = updated.Revision, fmt.Sprintf("policy-zone-noop-%d", index)
		unchanged, err := store.UpdateDeliveryPolicy(t.Context(), actor, request)
		if err != nil || unchanged.Changed || unchanged.Revision != updated.Revision {
			t.Fatalf("no-op = %+v, %v", unchanged, err)
		}
	}
	assertDeliveryPolicyWriteCounts(t, pool, 6, 3, 0)
}

func TestPlatformSelfSubscriptionsRetainScopeAndPermissionBoundaries(t *testing.T) {
	// readSubscription reads notification_subscriptions.inbox_enabled (546), so the schema goes to 546;
	// 546 already has the unified audit columns (361/491), so none are added.
	pool := notificationControlMigrationPool091(t, 546)
	now := func() time.Time { return controlTestNow }
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, now), now)
	if err != nil {
		t.Fatal(err)
	}
	actor := seedControlActor(t, pool, "platform")
	other := seedControlActor(t, pool, "tenant")
	for index, eventType := range supportedEventTypes {
		initial, err := store.GetSubscription(t.Context(), actor, eventType)
		// fix-notifsub: the never-chosen default follows notification.DefaultChannels
		// (tenant events on when supported); SMS on + email off differs from every default.
		if err != nil || initial.Revision != 0 {
			t.Fatalf("self initial=%+v, %v", initial, err)
		}
		request := UpdateSubscriptionRequest{ExpectedRevision: 0, SMSEnabled: true, EmailEnabled: false, RequestID: fmt.Sprintf("platform-self-%d", index)}
		updated, err := store.UpdateSubscription(t.Context(), actor, eventType, request)
		if err != nil || !updated.Changed || updated.Revision != 1 || !updated.SMSEnabled || updated.EmailEnabled {
			t.Fatalf("self write=%+v, %v", updated, err)
		}
		if replay, err := store.UpdateSubscription(t.Context(), actor, eventType, request); err != nil || !reflect.DeepEqual(replay, updated) {
			t.Fatalf("self replay=%+v, %v", replay, err)
		}
		readback, err := store.GetSubscription(t.Context(), actor, eventType)
		updated.Changed = false
		if err != nil || !reflect.DeepEqual(readback, updated) {
			t.Fatalf("self readback=%+v, %v", readback, err)
		}
		foreign, err := store.GetSubscription(t.Context(), other, eventType)
		if err != nil || foreign.Revision != 0 || foreign.SMSEnabled != initial.SMSEnabled || foreign.EmailEnabled != initial.EmailEnabled {
			t.Fatalf("foreign leaked=%+v, %v", foreign, err)
		}
	}
	for _, eventType := range []string{"unknown.event", "certificate.expiring_soon", "package.monitor.bandwidth_over_limit"} {
		if _, err := store.GetSubscription(t.Context(), actor, eventType); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unsupported read=%v", err)
		}
		if _, err := store.UpdateSubscription(t.Context(), actor, eventType, UpdateSubscriptionRequest{RequestID: "platform-unknown"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unsupported write=%v", err)
		}
	}
	if _, err := store.UpdateSubscription(t.Context(), actor, supportedEventTypes[1], UpdateSubscriptionRequest{SMSEnabled: true, EmailEnabled: true, RequestID: "platform-self-0"}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("cross-event retry key=%v", err)
	}
	forged := actor
	forged.ScopeID = other.ScopeID
	if _, err := store.GetSubscription(t.Context(), forged, EventTypeAnnouncementPublished); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("forged scope read=%v", err)
	}
	if _, err := store.UpdateSubscription(t.Context(), forged, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{RequestID: "forged-scope"}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("forged scope write=%v", err)
	}
	if _, err := store.GetDeliveryPolicy(t.Context(), actor); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("self subscription must not grant policy read: %v", err)
	}
	if _, err := store.UpdateDeliveryPolicy(t.Context(), actor, UpdateDeliveryPolicyRequest{RequestID: "platform-policy-denied"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("self subscription must not grant policy write: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, actor.ScopeID, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSubscription(t.Context(), actor, EventTypeAnnouncementPublished); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("suspended self read=%v", err)
	}
	if _, err := store.UpdateSubscription(t.Context(), actor, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{SMSEnabled: true, EmailEnabled: true, RequestID: "platform-self-0"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("suspended self replay=%v", err)
	}
}
