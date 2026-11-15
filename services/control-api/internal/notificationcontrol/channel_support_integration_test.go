//go:build integration

package notificationcontrol

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// A customer is only offered a channel the runtime can
// send with and the platform switched on; otherwise the subscription reads
// it as unsupported (the page hides it) and refuses to switch it on.
func TestSubscriptionChannelSupportFollowsConfiguration(t *testing.T) {
	pool := notificationControlPool(t)
	now := func() time.Time { return controlTestNow }
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, now), now)
	if err != nil {
		t.Fatal(err)
	}
	store.WithChannelTransports(ChannelTransports{SMS: false, Email: true})
	admin := seedControlActor(t, pool, "platform", permissionRead, permissionManage)
	tenant := seedControlActor(t, pool, "tenant")

	// Platform switches off (migration default): nothing is supported.
	initial, err := store.GetSubscription(t.Context(), tenant, EventTypeAnnouncementPublished)
	if err != nil || initial.SMSSupported || initial.EmailSupported {
		t.Fatalf("switches off: %+v, %v", initial, err)
	}
	if _, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		EmailEnabled: true, RequestID: "email-while-off"}); !errors.Is(err, ErrChannelUnsupported) {
		t.Fatalf("email while switched off err = %v", err)
	}

	// The administrator cannot switch on a channel without a transport.
	channels, err := store.GetChannels(t.Context(), admin)
	if err != nil || channels.SMSSupported || !channels.EmailSupported {
		t.Fatalf("channels = %+v, %v", channels, err)
	}
	if _, err := store.UpdateChannels(t.Context(), admin, UpdateChannelsRequest{ExpectedRevision: channels.Revision,
		SMSEnabled: true, EmailEnabled: true, RequestID: "sms-without-transport"}); !errors.Is(err, ErrChannelUnsupported) {
		t.Fatalf("sms without transport err = %v", err)
	}
	if _, err := store.UpdateChannels(t.Context(), admin, UpdateChannelsRequest{ExpectedRevision: channels.Revision,
		EmailEnabled: true, RequestID: "email-on"}); err != nil {
		t.Fatal(err)
	}

	// Email on and configured: offered and accepted; SMS still hidden.
	value, err := store.GetSubscription(t.Context(), tenant, EventTypeAnnouncementPublished)
	if err != nil || value.SMSSupported || !value.EmailSupported {
		t.Fatalf("email on: %+v, %v", value, err)
	}
	updated, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		ExpectedRevision: value.Revision, EmailEnabled: true, RequestID: "email-on-sub"})
	if err != nil || !updated.EmailEnabled || !updated.EmailSupported || updated.SMSSupported {
		t.Fatalf("subscribe email = %+v, %v", updated, err)
	}
	if _, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		ExpectedRevision: updated.Revision, SMSEnabled: true, EmailEnabled: true, RequestID: "sms-sub"}); !errors.Is(err, ErrChannelUnsupported) {
		t.Fatalf("sms subscription err = %v", err)
	}
}

// Switching a channel off suspends the per-user sign-in second
// step, so an unconfirmed request is refused with the head count and the
// confirmed one goes through (the audit row carries the count).
func TestChannelDisableNeedsConfirmationWhenSecondStepUsersExist(t *testing.T) {
	pool := notificationControlPool(t)
	now := func() time.Time { return controlTestNow }
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, now), now)
	if err != nil {
		t.Fatal(err)
	}
	store.WithChannelTransports(ChannelTransports{SMS: false, Email: true})
	admin := seedControlActor(t, pool, "platform", permissionRead, permissionManage)
	tenant := seedControlActor(t, pool, "tenant")
	channels, err := store.GetChannels(t.Context(), admin)
	if err != nil {
		t.Fatal(err)
	}
	on, err := store.UpdateChannels(t.Context(), admin, UpdateChannelsRequest{ExpectedRevision: channels.Revision, EmailEnabled: true, RequestID: "email-on"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO identity_user_login_security(scope_id,user_id,revision,login_verification,updated_by_user_id,updated_at)
		VALUES($1,$2,1,'email',$2,now())`, tenant.ScopeID, tenant.UserID); err != nil {
		t.Fatal(err)
	}
	_, err = store.UpdateChannels(t.Context(), admin, UpdateChannelsRequest{ExpectedRevision: on.Revision, RequestID: "email-off"})
	var need *ChannelDisableConfirmationError
	if !errors.Is(err, ErrChannelDisableConfirmation) || !errors.As(err, &need) || need.EmailUsers != 1 || need.SMSUsers != 0 {
		t.Fatalf("unconfirmed disable err = %v", err)
	}
	off, err := store.UpdateChannels(t.Context(), admin, UpdateChannelsRequest{ExpectedRevision: on.Revision, ConfirmDisable: true, RequestID: "email-off"})
	if err != nil || off.EmailEnabled || !off.Changed {
		t.Fatalf("confirmed disable = %+v, %v", off, err)
	}
	var suspended int64
	if err := pool.QueryRow(t.Context(), `SELECT (payload->>'suspended_email_second_step_users')::bigint FROM audit_events
		WHERE action='notification.channels.update' AND request_id='email-off'`).Scan(&suspended); err != nil || suspended != 1 {
		t.Fatalf("audit suspended=%d err=%v", suspended, err)
	}
}
