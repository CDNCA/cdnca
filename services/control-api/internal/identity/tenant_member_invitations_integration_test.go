//go:build integration

package identity_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

type invitationMailRecorder struct {
	mails []identity.TenantMemberInvitationMail
}

func (r *invitationMailRecorder) SendTenantMemberInvitation(_ context.Context, mail identity.TenantMemberInvitationMail) notification.SendResult {
	r.mails = append(r.mails, mail)
	return notification.SendResult{Disposition: notification.SendDelivered}
}

func TestTenantMemberInvitationInviteDispatchAccept(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	owner, scopeID := seedTenantMemberOwner(t, fixture)
	service := fixture.service
	if _, err := service.InviteTenantMember(ctx, owner, "new@example.com", "i0"); !errors.Is(err, identity.ErrTenantMemberInvitationUnavailable) {
		t.Fatalf("invite without key: %v", err)
	}
	outbox, err := notification.NewStore(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte(strings.Repeat("i", 32))
	if err := service.SetTenantMemberInvitationKey(key, outbox); err != nil {
		t.Fatal(err)
	}
	// The email channel is off by default: no invitation can be mailed.
	if _, err := service.InviteTenantMember(ctx, owner, "new@example.com", "i1"); !errors.Is(err, identity.ErrTenantMemberInvitationUnavailable) {
		t.Fatalf("invite with email off: %v", err)
	}
	if err := outbox.SetChannelSwitches(ctx, notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InviteTenantMember(ctx, owner, "not an email", "i2"); !errors.Is(err, identity.ErrInvalidUserInput) {
		t.Fatalf("invalid email: %v", err)
	}
	first, err := service.InviteTenantMember(ctx, owner, " New@Example.com ", "invite-1")
	if err != nil || first.Email != "new@example.com" || first.Status != "pending" {
		t.Fatalf("invite: %+v %v", first, err)
	}
	// A second invitation to the same address replaces the first.
	second, err := service.InviteTenantMember(ctx, owner, "new@example.com", "invite-2")
	if err != nil {
		t.Fatal(err)
	}
	items, err := service.ListTenantMemberInvitations(ctx, owner)
	if err != nil || len(items) != 2 || items[0].ID != second.ID || items[0].Status != "pending" || items[1].Status != "revoked" {
		t.Fatalf("list: %+v %v", items, err)
	}

	recorder := &invitationMailRecorder{}
	dispatcher, err := identity.NewTenantMemberInvitationDispatcher(fixture.pool, key, "https://console.example.test/accept-invitation", recorder)
	if err != nil {
		t.Fatal(err)
	}
	dispatch := func(invitationID uuid.UUID) notification.AnonymousDispatchResult {
		var attempt notification.AnonymousDeliveryAttempt
		if err := fixture.pool.QueryRow(ctx, `SELECT outbox.id,outbox.scope_id,invitation.anonymous_dispatch_reference,
			outbox.subject,outbox.body,outbox.dedup_key,outbox.template_id
			FROM tenant_member_invitations_398 invitation JOIN notification_outbox outbox ON outbox.id=invitation.outbox_id
			WHERE invitation.id=$1`, invitationID).Scan(&attempt.OutboxID, &attempt.ScopeID, &attempt.AnonymousDispatchReference,
			&attempt.Subject, &attempt.Body, &attempt.DedupKey, &attempt.Template.ID); err != nil {
			t.Fatal(err)
		}
		attempt.EventType, attempt.Channel, attempt.AttemptNumber = identity.TenantMemberInvitationEventType, notification.ChannelEmail, 1
		return dispatcher.Dispatch(ctx, attempt)
	}
	if result := dispatch(first.ID); result.Disposition != notification.AnonymousDispatchNoopACK || len(recorder.mails) != 0 {
		t.Fatalf("revoked invitation dispatch: %+v", result)
	}
	if result := dispatch(second.ID); result.Disposition != notification.AnonymousDispatchDelivered || len(recorder.mails) != 1 {
		t.Fatalf("dispatch: %+v", result)
	}
	mail := recorder.mails[0]
	if mail.Contact != "new@example.com" || !strings.Contains(mail.Body, "Member Tenant") || strings.Contains(mail.Body, "{{") {
		t.Fatalf("mail: %+v", mail)
	}
	link, err := url.Parse(mail.ActionURL)
	if err != nil || link.Host != "console.example.test" || link.Path != "/accept-invitation" || link.RawQuery != "" {
		t.Fatalf("link: %q", mail.ActionURL)
	}
	fragment, _ := url.ParseQuery(link.Fragment)
	token := fragment.Get("token")

	accept := func(token, username string) (identity.TenantMember, error) {
		return service.AcceptTenantMemberInvitation(ctx, identity.AcceptTenantMemberInvitationInput{
			Token: token, Username: username, DisplayName: "Newbie", Password: "LongEnough-Pass1", RequestID: "accept-" + username})
	}
	if _, err := accept(strings.Repeat("A", 43), "newbie"); !errors.Is(err, identity.ErrTenantMemberInvitationInvalid) {
		t.Fatalf("forged token: %v", err)
	}
	member, err := accept(token, "Newbie")
	if err != nil || member.Username != "newbie" || member.Role != identity.UserRoleViewer || member.Email == nil || *member.Email != "new@example.com" {
		t.Fatalf("accept: %+v %v", member, err)
	}
	if _, err := accept(token, "newbie2"); !errors.Is(err, identity.ErrTenantMemberInvitationInvalid) {
		t.Fatalf("token reused: %v", err)
	}
	login, err := service.Login(ctx, identity.LoginInput{Username: "newbie", Password: "LongEnough-Pass1"},
		identity.RequestInfo{RequestID: "newbie-login", SourceIP: "192.0.2.70"})
	if err != nil || login.Principal.ScopeID != scopeID {
		t.Fatalf("invited member login: %+v %v", login.Principal, err)
	}
	if result := dispatch(second.ID); result.Disposition != notification.AnonymousDispatchNoopACK || len(recorder.mails) != 1 {
		t.Fatalf("accepted invitation re-dispatch: %+v", result)
	}
	// The address now belongs to an account; expired links are refused.
	if _, err := service.InviteTenantMember(ctx, owner, "new@example.com", "invite-3"); !errors.Is(err, identity.ErrTenantMemberEmailTaken) {
		t.Fatalf("invite taken email: %v", err)
	}
	expiring, err := service.InviteTenantMember(ctx, owner, "late@example.com", "invite-4")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `ALTER TABLE tenant_member_invitations_398 DISABLE TRIGGER tenant_member_invitations_guard_398`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE tenant_member_invitations_398 SET created_at=$2,expires_at=$3 WHERE id=$1`,
		expiring.ID, time.Now().Add(-73*time.Hour), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `ALTER TABLE tenant_member_invitations_398 ENABLE TRIGGER tenant_member_invitations_guard_398`); err != nil {
		t.Fatal(err)
	}
	if result := dispatch(expiring.ID); result.Disposition != notification.AnonymousDispatchNoopACK {
		t.Fatalf("expired dispatch: %+v", result)
	}
	if err := service.RevokeTenantMemberInvitation(ctx, owner, second.ID, "revoke-accepted"); !errors.Is(err, identity.ErrMembershipNotFound) {
		t.Fatalf("revoke accepted: %v", err)
	}
	if err := service.RevokeTenantMemberInvitation(ctx, owner, expiring.ID, "revoke-expired"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	var actions []string
	rows, err := fixture.pool.Query(ctx, `SELECT action FROM audit_events WHERE action LIKE 'identity.tenant_member.inv%' ORDER BY occurred_at,action`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var action string
		_ = rows.Scan(&action)
		actions = append(actions, action)
	}
	want := "identity.tenant_member.invite,identity.tenant_member.invite,identity.tenant_member.invitation.accept," +
		"identity.tenant_member.invite,identity.tenant_member.invitation.revoke"
	if strings.Join(actions, ",") != want {
		t.Fatalf("audit actions=%v", actions)
	}
}
