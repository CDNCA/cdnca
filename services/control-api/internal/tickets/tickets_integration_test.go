package tickets

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/google/uuid"
)

func ptr(value string) *string { return &value }

// TestTicketIsolationAndPermissions: customers see only their own tickets
// (not even a teammate's in the same tenant); staff need tickets.read to
// look and tickets.manage to act; a platform session cannot use the
// customer surface for writes.
func TestTicketIsolationAndPermissions(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	own := f.create(t, f.customer, "iso-1", CreateInput{SiteID: f.siteID.String()})
	// evt-site: the created notice records the linked site (502).
	var subject uuid.UUID
	if err := f.pool.QueryRow(t.Context(), `SELECT subject_site_id FROM notification_events
		WHERE event_type=$1 AND source_event_id=$2`, EventCreated, own.Ticket.ID).Scan(&subject); err != nil || subject != f.siteID {
		t.Fatalf("ticket subject_site_id=%s, %v (want %s)", subject, err, f.siteID)
	}
	if own.Ticket.Status != StatusOpen || own.Ticket.TicketNo < 10001 || own.Ticket.SiteDomain == "" ||
		len(own.Messages) != 1 || own.Messages[0].AuthorKind != AuthorCustomer || own.Ticket.AssigneeUserID != "" {
		t.Fatalf("created = %+v", own)
	}
	f.create(t, f.teammate, "iso-2", CreateInput{Subject: "队友的工单"})
	f.create(t, f.otherTenant, "iso-3", CreateInput{Subject: "别家的工单"})

	page, err := f.service.List(ctx, f.customer, false, Filter{})
	if err != nil || page.Total != 1 || page.Items[0].ID != own.Ticket.ID || page.Items[0].UserID != "" {
		t.Fatalf("customer list = %+v, %v", page, err)
	}
	for _, actor := range []Actor{f.teammate, f.otherTenant} {
		if _, err := f.service.Get(ctx, actor, false, own.Ticket.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign get = %v", err)
		}
		if _, err := f.service.Reply(ctx, actor, false, "k-"+actor.UserID.String()[:8], "r1", own.Ticket.ID,
			ReplyInput{Body: "x"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign reply = %v", err)
		}
		if _, err := f.service.Close(ctx, actor, "r1", own.Ticket.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign close = %v", err)
		}
	}
	// Relating another tenant's site is refused.
	if _, err := f.service.Create(ctx, f.customer, "iso-4", "r", CreateInput{Category: "technical", Subject: "x",
		Body: "x", SiteID: f.otherSiteID.String()}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("foreign site = %v", err)
	}

	queue, err := f.service.List(ctx, f.reader, true, Filter{})
	if err != nil || queue.Total != 3 || queue.Items[0].Username == "" {
		t.Fatalf("staff queue = %+v, %v", queue, err)
	}
	if _, err := f.service.List(ctx, f.outsider, true, Filter{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("outsider list = %v", err)
	}
	if _, err := f.service.Reply(ctx, f.reader, true, "reader-1", "r", own.Ticket.ID, ReplyInput{Body: "x"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("read-only reply = %v", err)
	}
	if _, err := f.service.Update(ctx, f.reader, "r", own.Ticket.ID, UpdateInput{ExpectedRevision: 1,
		Priority: ptr("high")}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("read-only update = %v", err)
	}
	// A customer session is not a staff session and vice versa.
	if _, err := f.service.List(ctx, f.customer, true, Filter{}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("customer as staff = %v", err)
	}
	if _, err := f.service.Create(ctx, f.manager, "staff-create", "r", CreateInput{Category: "other", Subject: "x",
		Body: "x"}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("staff as customer = %v", err)
	}
	// Customer filters cannot reach staff-only fields.
	if _, err := f.service.List(ctx, f.customer, false, Filter{UserID: f.teammate.UserID.String()}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("customer user filter = %v", err)
	}
	// Staff filters.
	mine, err := f.service.List(ctx, f.reader, true, Filter{UserID: f.customer.UserID.String()})
	if err != nil || mine.Total != 1 {
		t.Fatalf("staff user filter = %+v, %v", mine, err)
	}
	byNumber, err := f.service.List(ctx, f.reader, true, Filter{Query: "#" + strconv.FormatInt(own.Ticket.TicketNo, 10)})
	if err != nil || byNumber.Total != 1 || byNumber.Items[0].ID != own.Ticket.ID {
		t.Fatalf("number search = %+v, %v", byNumber, err)
	}
	var auditRows int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='ticket.create' AND resource_id=$1
		AND scope_id=$2`, own.Ticket.ID, f.tenantScope).Scan(&auditRows); err != nil || auditRows != 1 {
		t.Fatalf("create audit = %d, %v", auditRows, err)
	}
}

// TestTicketLifecycle walks the state machine, unread markers, internal
// notes, SLA and the notification events.
func TestTicketLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	f.subscribe(t, f.customer, EventCreated, EventReplied, EventStatusChanged)
	created := f.create(t, f.customer, "life-1", CreateInput{Priority: "high"})
	id := created.Ticket.ID
	if events, deliveries := f.outbox(t, f.customer, EventCreated); events != 1 || deliveries != 1 {
		t.Fatalf("created notification events=%d deliveries=%d", events, deliveries)
	}
	staffSummary, err := f.service.Summary(ctx, f.manager, true)
	if err != nil || staffSummary.Pending != 1 || staffSummary.Unread != 1 {
		t.Fatalf("staff summary = %+v, %v", staffSummary, err)
	}

	// SLA: no staff answer for more than a day.
	f.clock.Advance(ResponseSLA + time.Minute)
	breached, err := f.service.List(ctx, f.manager, true, Filter{SLABreached: true})
	if err != nil || breached.Total != 1 || !breached.Items[0].SLABreached {
		t.Fatalf("sla list = %+v, %v", breached, err)
	}

	// Internal note: invisible to the customer, no notification, no unread.
	if _, err := f.service.Reply(ctx, f.manager, true, "note-1", "r", id, ReplyInput{Body: "怀疑源站故障",
		Internal: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Reply(ctx, f.customer, false, "note-2", "r", id, ReplyInput{Body: "x", Internal: true}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("customer internal = %v", err)
	}
	customerView, err := f.service.Get(ctx, f.customer, false, id)
	if err != nil || len(customerView.Messages) != 1 || customerView.Ticket.Unread {
		t.Fatalf("customer view after note = %+v, %v", customerView, err)
	}

	// Staff answer: pending_customer, claimed, first response, customer unread, notified.
	answered, err := f.service.Reply(ctx, f.manager, true, "reply-1", "r", id, ReplyInput{Body: "请检查源站"})
	if err != nil || answered.Ticket.Status != StatusPendingCustomer || answered.Ticket.AssigneeUserID != f.manager.UserID.String() ||
		answered.Ticket.FirstResponseAt == nil || answered.Ticket.SLABreached || len(answered.Messages) != 3 {
		t.Fatalf("staff reply = %+v, %v", answered.Ticket, err)
	}
	if events, _ := f.outbox(t, f.customer, EventReplied); events != 1 {
		t.Fatalf("replied events = %d", events)
	}
	summary, err := f.service.Summary(ctx, f.customer, false)
	if err != nil || summary.Unread != 1 {
		t.Fatalf("customer summary = %+v, %v", summary, err)
	}
	customerView, err = f.service.Get(ctx, f.customer, false, id)
	if err != nil || len(customerView.Messages) != 2 || !strings.HasPrefix(customerView.Messages[1].AuthorName, "客服") ||
		customerView.Ticket.AssigneeUserID != "" {
		t.Fatalf("customer view = %+v, %v", customerView, err)
	}
	if summary, _ := f.service.Summary(ctx, f.customer, false); summary.Unread != 0 {
		t.Fatalf("read did not clear unread: %+v", summary)
	}

	// Customer answers: back to processing (assigned) and staff unread.
	again, err := f.service.Reply(ctx, f.customer, false, "reply-2", "r", id, ReplyInput{Body: "已检查，正常"})
	if err != nil || again.Ticket.Status != StatusProcessing {
		t.Fatalf("customer reply = %+v, %v", again.Ticket, err)
	}

	// Stale revision is refused; resolve announces a status change.
	if _, err := f.service.Update(ctx, f.manager, "r", id, UpdateInput{ExpectedRevision: 1,
		Status: ptr(StatusResolved)}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update = %v", err)
	}
	staffView, _ := f.service.Get(ctx, f.manager, true, id)
	resolved, err := f.service.Update(ctx, f.manager, "r", id, UpdateInput{ExpectedRevision: staffView.Ticket.Revision,
		Status: ptr(StatusResolved)})
	if err != nil || resolved.Ticket.Status != StatusResolved || resolved.Ticket.ResolvedAt == nil {
		t.Fatalf("resolve = %+v, %v", resolved.Ticket, err)
	}
	if events, _ := f.outbox(t, f.customer, EventStatusChanged); events != 1 {
		t.Fatalf("status events = %d", events)
	}

	// Resolved: customer cannot reply until reopened; reopen is time-limited.
	if _, err := f.service.Reply(ctx, f.customer, false, "reply-3", "r", id, ReplyInput{Body: "x"}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reply to resolved = %v", err)
	}
	customerView, _ = f.service.Get(ctx, f.customer, false, id)
	if customerView.Ticket.ReopenableUntil == nil {
		t.Fatal("resolved ticket is not reopenable")
	}
	reopened, err := f.service.Reopen(ctx, f.customer, "r", id)
	if err != nil || reopened.Ticket.Status != StatusProcessing || reopened.Ticket.ResolvedAt != nil {
		t.Fatalf("reopen = %+v, %v", reopened.Ticket, err)
	}
	if _, err := f.service.Reopen(ctx, f.customer, "r", id); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reopen active = %v", err)
	}
	closed, err := f.service.Close(ctx, f.customer, "r", id)
	if err != nil || closed.Ticket.Status != StatusClosed || closed.Ticket.ClosedAt == nil {
		t.Fatalf("close = %+v, %v", closed.Ticket, err)
	}
	if again, err := f.service.Close(ctx, f.customer, "r", id); err != nil || again.Ticket.Revision != closed.Ticket.Revision {
		t.Fatalf("close twice = %+v, %v", again.Ticket, err)
	}
	if _, err := f.service.Reply(ctx, f.manager, true, "reply-4", "r", id, ReplyInput{Body: "x"}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("staff reply to closed = %v", err)
	}
	f.clock.Advance(ReopenWindow + time.Minute)
	if _, err := f.service.Reopen(ctx, f.customer, "r", id); !errors.Is(err, ErrReopenExpired) {
		t.Fatalf("late reopen = %v", err)
	}
}

// TestTicketNotificationFollowsSubscriptionAndPolicy: with no subscription
// row the event default applies (email on, SMS off); an explicit opt-out
// wins; a disabled event policy sends nothing. The subscription read returns
// the same default.
func TestTicketNotificationFollowsSubscriptionAndPolicy(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	control, err := notificationcontrol.NewStoreWithDependencies(f.pool, audit.New(f.pool), f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := notificationcontrol.Actor{UserID: f.customer.UserID, ScopeID: f.customer.ScopeID,
		SessionID: f.customer.SessionID, ScopeKind: "tenant"}
	initial, err := control.GetSubscription(ctx, actor, EventCreated)
	// fix-notifsub: a member who never chose has both reminders on.
	if err != nil || !initial.EmailEnabled || !initial.SMSEnabled || initial.Revision != 0 {
		t.Fatalf("default subscription read = %+v, %v", initial, err)
	}
	f.create(t, f.customer, "sub-1", CreateInput{})
	var channels []string
	if err := f.pool.QueryRow(ctx, `SELECT COALESCE(array_agg(outbox.channel ORDER BY outbox.channel), '{}')
		FROM notification_outbox outbox JOIN notification_events event ON event.id=outbox.event_id
		WHERE event.recipient_user_id=$1 AND event.event_type=$2`, f.customer.UserID, EventCreated).Scan(&channels); err != nil ||
		len(channels) != 2 || channels[0] != "email" || channels[1] != "sms" {
		t.Fatalf("default channels = %v, %v", channels, err)
	}
	if _, err := control.UpdateSubscription(ctx, actor, EventCreated, notificationcontrol.UpdateSubscriptionRequest{
		ExpectedRevision: 0, RequestID: "opt-out-1"}); err != nil {
		t.Fatal(err)
	}
	f.create(t, f.customer, "sub-2", CreateInput{})
	if events, deliveries := f.outbox(t, f.customer, EventCreated); events != 2 || deliveries != 2 {
		t.Fatalf("opted out events=%d deliveries=%d", events, deliveries)
	}
	f.subscribe(t, f.customer, EventCreated)
	exec(t, f.pool, `UPDATE notification_event_policies SET enabled=false WHERE event_type=$1`, EventCreated)
	f.create(t, f.customer, "sub-3", CreateInput{})
	if events, deliveries := f.outbox(t, f.customer, EventCreated); events != 3 || deliveries != 2 {
		t.Fatalf("policy disabled events=%d deliveries=%d", events, deliveries)
	}
	exec(t, f.pool, `UPDATE notification_event_policies SET enabled=true WHERE event_type=$1`, EventCreated)
	f.create(t, f.customer, "sub-4", CreateInput{})
	var body string
	if err := f.pool.QueryRow(ctx, `SELECT outbox.body FROM notification_outbox outbox
		JOIN notification_events event ON event.id=outbox.event_id
		WHERE event.recipient_user_id=$1 AND event.event_type=$2 ORDER BY outbox.created_at DESC LIMIT 1`,
		f.customer.UserID, EventCreated).Scan(&body); err != nil || !strings.Contains(body, "网站 502") {
		t.Fatalf("rendered body = %q, %v", body, err)
	}
}

// TestTicketStaffNotification: new tickets and customer replies reach the
// platform members holding tickets.manage (email by default); read-only staff
// and outsiders are not notified, nor are staff replies or internal notes.
func TestTicketStaffNotification(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	ticket := f.create(t, f.customer, "staff-1", CreateInput{Subject: "证书问题"})
	if events, deliveries := f.outbox(t, f.manager, EventStaffCreated); events != 1 || deliveries != 1 {
		t.Fatalf("manager created events=%d deliveries=%d", events, deliveries)
	}
	for _, other := range []Actor{f.reader, f.outsider} {
		if events, _ := f.outbox(t, other, EventStaffCreated); events != 0 {
			t.Fatalf("non-manager notified %d times", events)
		}
	}
	var body string
	if err := f.pool.QueryRow(ctx, `SELECT outbox.body FROM notification_outbox outbox
		JOIN notification_events event ON event.id=outbox.event_id
		WHERE event.recipient_user_id=$1 AND event.event_type=$2`, f.manager.UserID, EventStaffCreated).Scan(&body); err != nil ||
		!strings.Contains(body, "证书问题") || !strings.Contains(body, "tk-") {
		t.Fatalf("staff body = %q, %v", body, err)
	}
	if _, err := f.service.Reply(ctx, f.manager, true, "staff-2", "r", ticket.Ticket.ID, ReplyInput{Body: "处理中"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Reply(ctx, f.manager, true, "staff-3", "r", ticket.Ticket.ID, ReplyInput{Body: "备注", Internal: true}); err != nil {
		t.Fatal(err)
	}
	if events, _ := f.outbox(t, f.manager, EventStaffReplied); events != 0 {
		t.Fatalf("staff own reply notified staff %d times", events)
	}
	if _, err := f.service.Reply(ctx, f.customer, false, "staff-4", "r", ticket.Ticket.ID, ReplyInput{Body: "还是不行"}); err != nil {
		t.Fatal(err)
	}
	if events, deliveries := f.outbox(t, f.manager, EventStaffReplied); events != 1 || deliveries != 1 {
		t.Fatalf("manager replied events=%d deliveries=%d", events, deliveries)
	}
}

// TestTicketIdempotency: the same key replays, a different request under the
// same key is refused.
func TestTicketIdempotency(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	first := f.create(t, f.customer, "idem-1", CreateInput{})
	replayed := f.create(t, f.customer, "idem-1", CreateInput{})
	if replayed.Ticket.ID != first.Ticket.ID {
		t.Fatalf("replay created a second ticket")
	}
	if _, err := f.service.Create(ctx, f.customer, "idem-1", "r", CreateInput{Category: "technical", Subject: "不同",
		Body: "x"}); !errors.Is(err, ErrIdempotency) {
		t.Fatalf("conflicting replay = %v", err)
	}
	for range 2 {
		if _, err := f.service.Reply(ctx, f.customer, false, "idem-reply", "r", first.Ticket.ID, ReplyInput{Body: "补充"}); err != nil {
			t.Fatal(err)
		}
	}
	detail, _ := f.service.Get(ctx, f.customer, false, first.Ticket.ID)
	if len(detail.Messages) != 2 {
		t.Fatalf("replayed reply added %d messages", len(detail.Messages)-1)
	}
}

// TestTicketAttachments: type and size limits, malware rejection, binding
// only the caller's own uploads, and visibility (internal note attachments
// stay staff-only).
func TestTicketAttachments(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	upload := func(actor Actor, staff bool, name, mime string, body []byte) (Attachment, error) {
		return f.service.Upload(ctx, actor, staff, "r", UploadInput{FileName: name, MIMEType: mime, Body: body})
	}
	if _, err := upload(f.customer, false, "a.png", "image/png", []byte("<script>alert(1)</script>")); !errors.Is(err, ErrAttachmentType) {
		t.Fatalf("disguised html = %v", err)
	}
	if _, err := upload(f.customer, false, "a.svg", "image/svg+xml", []byte("<svg/>")); !errors.Is(err, ErrAttachmentType) {
		t.Fatalf("svg = %v", err)
	}
	if _, err := upload(f.customer, false, "a.txt", "text/plain", make([]byte, MaxAttachmentSize+1)); !errors.Is(err, ErrAttachmentTooLarge) {
		t.Fatalf("oversize = %v", err)
	}
	if _, err := upload(f.customer, false, "../a.txt", "text/plain", []byte("x")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("path name = %v", err)
	}
	eicar := []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	if _, err := upload(f.customer, false, "eicar.txt", "text/plain", eicar); !errors.Is(err, ErrAttachmentRejected) {
		t.Fatalf("eicar = %v", err)
	}
	image, err := upload(f.customer, false, "截图.png", "image/png", pngBody)
	if err != nil || image.SizeBytes != int64(len(pngBody)) {
		t.Fatalf("png = %+v, %v", image, err)
	}
	var key string
	if err := f.pool.QueryRow(ctx, `SELECT object_key FROM ticket_attachments WHERE id=$1`, image.ID).Scan(&key); err != nil ||
		!strings.HasPrefix(key, "ticket-attachments/"+f.customer.UserID.String()+"/") || strings.Contains(key, image.ID) {
		t.Fatalf("object key %q is derived from the public id (%v)", key, err)
	}
	foreign, err := upload(f.teammate, false, "x.txt", "text/plain", []byte("teammate"))
	if err != nil {
		t.Fatal(err)
	}
	// Someone else's pending upload cannot be bound or downloaded.
	if _, err := f.service.Create(ctx, f.customer, "att-0", "r", CreateInput{Category: "technical", Subject: "x",
		Body: "x", AttachmentIDs: []string{foreign.ID}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bind foreign upload = %v", err)
	}
	if _, err := f.service.Open(ctx, f.customer, false, foreign.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("open foreign pending = %v", err)
	}
	ticket := f.create(t, f.customer, "att-1", CreateInput{AttachmentIDs: []string{image.ID}})
	if len(ticket.Messages[0].Attachments) != 1 {
		t.Fatalf("attachments = %+v", ticket.Messages[0])
	}
	// Bound once only.
	if _, err := f.service.Reply(ctx, f.customer, false, "att-2", "r", ticket.Ticket.ID,
		ReplyInput{Body: "x", AttachmentIDs: []string{image.ID}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("rebind = %v", err)
	}
	for _, viewer := range []struct {
		actor Actor
		staff bool
	}{{f.customer, false}, {f.reader, true}} {
		download, err := f.service.Open(ctx, viewer.actor, viewer.staff, image.ID)
		if err != nil {
			t.Fatalf("open = %v", err)
		}
		body, _ := io.ReadAll(download.Body)
		download.Body.Close()
		if string(body) != string(pngBody) {
			t.Fatal("downloaded body differs")
		}
	}
	if _, err := f.service.Open(ctx, f.teammate, false, image.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("teammate open = %v", err)
	}
	// Staff note attachment is invisible to the customer.
	note, err := upload(f.manager, true, "log.txt", "text/plain", []byte("internal log"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Reply(ctx, f.manager, true, "att-3", "r", ticket.Ticket.ID,
		ReplyInput{Body: "内部日志", Internal: true, AttachmentIDs: []string{note.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Open(ctx, f.customer, false, note.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("customer open internal attachment = %v", err)
	}
	view, _ := f.service.Get(ctx, f.customer, false, ticket.Ticket.ID)
	for _, message := range view.Messages {
		for _, attachment := range message.Attachments {
			if attachment.ID == note.ID {
				t.Fatal("internal attachment listed to the customer")
			}
		}
	}
	// Pending upload cap.
	for index := 0; ; index++ {
		_, err := upload(f.otherTenant, false, "n.txt", "text/plain", []byte("n"))
		if errors.Is(err, ErrUploadLimit) {
			if index != MaxPendingUploads {
				t.Fatalf("limit hit after %d uploads", index)
			}
			break
		}
		if err != nil || index > MaxPendingUploads {
			t.Fatalf("upload %d = %v", index, err)
		}
	}
	// Attachments disabled without an object store.
	disabled, _ := New(Config{Pool: f.pool, Notifier: f.notifications, Now: f.clock.Now})
	if _, err := disabled.Upload(ctx, f.customer, false, "r", UploadInput{FileName: "a.txt", MIMEType: "text/plain",
		Body: []byte("x")}); !errors.Is(err, ErrAttachmentsDisabled) {
		t.Fatalf("disabled upload = %v", err)
	}
}

// TestTicketAssignment: only ticket staff can be assignees; claiming an open
// ticket moves it to processing without notifying the customer.
func TestTicketAssignment(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	f.subscribe(t, f.customer, EventStatusChanged)
	ticket := f.create(t, f.customer, "assign-1", CreateInput{})
	assignees, err := f.service.Assignees(ctx, f.reader)
	if err != nil || len(assignees) != 1 || assignees[0].UserID != f.manager.UserID.String() {
		t.Fatalf("assignees = %+v, %v", assignees, err)
	}
	if _, err := f.service.Update(ctx, f.manager, "r", ticket.Ticket.ID, UpdateInput{ExpectedRevision: 1,
		AssigneeUserID: ptr(f.outsider.UserID.String())}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("assign outsider = %v", err)
	}
	claimed, err := f.service.Update(ctx, f.manager, "r", ticket.Ticket.ID, UpdateInput{ExpectedRevision: 1,
		AssigneeUserID: ptr(f.manager.UserID.String()), Priority: ptr("urgent")})
	if err != nil || claimed.Ticket.Status != StatusProcessing || claimed.Ticket.Priority != "urgent" {
		t.Fatalf("claim = %+v, %v", claimed.Ticket, err)
	}
	if events, _ := f.outbox(t, f.customer, EventStatusChanged); events != 0 {
		t.Fatalf("claim notified the customer %d times", events)
	}
	mine, err := f.service.List(ctx, f.manager, true, Filter{AssigneeUserID: "me"})
	if err != nil || mine.Total != 1 {
		t.Fatalf("mine = %+v, %v", mine, err)
	}
	unassigned, err := f.service.Update(ctx, f.manager, "r", ticket.Ticket.ID, UpdateInput{
		ExpectedRevision: claimed.Ticket.Revision, AssigneeUserID: ptr("")})
	if err != nil || unassigned.Ticket.AssigneeUserID != "" {
		t.Fatalf("unassign = %+v, %v", unassigned.Ticket, err)
	}
}

// TestTicketPendingAttachmentCleanup: unbound uploads older than the window
// lose their object and row; fresh and bound ones stay; a store failure keeps
// the row so the next run retries.
func TestTicketPendingAttachmentCleanup(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	upload := func(name string) Attachment {
		attachment, err := f.service.Upload(ctx, f.customer, false, "r", UploadInput{FileName: name, MIMEType: "text/plain",
			Body: []byte(name)})
		if err != nil {
			t.Fatal(err)
		}
		return attachment
	}
	stale, bound := upload("stale.txt"), upload("bound.txt")
	f.create(t, f.customer, "cleanup-1", CreateInput{AttachmentIDs: []string{bound.ID}})
	f.clock.Advance(PendingUploadWindow + time.Minute)
	fresh := upload("fresh.txt")

	f.objects.failDelete = true
	if removed, err := f.service.CleanupPendingAttachments(ctx, 100); err != nil || removed != 0 {
		t.Fatalf("cleanup with store down = %d, %v", removed, err)
	}
	if _, err := f.service.Open(ctx, f.customer, false, stale.ID); err != nil {
		t.Fatalf("row was dropped before its object: %v", err)
	}
	f.objects.failDelete = false
	removed, err := f.service.CleanupPendingAttachments(ctx, 100)
	if err != nil || removed != 1 {
		t.Fatalf("cleanup = %d, %v", removed, err)
	}
	if _, err := f.service.Open(ctx, f.customer, false, stale.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale still readable: %v", err)
	}
	for _, id := range []string{fresh.ID, bound.ID} {
		if _, err := f.service.Open(ctx, f.customer, false, id); err != nil {
			t.Fatalf("kept attachment %s: %v", id, err)
		}
	}
	if f.objects.count() != 2 {
		t.Fatalf("objects left = %d", f.objects.count())
	}
	var audits int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='ticket.attachment.expire'
		AND resource_id=$1`, stale.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("expire audit = %d, %v", audits, err)
	}
	// A bound attachment cannot be deleted even directly.
	if _, err := f.pool.Exec(ctx, `DELETE FROM ticket_attachments WHERE id=$1`, bound.ID); err == nil {
		t.Fatal("bound attachment was deletable")
	}
}

// TestTicketListLastReplyAuthor (AUDIT-FINAL-1027 P6): the list names who
// wrote the newest visible message. Customers never see internal notes, and a
// staff author shows as "客服 <name>" to them, the same as the detail view.
func TestTicketListLastReplyAuthor(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	created := f.create(t, f.customer, "last-1", CreateInput{})
	id := created.Ticket.ID
	author := func(actor Actor, staff bool) (string, string) {
		t.Helper()
		page, err := f.service.List(ctx, actor, staff, Filter{})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != id {
			t.Fatalf("list = %+v, %v", page, err)
		}
		return page.Items[0].LastReplyAuthor, page.Items[0].LastReplyAuthorKind
	}
	if name, kind := author(f.manager, true); name != "customer" || kind != AuthorCustomer {
		t.Fatalf("after create staff sees %q/%q, want customer/customer", name, kind)
	}
	f.clock.Advance(time.Minute)
	if _, err := f.service.Reply(ctx, f.manager, true, "last-2", "r", id, ReplyInput{Body: "请检查源站"}); err != nil {
		t.Fatal(err)
	}
	if name, kind := author(f.customer, false); name != "客服 staff-manager" || kind != AuthorStaff {
		t.Fatalf("after staff reply customer sees %q/%q", name, kind)
	}
	f.clock.Advance(time.Minute)
	if _, err := f.service.Reply(ctx, f.manager, true, "last-4", "r", id, ReplyInput{Body: "内部备注", Internal: true}); err != nil {
		t.Fatal(err)
	}
	if name, _ := author(f.manager, true); name != "staff-manager" {
		t.Fatalf("staff after internal note sees %q", name)
	}
	if name, kind := author(f.customer, false); name != "客服 staff-manager" || kind != AuthorStaff {
		t.Fatalf("customer must not see the internal note author: %q/%q", name, kind)
	}
	f.clock.Advance(time.Minute)
	if _, err := f.service.Reply(ctx, f.customer, false, "last-5", "r", id, ReplyInput{Body: "已检查"}); err != nil {
		t.Fatal(err)
	}
	if name, kind := author(f.manager, true); name != "customer" || kind != AuthorCustomer {
		t.Fatalf("after customer reply staff sees %q/%q", name, kind)
	}
}
