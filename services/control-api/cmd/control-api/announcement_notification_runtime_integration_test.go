package main

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var announcementNotificationTestTime = time.Date(2026, 7, 28, 9, 30, 0, 0, time.UTC)

func TestAnnouncementNotificationPostgresTransactionRoutingReplayAndRevocation(t *testing.T) {
	pool := openAnnouncementNotificationDatabase(t)
	store, err := notification.NewStoreWithClock(
		pool,
		audit.New(pool),
		func() time.Time { return announcementNotificationTestTime },
	)
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := newAnnouncementNotificationOutbox(store)
	if err != nil {
		t.Fatal(err)
	}
	refs := saveAnnouncementPublishedTemplates(t, store)
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true, SMS: true}); err != nil {
		t.Fatal(err)
	}
	scopeID, emailUserID := seedNotificationRuntimeMember(t, pool)
	smsUserID := seedAnnouncementNotificationMember(t, pool, scopeID, "sms")
	// seedNotificationRuntimeMember 固定邮箱 member@example.test，第二次调用会撞 159 的邮箱唯一索引
	foreignTenantID, foreignScopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'Announcement Foreign')`, foreignTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, foreignScopeID, foreignTenantID); err != nil {
		t.Fatal(err)
	}
	foreignUserID := seedAnnouncementNotificationMember(t, pool, foreignScopeID, "foreign")
	if err := store.SetSubscription(
		t.Context(), scopeID, emailUserID, announcementPublishedEventType,
		notification.Subscription{Email: true},
	); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSubscription(
		t.Context(), scopeID, smsUserID, announcementPublishedEventType,
		notification.Subscription{SMS: true},
	); err != nil {
		t.Fatal(err)
	}

	notice := announcement.PublicationNotice{
		ScopeID: scopeID, AnnouncementID: uuid.New(), Version: 7,
		Title: "维护公告", Body: "边缘节点将在低峰期滚动升级。", PublishedAt: announcementNotificationTestTime,
		RecipientIDs:  []uuid.UUID{emailUserID, smsUserID},
		InboxEventIDs: []uuid.UUID{uuid.New(), uuid.New()},
	}
	if err := enqueueAnnouncementNotice(t.Context(), pool, outbox, notice, true); err != nil {
		t.Fatal(err)
	}

	sourceEventID := announcementPublicationSourceEventID(notice.AnnouncementID, notice.Version)
	rows, err := pool.Query(t.Context(), `
		SELECT event.recipient_user_id,outbox.channel,outbox.template_id,outbox.template_version,
		       outbox.subject,outbox.body,outbox.dedup_key
		FROM notification_events event
		JOIN notification_outbox outbox ON outbox.scope_id=event.scope_id AND outbox.event_id=event.id
		WHERE event.scope_id=$1 AND event.source_event_id=$2 AND event.event_type=$3
		ORDER BY event.recipient_user_id`, scopeID, sourceEventID, announcementPublishedEventType)
	if err != nil {
		t.Fatal(err)
	}
	type persistedDelivery struct {
		recipientID uuid.UUID
		channel     notification.Channel
		templateID  string
		version     uint64
		subject     string
		body        string
		dedupKey    string
	}
	var deliveries []persistedDelivery
	for rows.Next() {
		var delivery persistedDelivery
		if err := rows.Scan(
			&delivery.recipientID,
			&delivery.channel,
			&delivery.templateID,
			&delivery.version,
			&delivery.subject,
			&delivery.body,
			&delivery.dedupKey,
		); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		deliveries = append(deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if len(deliveries) != 2 {
		t.Fatalf("deliveries = %+v", deliveries)
	}
	for _, delivery := range deliveries {
		wantChannel := notification.ChannelEmail
		wantSubject := "[公告] " + notice.Title
		wantBody := notice.Body
		if delivery.recipientID == smsUserID {
			wantChannel = notification.ChannelSMS
			wantSubject = ""
			wantBody = notice.Title + "\n" + notice.Body
		}
		if delivery.channel != wantChannel || delivery.templateID != announcementPublishedTemplateID ||
			delivery.version != 1 || delivery.subject != wantSubject || delivery.body != wantBody ||
			!strings.HasPrefix(delivery.dedupKey, "notification-v1-") {
			t.Fatalf("persisted delivery = %+v", delivery)
		}
	}
	for _, recipientID := range notice.RecipientIDs {
		requestID := announcementPublicationAuditRequestID(notice.AnnouncementID, notice.Version, recipientID)
		var count int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
			WHERE scope_id=$1 AND action='notification.event.enqueue' AND request_id=$2`, scopeID, requestID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("audit request %q count = %d", requestID, count)
		}
	}

	if err := enqueueAnnouncementNotice(t.Context(), pool, outbox, notice, true); err != nil {
		t.Fatalf("same payload replay = %v", err)
	}
	assertAnnouncementNotificationCounts(t, pool, scopeID, sourceEventID, 2, 2)
	conflict := notice
	conflict.Title = "不同公告"
	if err := enqueueAnnouncementNotice(t.Context(), pool, outbox, conflict, false); !errors.Is(err, notification.ErrEventConflict) ||
		!errors.Is(err, errAnnouncementNotificationEnqueueFailed) {
		t.Fatalf("different payload replay = %v", err)
	}
	assertAnnouncementNotificationCounts(t, pool, scopeID, sourceEventID, 2, 2)

	rolledBack := notice
	rolledBack.Version++
	rolledBack.InboxEventIDs = []uuid.UUID{uuid.New(), uuid.New()}
	if err := enqueueAnnouncementNotice(t.Context(), pool, outbox, rolledBack, false); err != nil {
		t.Fatalf("rollback enqueue = %v", err)
	}
	assertAnnouncementNotificationCounts(
		t,
		pool,
		scopeID,
		announcementPublicationSourceEventID(rolledBack.AnnouncementID, rolledBack.Version),
		0,
		0,
	)

	crossTenant := notice
	crossTenant.Version += 2
	crossTenant.RecipientIDs = []uuid.UUID{emailUserID, foreignUserID}
	crossTenant.InboxEventIDs = []uuid.UUID{uuid.New(), uuid.New()}
	if err := enqueueAnnouncementNotice(t.Context(), pool, outbox, crossTenant, false); !errors.Is(err, notification.ErrTenantScopeDenied) {
		t.Fatalf("cross-tenant enqueue = %v", err)
	}
	assertAnnouncementNotificationCounts(
		t,
		pool,
		scopeID,
		announcementPublicationSourceEventID(crossTenant.AnnouncementID, crossTenant.Version),
		0,
		0,
	)

	if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended'
		WHERE scope_id=$1 AND user_id=$2`, scopeID, emailUserID); err != nil {
		t.Fatal(err)
	}
	resolution := (&postgresMemberContactResolver{pool: pool}).Resolve(
		t.Context(), scopeID, emailUserID, notification.ChannelEmail,
	)
	if resolution.Contact != "" || resolution.Failure == nil ||
		resolution.Failure.Class != notification.FailurePermanent ||
		resolution.Failure.Code != "recipient_unavailable" {
		t.Fatalf("revoked member resolution = %+v", resolution)
	}

	if refs[notification.ChannelEmail].ID != announcementPublishedTemplateID ||
		refs[notification.ChannelSMS].ID != announcementPublishedTemplateID {
		t.Fatalf("template refs = %+v", refs)
	}
}

func TestAnnouncementNotificationPostgresSelectsV2AndCommitsMaximumEmailPublication(t *testing.T) {
	pool := openAnnouncementNotificationDatabase(t)
	store, err := notification.NewStoreWithClock(
		pool,
		audit.New(pool),
		func() time.Time { return announcementNotificationTestTime },
	)
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := newAnnouncementNotificationOutbox(store)
	if err != nil {
		t.Fatal(err)
	}
	for version, subject := range map[uint64]string{1: "[公告 v1] {{.title}}", 2: "[公告 v2] {{.title}}"} {
		if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{
			Ref: notification.TemplateRef{
				ID: announcementPublishedTemplateID, Version: version, Channel: notification.ChannelEmail,
			},
			Subject: subject, Body: "{{.body}}", Variables: []string{"title", "body"},
		}); err != nil {
			t.Fatalf("save template v%d: %v", version, err)
		}
	}
	if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref: notification.TemplateRef{
			ID: announcementPublishedTemplateID, Version: 1, Channel: notification.ChannelSMS,
		},
		Body: "{{.title}}\n{{.body}}", Variables: []string{"title", "body"},
	}); err != nil {
		t.Fatalf("save legacy SMS template: %v", err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	scopeID, userID := seedNotificationRuntimeMember(t, pool)
	if err := store.SetSubscription(
		t.Context(), scopeID, userID, announcementPublishedEventType,
		notification.Subscription{Email: true},
	); err != nil {
		t.Fatal(err)
	}

	notice := announcement.PublicationNotice{
		ScopeID: scopeID, AnnouncementID: uuid.New(), Version: 9,
		Title: "边界公告", Body: strings.Repeat("x", announcement.MaxBodyBytes),
		PublishedAt:  announcementNotificationTestTime,
		RecipientIDs: []uuid.UUID{userID}, InboxEventIDs: []uuid.UUID{uuid.New()},
	}
	if err := enqueueAnnouncementNotice(t.Context(), pool, outbox, notice, true); err != nil {
		t.Fatalf("maximum publication: %v", err)
	}
	sourceEventID := announcementPublicationSourceEventID(notice.AnnouncementID, notice.Version)
	ref := notification.TemplateRef{
		ID: announcementPublishedTemplateID, Version: 2, Channel: notification.ChannelEmail,
	}
	wantDedup, err := notification.DedupKey(notification.EventIdentity{
		TenantID: scopeID.String(), RecipientID: userID.String(), EventID: sourceEventID,
		EventType: announcementPublishedEventType,
	}, ref)
	if err != nil {
		t.Fatal(err)
	}
	var version uint64
	var subject, body, dedupKey string
	if err := pool.QueryRow(t.Context(), `
		SELECT outbox.template_version,outbox.subject,outbox.body,outbox.dedup_key
		FROM notification_events event
		JOIN notification_outbox outbox ON outbox.scope_id=event.scope_id AND outbox.event_id=event.id
		WHERE event.scope_id=$1 AND event.source_event_id=$2 AND event.event_type=$3`,
		scopeID, sourceEventID, announcementPublishedEventType,
	).Scan(&version, &subject, &body, &dedupKey); err != nil {
		t.Fatal(err)
	}
	if version != 2 || subject != "[公告 v2] "+notice.Title || body != notice.Body || dedupKey != wantDedup {
		t.Fatalf("persisted maximum delivery = version %d, subject %q, body bytes %d, dedup match %t",
			version, subject, len(body), dedupKey == wantDedup)
	}
	assertAnnouncementNotificationCounts(t, pool, scopeID, sourceEventID, 1, 1)
	requestID := announcementPublicationAuditRequestID(notice.AnnouncementID, notice.Version, userID)
	var auditCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action='notification.event.enqueue' AND request_id=$2`,
		scopeID, requestID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("maximum publication audit count = %d", auditCount)
	}

	if _, err := pool.Exec(t.Context(), `INSERT INTO notification_templates(
		template_id,version,channel,subject,body,variables,created_at
	) VALUES($1,3,'email',$2,$3,$4,$5)`, announcementPublishedTemplateID,
		`{{if eq .title "trigger"}}{{.body}}{{else}}{{.title}}{{end}}`, "{{.body}}",
		[]string{"title", "body"}, announcementNotificationTestTime); err != nil {
		t.Fatal(err)
	}
	poisoned := notice
	poisoned.Version++
	poisoned.Title = "trigger"
	poisoned.InboxEventIDs = []uuid.UUID{uuid.New()}
	err = enqueueAnnouncementNotice(t.Context(), pool, outbox, poisoned, true)
	if !errors.Is(err, notificationcontrol.ErrInvalidInput) ||
		!errors.Is(err, errAnnouncementNotificationEnqueueFailed) {
		t.Fatalf("poisoned highest template = %v", err)
	}
	poisonedSourceEventID := announcementPublicationSourceEventID(poisoned.AnnouncementID, poisoned.Version)
	assertAnnouncementNotificationCounts(t, pool, scopeID, poisonedSourceEventID, 0, 0)
	poisonedRequestID := announcementPublicationAuditRequestID(poisoned.AnnouncementID, poisoned.Version, userID)
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action='notification.event.enqueue' AND request_id=$2`,
		scopeID, poisonedRequestID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 0 {
		t.Fatalf("poisoned publication audit count = %d", auditCount)
	}
}

func TestAnnouncementNotificationPostgresSMTPTLS(t *testing.T) {
	pool := openAnnouncementNotificationDatabase(t)
	server := newSMTPTestServer(t, smtpTestServerConfig{})
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	refs := saveAnnouncementPublishedTemplates(t, store)
	recoveryTemplate := notification.TemplateRef{
		ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail,
	}
	if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref: recoveryTemplate, Subject: "账户通知", Body: "账户恢复", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	scopeID, userID := seedNotificationRuntimeMember(t, pool)
	if err := store.SetSubscription(
		t.Context(), scopeID, userID, announcementPublishedEventType,
		notification.Subscription{Email: true},
	); err != nil {
		t.Fatal(err)
	}

	config := notificationRuntimeConfig{
		Enabled: true,
		Worker: notification.WorkerConfig{
			BatchSize: 1, LeaseDuration: 2 * time.Second, LeaseSafetyMargin: 250 * time.Millisecond,
			MaxAttempts: 3, BaseDelay: 20 * time.Millisecond, MaxDelay: 100 * time.Millisecond,
		},
		RecoveryTemplates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelEmail: recoveryTemplate,
		},
		EmailProvider:    notificationEmailProviderSMTPTLS,
		SMTP:             server.clientConfig(),
		IdleWait:         5 * time.Millisecond,
		ErrorBackoffBase: 10 * time.Millisecond, ErrorBackoffMax: 50 * time.Millisecond,
		MaxConsecutiveFailures: 3, SendTimeout: time.Second,
		StartupTimeout: time.Second, ShutdownTimeout: time.Second,
	}
	runtime, err := openNotificationProcessRuntime(
		t.Context(), config, pool, notificationRuntimeDependencies{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	})
	outbox, err := newAnnouncementNotificationOutbox(store)
	if err != nil {
		t.Fatal(err)
	}
	body := "." + strings.Repeat("界", (announcement.MaxBodyBytes-1)/len("界"))
	if len(body) != announcement.MaxBodyBytes {
		t.Fatalf("test body bytes = %d", len(body))
	}
	notice := announcement.PublicationNotice{
		ScopeID: scopeID, AnnouncementID: uuid.New(), Version: 1,
		Title: "证书升级公告", Body: body, PublishedAt: time.Now().UTC(),
		RecipientIDs: []uuid.UUID{userID}, InboxEventIDs: []uuid.UUID{uuid.New()},
	}
	if err := enqueueAnnouncementNotice(t.Context(), pool, outbox, notice, true); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, 2*time.Second, func() bool { return len(server.messages()) == 1 })
	messages := server.messages()
	if len(messages) != 1 || !strings.Contains(messages[0], "Subject: =?UTF-8?q?") ||
		!strings.Contains(messages[0], "Content-Transfer-Encoding: quoted-printable\r\n") ||
		!strings.Contains(messages[0], "X-CDNCA-Idempotency-Key: notification-v1-") {
		t.Fatalf("announcement SMTP message contract = %q", messages)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(messages[0]))
	if err != nil {
		t.Fatal(err)
	}
	decodedBody := announcementPlainTextBody(t, parsed)
	// multipart 段尾的 CRLF 属于边界分隔符，单段时由 buildSMTPMessage 追加，比较时统一去掉
	if strings.TrimSuffix(string(decodedBody), "\r\n") != notice.Body {
		t.Fatalf("decoded announcement body bytes = %d, want %d", len(decodedBody), len(notice.Body))
	}
	var outboxID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT outbox.id FROM notification_outbox outbox
		JOIN notification_events event ON event.id=outbox.event_id
		WHERE event.scope_id=$1 AND event.source_event_id=$2 AND outbox.template_id=$3`,
		scopeID, announcementPublicationSourceEventID(notice.AnnouncementID, notice.Version),
		refs[notification.ChannelEmail].ID,
	).Scan(&outboxID); err != nil {
		t.Fatal(err)
	}
	waitForNotificationRuntimeAcceptance(t, pool, outboxID, 2*time.Second)
}

func saveAnnouncementPublishedTemplates(
	t *testing.T,
	store *notification.Store,
) map[notification.Channel]notification.TemplateRef {
	t.Helper()
	refs := announcementPublishedTemplates()
	definitions := []notification.TemplateDefinition{
		{
			Ref: refs[notification.ChannelEmail], Subject: "[公告] {{.title}}", Body: "{{.body}}",
			Variables: []string{"title", "body"},
		},
		{
			Ref: refs[notification.ChannelSMS], Body: "{{.title}}\n{{.body}}",
			Variables: []string{"title", "body"},
		},
	}
	for _, definition := range definitions {
		if err := store.SaveTemplate(t.Context(), definition); err != nil {
			t.Fatal(err)
		}
	}
	return refs
}

// announcementPlainTextBody 取邮件纯文本正文：PA-17 起有主题布局时为 multipart/alternative，
// multipart.Reader 会自动解 quoted-printable；无布局时是单段 quoted-printable。
func announcementPlainTextBody(t *testing.T, parsed *mail.Message) []byte {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	if mediaType != "multipart/alternative" {
		body, err := io.ReadAll(quotedprintable.NewReader(parsed.Body))
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	reader := multipart.NewReader(parsed.Body, params["boundary"])
	for {
		part, err := reader.NextPart()
		if err != nil {
			t.Fatalf("multipart message has no text/plain part: %v", err)
		}
		if strings.HasPrefix(part.Header.Get("Content-Type"), "text/plain") {
			body, err := io.ReadAll(part)
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
}

func openAnnouncementNotificationDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return openNotificationRuntimeDatabase(t)
}

func seedAnnouncementNotificationMember(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	suffix string,
) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	username := "announcement-notification-" + suffix + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash,email)
		VALUES($1,$2,'Announcement Notification Member','unused',$3)`,
		userID, username, suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
		scopeID, userID); err != nil {
		t.Fatal(err)
	}
	return userID
}

func enqueueAnnouncementNotice(
	ctx context.Context,
	pool *pgxpool.Pool,
	outbox *announcementNotificationOutbox,
	notice announcement.PublicationNotice,
	commit bool,
) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := outbox.EnqueuePublication(ctx, tx, notice); err != nil {
		return err
	}
	if !commit {
		return nil
	}
	return tx.Commit(ctx)
}

func assertAnnouncementNotificationCounts(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	sourceEventID string,
	wantEvents, wantOutbox int,
) {
	t.Helper()
	var events, outbox int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_events
		WHERE scope_id=$1 AND source_event_id=$2 AND event_type=$3`,
		scopeID, sourceEventID, announcementPublishedEventType).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_outbox outbox
		JOIN notification_events event ON event.id=outbox.event_id
		WHERE event.scope_id=$1 AND event.source_event_id=$2 AND event.event_type=$3`,
		scopeID, sourceEventID, announcementPublishedEventType).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if events != wantEvents || outbox != wantOutbox {
		t.Fatalf("notification counts events=%d outbox=%d, want %d/%d", events, outbox, wantEvents, wantOutbox)
	}
}
