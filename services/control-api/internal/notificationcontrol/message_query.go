package notificationcontrol

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const defaultMessageQueryLimit = 10

var messageTypePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)

// validMessageKeyword: a name / display-ID keyword, up to 128 bytes, trimmed,
// no control characters (fix-livefilter2).
func validMessageKeyword(value string) bool {
	return value == "" || len(value) <= 128 && value == strings.TrimSpace(value) &&
		strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

// Keyword matches (fix-livefilter2): an exact display ID, or a case-insensitive
// substring of the readable name. Placeholders are filled by the caller.
const (
	messageUserKeywordSQL = `($%[1]d::text='' OR EXISTS (SELECT 1 FROM users keyword_user WHERE keyword_user.id=%[2]s AND (
		keyword_user.display_id::text=$%[1]d OR position(lower($%[1]d) in lower(keyword_user.username))>0 OR
		position(lower($%[1]d) in lower(COALESCE(keyword_user.display_name,'')))>0)))`
	messagePackageKeywordSQL = `($%[1]d::text='' OR EXISTS (SELECT 1 FROM package_subscriptions keyword_package
		JOIN package_subscription_display_ids keyword_package_display ON keyword_package_display.subscription_id=keyword_package.id
		WHERE keyword_package.id=%[2]s AND (keyword_package_display.display_id::text=$%[1]d OR
		position(lower($%[1]d) in lower(COALESCE(keyword_package.product_snapshot->>'name','')))>0)))`
	messageSiteKeywordSQL = `($%[1]d::text='' OR EXISTS (SELECT 1 FROM sites keyword_site WHERE keyword_site.id=%[2]s AND (
		keyword_site.display_id::text=$%[1]d OR position(lower($%[1]d) in lower(keyword_site.domain))>0)))`
)

type normalizedMessageQuery struct {
	ScopeID             *uuid.UUID
	Type                string
	UserID              *uuid.UUID
	PackageID           string
	SiteID              string
	User, Package, Site string
	Limit               int
	Cursor              *uuid.UUID
}

func normalizeMessageQuery(raw MessageQuery) (normalizedMessageQuery, error) {
	if raw.Invalid {
		return normalizedMessageQuery{}, ErrInvalidInput
	}
	result := normalizedMessageQuery{Type: raw.Type, Limit: defaultMessageQueryLimit}
	if raw.ScopeID != "" {
		value, err := uuid.Parse(raw.ScopeID)
		if err != nil || value == uuid.Nil || value.String() != raw.ScopeID {
			return normalizedMessageQuery{}, ErrInvalidInput
		}
		result.ScopeID = &value
	}
	if raw.Type != "" && !messageTypePattern.MatchString(raw.Type) {
		return normalizedMessageQuery{}, ErrInvalidInput
	}
	if raw.UserID != "" {
		value, err := uuid.Parse(raw.UserID)
		if err != nil || value == uuid.Nil || value.String() != raw.UserID {
			return normalizedMessageQuery{}, ErrInvalidInput
		}
		result.UserID = &value
	}
	for _, value := range []string{raw.PackageID, raw.SiteID} {
		if value != "" && (len(value) > 128 || value != strings.TrimSpace(value) || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0) {
			return normalizedMessageQuery{}, ErrInvalidInput
		}
	}
	result.PackageID, result.SiteID = raw.PackageID, raw.SiteID
	if !validMessageKeyword(raw.User) || !validMessageKeyword(raw.Package) || !validMessageKeyword(raw.Site) {
		return normalizedMessageQuery{}, ErrInvalidInput
	}
	result.User, result.Package, result.Site = raw.User, raw.Package, raw.Site
	if raw.Limit != "" {
		value, err := strconv.Atoi(raw.Limit)
		if err != nil || value < 1 || value > 300 || strconv.Itoa(value) != raw.Limit {
			return normalizedMessageQuery{}, ErrInvalidInput
		}
		result.Limit = value
	}
	if raw.Cursor != "" {
		value, err := uuid.Parse(raw.Cursor)
		if err != nil || value == uuid.Nil || value.String() != raw.Cursor {
			return normalizedMessageQuery{}, ErrInvalidInput
		}
		result.Cursor = &value
	}
	return result, nil
}

var messageQueryCandidatesSQL = `WITH message_candidates AS (
	SELECT event.id,event.scope_id,event.recipient_user_id,event.event_type,event.created_at,
	       COALESCE(event.subject_package_id,fact.subscription_id)::text AS package_id,
	       event.subject_site_id::text AS site_id
	FROM notification_events event
	LEFT JOIN package_monitor_transition_facts fact
	  ON fact.tenant_scope_id=event.scope_id AND fact.notification_event_id=event.id
	 AND fact.owner_user_id=event.recipient_user_id AND fact.source_event_id=event.source_event_id
	 AND fact.notification_event_type=event.event_type
	WHERE event.recipient_kind='member'
	  AND ($1::uuid IS NULL OR event.scope_id=$1)
	  AND ($2::text='' OR event.event_type=$2)
	  AND ($3::uuid IS NULL OR event.recipient_user_id=$3)
	  AND ($4::text='' OR COALESCE(event.subject_package_id,fact.subscription_id)::text=$4)
	  AND ($5::text='' OR event.subject_site_id::text=$5)
	  AND ` + fmt.Sprintf(messageUserKeywordSQL, 6, "event.recipient_user_id") + `
	  AND ` + fmt.Sprintf(messagePackageKeywordSQL, 7, "COALESCE(event.subject_package_id,fact.subscription_id)") + `
	  AND ` + fmt.Sprintf(messageSiteKeywordSQL, 8, "event.subject_site_id") + `
) `

// ListMessages returns one event-centric row per member notification. Site and
// package come from the event-time subject columns (migration 502; package
// falls back to immutable monitor facts for older rows) and are never inferred
// from current bindings. Channel title/content and delivery state come from
// the original (generation 1) outbox row; no row means nothing was generated
// for that channel, which is reported as null rather than a failure.
// Readable names (recipient user, site domain, package name) are the current
// values of those objects so operators can tell who/what a row is about; they
// are null when the object no longer exists.
func (s *Store) ListMessages(ctx context.Context, actor Actor, raw MessageQuery) (MessagePage, error) {
	page := MessagePage{Schema: "cdnca.notification-message-query/v1", Items: []Message{}}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRead(ctx, tx, actor, permissionRead, s.now()); err != nil {
			return err
		}
		query, err := normalizeMessageQuery(raw)
		if err != nil {
			return err
		}
		var scope, user any
		if query.ScopeID != nil {
			scope = *query.ScopeID
		}
		if query.UserID != nil {
			user = *query.UserID
		}
		arguments := []any{scope, query.Type, user, query.PackageID, query.SiteID, query.User, query.Package, query.Site}
		var cursorAt, cursorID any
		if query.Cursor != nil {
			var createdAt time.Time
			if err := tx.QueryRow(ctx, messageQueryCandidatesSQL+
				`SELECT created_at FROM message_candidates WHERE id=$9`,
				append(arguments, *query.Cursor)...).Scan(&createdAt); errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidInput
			} else if err != nil {
				return err
			}
			cursorAt, cursorID = createdAt, *query.Cursor
		}
		if err := tx.QueryRow(ctx, messageQueryCandidatesSQL+`SELECT count(*) FROM message_candidates`,
			arguments...).Scan(&page.Total); err != nil {
			return err
		}

		rows, err := tx.Query(ctx, messageQueryCandidatesSQL+`SELECT event.id,event.recipient_user_id,event.event_type,
			event.created_at,email.subject,event.package_id,event.site_id,email.body,sms.body,
			CASE WHEN email.id IS NOT NULL THEN COALESCE(email_settlement.state,'pending') END,
			CASE WHEN sms.id IS NOT NULL THEN COALESCE(sms_settlement.state,'pending') END,
			recipient.display_id,recipient.username,recipient.display_name,site.domain,
			subscription.product_snapshot->>'name'
			FROM message_candidates event
			LEFT JOIN users recipient ON recipient.id=event.recipient_user_id
			LEFT JOIN sites site ON site.id::text=event.site_id
			LEFT JOIN package_subscriptions subscription ON subscription.id::text=event.package_id
			LEFT JOIN notification_outbox email
			  ON email.scope_id=event.scope_id AND email.event_id=event.id
			 AND email.channel='email' AND email.generation=1
			LEFT JOIN notification_delivery_settlements_108 email_settlement ON email_settlement.outbox_id=email.id
			LEFT JOIN notification_outbox sms
			  ON sms.scope_id=event.scope_id AND sms.event_id=event.id
			 AND sms.channel='sms' AND sms.generation=1
			LEFT JOIN notification_delivery_settlements_108 sms_settlement ON sms_settlement.outbox_id=sms.id
			WHERE ($9::timestamptz IS NULL OR (event.created_at,event.id)<($9,$10::uuid))
			ORDER BY event.created_at DESC,event.id DESC LIMIT $11`,
			append(arguments, cursorAt, cursorID, query.Limit+1)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item Message
			if err := rows.Scan(&item.ID, &item.UserID, &item.Type, &item.CreatedAt,
				&item.Title, &item.PackageID, &item.SiteID, &item.EmailContent, &item.SMSContent,
				&item.EmailState, &item.SMSState, &item.UserDisplayID, &item.Username, &item.UserDisplayName,
				&item.SiteDomain, &item.PackageName); err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Items) > query.Limit {
			page.Items = page.Items[:query.Limit]
			page.NextCursor = page.Items[len(page.Items)-1].ID.String()
		}
		return nil
	})
	if err != nil {
		return MessagePage{}, fmt.Errorf("list notification messages: %w", err)
	}
	return page, nil
}
