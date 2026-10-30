package notificationcontrol

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// OwnMessageQuery is the caller's own event-message list (SEC-ACCOUNT-07).
// Scope and recipient always come from the session, never from the query.
type OwnMessageQuery struct {
	Type      string
	SiteID    string
	PackageID string
	// Site and Package match by domain/name or exact display ID (fix-livefilter2).
	Site, Package string
	Limit         string
	Offset        string
	Invalid       bool
}

type OwnMessage struct {
	ID        uuid.UUID  `json:"id"`
	Type      string     `json:"type"`
	Title     *string    `json:"title"`
	SiteID    *uuid.UUID `json:"site_id"`
	PackageID *uuid.UUID `json:"package_id"`
	CreatedAt time.Time  `json:"created_at"`
	Content   *string    `json:"content"`
}

type OwnMessagePage struct {
	Schema string       `json:"schema"`
	Items  []OwnMessage `json:"items"`
	Total  int64        `json:"total"`
}

type normalizedOwnMessageQuery struct {
	Type              string
	SiteID, PackageID *uuid.UUID
	Site, Package     string
	Limit, Offset     int
}

const (
	maxOwnMessageLimit  = 100
	maxOwnMessageOffset = 10000
)

func normalizeOwnMessageQuery(raw OwnMessageQuery) (normalizedOwnMessageQuery, error) {
	result := normalizedOwnMessageQuery{Type: raw.Type, Limit: defaultMessageQueryLimit}
	if raw.Invalid || raw.Type != "" && !messageTypePattern.MatchString(raw.Type) ||
		!validMessageKeyword(raw.Site) || !validMessageKeyword(raw.Package) {
		return normalizedOwnMessageQuery{}, ErrInvalidInput
	}
	result.Site, result.Package = raw.Site, raw.Package
	for _, item := range []struct {
		raw    string
		target **uuid.UUID
	}{{raw.SiteID, &result.SiteID}, {raw.PackageID, &result.PackageID}} {
		if item.raw == "" {
			continue
		}
		value, err := uuid.Parse(item.raw)
		if err != nil || value == uuid.Nil || value.String() != item.raw {
			return normalizedOwnMessageQuery{}, ErrInvalidInput
		}
		*item.target = &value
	}
	for _, item := range []struct {
		raw      string
		min, max int
		target   *int
	}{{raw.Limit, 1, maxOwnMessageLimit, &result.Limit}, {raw.Offset, 0, maxOwnMessageOffset, &result.Offset}} {
		if item.raw == "" {
			continue
		}
		value, err := strconv.Atoi(item.raw)
		if err != nil || value < item.min || value > item.max || strconv.Itoa(value) != item.raw {
			return normalizedOwnMessageQuery{}, ErrInvalidInput
		}
		*item.target = value
	}
	return result, nil
}

// Only subscribable operational events are messages. System-required events
// (verification codes, invitations) and announcements (own inbox) are not.
// The package ID falls back to the immutable monitor fact for rows written
// before migration 502; the site ID is never inferred from current bindings.
var ownMessageCandidatesSQL = `WITH own_messages AS (
	SELECT event.id,event.scope_id,event.event_type,event.created_at,event.subject_site_id,
	       COALESCE(event.subject_package_id,fact.subscription_id) AS package_id
	FROM notification_events event
	LEFT JOIN package_monitor_transition_facts fact
	  ON fact.tenant_scope_id=event.scope_id AND fact.notification_event_id=event.id
	 AND fact.owner_user_id=event.recipient_user_id AND fact.source_event_id=event.source_event_id
	 AND fact.notification_event_type=event.event_type
	WHERE event.scope_id=$1 AND event.recipient_user_id=$2 AND event.recipient_kind='member'
	  AND event.delivery_policy='tenant_subscribed' AND event.event_type<>'announcement.published'
	  AND ($3::text='' OR event.event_type=$3)
	  AND ($4::uuid IS NULL OR event.subject_site_id=$4)
	  AND ($5::uuid IS NULL OR COALESCE(event.subject_package_id,fact.subscription_id)=$5)
	  AND ` + fmt.Sprintf(messageSiteKeywordSQL, 6, "event.subject_site_id") + `
	  AND ` + fmt.Sprintf(messagePackageKeywordSQL, 7, "COALESCE(event.subject_package_id,fact.subscription_id)") + `
) `

func (s *Store) ListOwnMessages(ctx context.Context, actor Actor, raw OwnMessageQuery) (OwnMessagePage, error) {
	page := OwnMessagePage{Schema: "cdnca.notification-own-messages/v1", Items: []OwnMessage{}}
	query, err := normalizeOwnMessageQuery(raw)
	if err != nil {
		return OwnMessagePage{}, err
	}
	permissionDenied := false
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if authErr := authorizeRead(ctx, tx, actor, "", s.now()); authErr != nil {
			if !errors.Is(authErr, ErrPermissionDenied) {
				return authErr
			}
			permissionDenied = true
			return nil
		}
		if !selfSubscriptionScope(actor) {
			permissionDenied = true
			return nil
		}
		var site, pkg any
		if query.SiteID != nil {
			site = *query.SiteID
		}
		if query.PackageID != nil {
			pkg = *query.PackageID
		}
		arguments := []any{actor.ScopeID, actor.UserID, query.Type, site, pkg, query.Site, query.Package}
		if err := tx.QueryRow(ctx, ownMessageCandidatesSQL+`SELECT count(*) FROM own_messages`,
			arguments...).Scan(&page.Total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, ownMessageCandidatesSQL+`SELECT message.id,message.event_type,message.created_at,
			email.subject,message.subject_site_id,message.package_id,COALESCE(email.body,sms.body)
			FROM own_messages message
			LEFT JOIN notification_outbox email
			  ON email.scope_id=message.scope_id AND email.event_id=message.id
			 AND email.channel='email' AND email.generation=1
			LEFT JOIN notification_outbox sms
			  ON sms.scope_id=message.scope_id AND sms.event_id=message.id
			 AND sms.channel='sms' AND sms.generation=1
			ORDER BY message.created_at DESC,message.id DESC LIMIT $8 OFFSET $9`,
			append(arguments, query.Limit, query.Offset)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item OwnMessage
			if err := rows.Scan(&item.ID, &item.Type, &item.CreatedAt, &item.Title,
				&item.SiteID, &item.PackageID, &item.Content); err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return OwnMessagePage{}, fmt.Errorf("list own notification messages: %w", err)
	}
	if permissionDenied {
		return OwnMessagePage{}, ErrPermissionDenied
	}
	return page, nil
}
