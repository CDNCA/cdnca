package announcement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ListGlobalAnnouncements(ctx context.Context, actor Actor, request AnnouncementListRequest) (GlobalAnnouncementPage, error) {
	if request.Limit == 0 {
		request.Limit = DefaultPageSize
	}
	if request.Limit < 1 || request.Limit > MaxPageSize || !validGlobalStatus(request.Status) {
		return GlobalAnnouncementPage{}, ErrInvalidInput
	}
	filter := "global-snapshot:" + normalizeStatusFilter(request.Status)
	var cursor *announcementCursor
	if request.Cursor != "" {
		decoded, err := decodeAnnouncementCursor(s.cursorKeys, request.Cursor)
		if err != nil || decoded.ScopeID != actor.ScopeID || decoded.UserID != actor.UserID || decoded.Filter != filter {
			return GlobalAnnouncementPage{}, ErrInvalidCursor
		}
		cursor = &decoded
	}
	var result GlobalAnnouncementPage
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := s.authorizeGlobalManage(ctx, tx, actor); err != nil {
			return err
		}
		watermark, err := announcementStateWatermark(ctx, tx, actor.ScopeID)
		if err != nil {
			return err
		}
		if cursor != nil {
			watermark = cursor.Watermark
		}
		query := `WITH snapshot AS (
			SELECT DISTINCT ON (announcement_id) payload FROM platform_announcement_snapshots_255
			WHERE platform_scope_id=$1 AND watermark <= $2 ORDER BY announcement_id,watermark DESC
		) SELECT payload FROM snapshot WHERE (payload->>'archived')::boolean=$3`
		args := []any{actor.ScopeID, watermark, request.Status == StatusArchived}
		if request.Status != "" && request.Status != StatusArchived {
			args = append(args, request.Status)
			query += fmt.Sprintf(" AND payload->>'status'=$%d", len(args))
		}
		if cursor != nil {
			args = append(args, cursor.CreatedAt, cursor.ID)
			query += fmt.Sprintf(" AND ((payload->>'created_at')::timestamptz,(payload->>'id')::uuid) < ($%d,$%d)", len(args)-1, len(args))
		}
		args = append(args, request.Limit+1)
		query += fmt.Sprintf(" ORDER BY (payload->>'created_at')::timestamptz DESC,(payload->>'id')::uuid DESC LIMIT $%d", len(args))
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var payload []byte
			if err := rows.Scan(&payload); err != nil {
				return err
			}
			var item GlobalAnnouncement
			if err := json.Unmarshal(payload, &item); err != nil {
				return err
			}
			result.Items = append(result.Items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		result.Items, result.NextCursor, err = boundedSnapshotItems(result.Items, request.Limit, func(last GlobalAnnouncement) string {
			return encodeAnnouncementCursor(s.cursorKeys, announcementCursor{
				ScopeID: actor.ScopeID, UserID: actor.UserID, Filter: filter, Watermark: watermark, CreatedAt: last.CreatedAt, ID: last.ID,
			})
		})
		return err
	})
	if err != nil {
		return GlobalAnnouncementPage{}, fmt.Errorf("list global announcements: %w", err)
	}
	return result, nil
}

func (s *Store) GetGlobalAnnouncement(ctx context.Context, actor Actor, id uuid.UUID) (GlobalAnnouncement, error) {
	if id == uuid.Nil {
		return GlobalAnnouncement{}, ErrInvalidInput
	}
	var result GlobalAnnouncement
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeGlobalManage(ctx, tx, actor); err != nil {
			return err
		}
		var err error
		result, err = loadGlobalAnnouncement(ctx, tx, actor.ScopeID, id, false)
		return err
	})
	if err != nil {
		return GlobalAnnouncement{}, fmt.Errorf("get global announcement: %w", err)
	}
	return result, nil
}

func (s *Store) CreateGlobalDraft(ctx context.Context, actor Actor, request CreateGlobalDraftRequest) (GlobalAnnouncement, error) {
	if request.Format == "" {
		request.Format, request.SortOrder, request.Visible = FormatContent, 100, true
	}
	if err := validateGlobalDraftInput(request.Content, request.Presentation, request.Audience, request.WithdrawalVisibility, request.IdempotencyKey, request.RequestID); err != nil {
		return GlobalAnnouncement{}, err
	}
	request.Audience = canonicalGlobalAudience(request.Audience)
	digest, err := requestDigest(request)
	if err != nil {
		return GlobalAnnouncement{}, err
	}
	var result GlobalAnnouncement
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeGlobalManage(ctx, tx, actor); err != nil {
			return err
		}
		replay, found, err := s.claimWrite(ctx, tx, actor, operationGlobalCreate, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			return decodeGlobalReplay(replay, &result)
		}
		if err := validateGlobalTargets(ctx, tx, request.Audience); err != nil {
			return err
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		now := storeTime(s.now())
		audience, err := json.Marshal(request.Audience)
		if err != nil {
			return ErrInvalidAudience
		}
		_, err = tx.Exec(ctx, `INSERT INTO platform_announcements_141(
			id,platform_scope_id,version,revision,status,title,body,content_format,link_url,sort_order,
			is_visible,is_popup,style_red,style_bold,audience,withdrawal_visibility,
			created_by_user_id,created_at,updated_at
		) VALUES($1,$2,1,1,'draft',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)`, id, actor.ScopeID, request.Title,
			request.Body, request.Format, nullableLinkURL(request.LinkURL), request.SortOrder,
			request.Visible, request.Popup, request.Red, request.Bold, audience, request.WithdrawalVisibility, actor.UserID, now)
		if err != nil {
			return err
		}
		result, err = loadGlobalAnnouncement(ctx, tx, actor.ScopeID, id, false)
		if err != nil {
			return err
		}
		if err := s.appendGlobalAudit(ctx, tx, actor, result, request.RequestID, operationGlobalCreate); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operationGlobalCreate, request.IdempotencyKey, result)
	})
	if err != nil {
		return GlobalAnnouncement{}, fmt.Errorf("create global announcement: %w", err)
	}
	return result, nil
}

func (s *Store) UpdateGlobalDraft(ctx context.Context, actor Actor, request UpdateGlobalDraftRequest) (GlobalAnnouncement, error) {
	if request.AnnouncementID == uuid.Nil || request.ExpectedRevision < 1 {
		return GlobalAnnouncement{}, ErrInvalidInput
	}
	if request.Format == "" {
		request.Format, request.SortOrder, request.Visible = FormatContent, 100, true
	}
	if err := validateGlobalDraftInput(request.Content, request.Presentation, request.Audience, request.WithdrawalVisibility, request.IdempotencyKey, request.RequestID); err != nil {
		return GlobalAnnouncement{}, err
	}
	request.Audience = canonicalGlobalAudience(request.Audience)
	digest, err := requestDigest(request)
	if err != nil {
		return GlobalAnnouncement{}, err
	}
	var result GlobalAnnouncement
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeGlobalManage(ctx, tx, actor); err != nil {
			return err
		}
		replay, found, err := s.claimWrite(ctx, tx, actor, operationGlobalUpdate, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			return decodeGlobalReplay(replay, &result)
		}
		current, err := loadGlobalAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, true)
		if err != nil {
			return err
		}
		if current.Status != StatusDraft || current.Archived {
			return ErrInvalidTransition
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if err := validateGlobalTargets(ctx, tx, request.Audience); err != nil {
			return err
		}
		audience, err := json.Marshal(request.Audience)
		if err != nil {
			return ErrInvalidAudience
		}
		now := storeTime(s.now())
		command, err := tx.Exec(ctx, `UPDATE platform_announcements_141 SET
			title=$3,body=$4,content_format=$5,link_url=$6,sort_order=$7,is_visible=$8,is_popup=$9,
			style_red=$10,style_bold=$11,audience=$12,withdrawal_visibility=$13,revision=revision+1,updated_at=$14
			WHERE id=$1 AND platform_scope_id=$2 AND status='draft' AND revision=$15`, request.AnnouncementID,
			actor.ScopeID, request.Title, request.Body, request.Format, nullableLinkURL(request.LinkURL), request.SortOrder,
			request.Visible, request.Popup, request.Red, request.Bold, audience, request.WithdrawalVisibility, now, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result, err = loadGlobalAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, false)
		if err != nil {
			return err
		}
		if err := s.appendGlobalAudit(ctx, tx, actor, result, request.RequestID, operationGlobalUpdate); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operationGlobalUpdate, request.IdempotencyKey, result)
	})
	if err != nil {
		return GlobalAnnouncement{}, fmt.Errorf("update global announcement: %w", err)
	}
	return result, nil
}

func (s *Store) PublishGlobal(ctx context.Context, actor Actor, request GlobalTransitionRequest) (GlobalAnnouncement, error) {
	return s.transitionGlobal(ctx, actor, request, true)
}

func (s *Store) WithdrawGlobal(ctx context.Context, actor Actor, request GlobalTransitionRequest) (GlobalAnnouncement, error) {
	return s.transitionGlobal(ctx, actor, request, false)
}

func (s *Store) transitionGlobal(ctx context.Context, actor Actor, request GlobalTransitionRequest, publish bool) (GlobalAnnouncement, error) {
	if request.AnnouncementID == uuid.Nil || request.ExpectedRevision < 1 || !validMeta(request.IdempotencyKey, request.RequestID) {
		return GlobalAnnouncement{}, ErrInvalidInput
	}
	operation := operationGlobalWithdraw
	if publish {
		operation = operationGlobalPublish
	}
	digest, err := requestDigest(request)
	if err != nil {
		return GlobalAnnouncement{}, err
	}
	var result GlobalAnnouncement
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeGlobalManage(ctx, tx, actor); err != nil {
			return err
		}
		replay, found, err := s.claimWrite(ctx, tx, actor, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			return decodeGlobalReplay(replay, &result)
		}
		current, err := loadGlobalAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, true)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		now := storeTime(s.now())
		if publish {
			if current.Status != StatusDraft || current.Archived {
				return ErrInvalidTransition
			}
			recipients, err := resolveGlobalRecipients(ctx, tx, current.Audience)
			if err != nil {
				return err
			}
			if len(recipients) == 0 {
				return ErrEmptyAudience
			}
			grouped := make(map[uuid.UUID]PublicationNotice)
			for _, recipient := range recipients {
				eventID, err := uuid.NewV7()
				if err != nil {
					return err
				}
				_, err = tx.Exec(ctx, `INSERT INTO platform_announcement_recipients_141(
					announcement_id,tenant_scope_id,user_id,event_id,revision,published_at,updated_at
				) VALUES($1,$2,$3,$4,1,$5,$5)`, current.ID, recipient.ScopeID, recipient.UserID, eventID, now)
				if err != nil {
					return err
				}
				notice := grouped[recipient.ScopeID]
				notice.ScopeID, notice.AnnouncementID, notice.Version = recipient.ScopeID, current.ID, current.Version
				notice.Title, notice.Body, notice.PublishedAt = current.Title, current.Body, now
				if current.Format == FormatLink {
					notice.Body = current.LinkURL
				}
				notice.RecipientIDs = append(notice.RecipientIDs, recipient.UserID)
				notice.InboxEventIDs = append(notice.InboxEventIDs, eventID)
				grouped[recipient.ScopeID] = notice
			}
			for _, notice := range grouped {
				if err := s.outbox.EnqueuePublication(ctx, tx, notice); err != nil {
					return fmt.Errorf("enqueue global announcement publication: %w", err)
				}
			}
			command, err := tx.Exec(ctx, `UPDATE platform_announcements_141 SET
				status='published',published_at=$3,revision=revision+1,updated_at=$3
				WHERE id=$1 AND platform_scope_id=$2 AND status='draft' AND revision=$4`,
				current.ID, actor.ScopeID, now, request.ExpectedRevision)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrRevisionConflict
			}
		} else {
			if current.Status != StatusPublished {
				return ErrInvalidTransition
			}
			command, err := tx.Exec(ctx, `UPDATE platform_announcements_141 SET
				status='withdrawn',withdrawn_at=$3,revision=revision+1,updated_at=$3
				WHERE id=$1 AND platform_scope_id=$2 AND status='published' AND revision=$4`,
				current.ID, actor.ScopeID, now, request.ExpectedRevision)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrRevisionConflict
			}
		}
		result, err = loadGlobalAnnouncement(ctx, tx, actor.ScopeID, current.ID, false)
		if err != nil {
			return err
		}
		if err := s.appendGlobalAudit(ctx, tx, actor, result, request.RequestID, operation); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operation, request.IdempotencyKey, result)
	})
	if err != nil {
		return GlobalAnnouncement{}, fmt.Errorf("transition global announcement: %w", err)
	}
	return result, nil
}

type globalRecipient struct {
	ScopeID uuid.UUID
	UserID  uuid.UUID
}

func resolveGlobalRecipients(ctx context.Context, tx pgx.Tx, audience GlobalAudience) ([]globalRecipient, error) {
	tenantIDs, roleScopeIDs, roleIDs, userScopeIDs, userIDs := globalTargetArrays(audience)
	rows, err := tx.Query(ctx, `WITH requested AS (
		SELECT membership.scope_id,membership.user_id
		FROM memberships membership
		JOIN access_scopes scope ON scope.id=membership.scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN users account ON account.id=membership.user_id AND account.status='active'
		WHERE $1 AND membership.status='active'
		UNION
		SELECT membership.scope_id,membership.user_id
		FROM memberships membership
		JOIN access_scopes scope ON scope.id=membership.scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN users account ON account.id=membership.user_id AND account.status='active'
		WHERE NOT $1 AND membership.status='active' AND membership.scope_id=ANY($2)
		UNION
		SELECT assignment.scope_id,assignment.user_id
		FROM unnest($3::uuid[],$4::uuid[]) target(scope_id,role_id)
		JOIN role_assignments assignment ON assignment.scope_id=target.scope_id AND assignment.role_id=target.role_id
		JOIN memberships membership ON membership.scope_id=assignment.scope_id AND membership.user_id=assignment.user_id AND membership.status='active'
		JOIN access_scopes scope ON scope.id=assignment.scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN users account ON account.id=assignment.user_id AND account.status='active'
		WHERE NOT $1
		UNION
		SELECT target.scope_id,target.user_id
		FROM unnest($5::uuid[],$6::uuid[]) target(scope_id,user_id)
		JOIN memberships membership ON membership.scope_id=target.scope_id AND membership.user_id=target.user_id AND membership.status='active'
		JOIN access_scopes scope ON scope.id=target.scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN users account ON account.id=target.user_id AND account.status='active'
		WHERE NOT $1
	) SELECT scope_id,user_id FROM requested ORDER BY scope_id,user_id`, audience.AllTenants,
		tenantIDs, roleScopeIDs, roleIDs, userScopeIDs, userIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []globalRecipient
	for rows.Next() {
		var recipient globalRecipient
		if err := rows.Scan(&recipient.ScopeID, &recipient.UserID); err != nil {
			return nil, err
		}
		result = append(result, recipient)
	}
	return result, rows.Err()
}

func validateGlobalTargets(ctx context.Context, tx pgx.Tx, audience GlobalAudience) error {
	if audience.AllTenants {
		return nil
	}
	tenantIDs, roleScopeIDs, roleIDs, userScopeIDs, userIDs := globalTargetArrays(audience)
	var tenants, roles, users int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM access_scopes scope JOIN tenants tenant ON tenant.id=scope.tenant_id
		WHERE scope.kind='tenant' AND scope.id=ANY($1)`, tenantIDs).Scan(&tenants); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM unnest($1::uuid[],$2::uuid[]) target(scope_id,role_id)
		JOIN roles role ON role.scope_id=target.scope_id AND role.id=target.role_id
		JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='tenant'`, roleScopeIDs, roleIDs).Scan(&roles); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM unnest($1::uuid[],$2::uuid[]) target(scope_id,user_id)
		JOIN memberships membership ON membership.scope_id=target.scope_id AND membership.user_id=target.user_id
		JOIN access_scopes scope ON scope.id=membership.scope_id AND scope.kind='tenant'`, userScopeIDs, userIDs).Scan(&users); err != nil {
		return err
	}
	if tenants != len(tenantIDs) || roles != len(roleIDs) || users != len(userIDs) {
		return ErrAudienceScopeDenied
	}
	return nil
}

func globalTargetArrays(audience GlobalAudience) ([]uuid.UUID, []uuid.UUID, []uuid.UUID, []uuid.UUID, []uuid.UUID) {
	roleScopes, roleIDs := make([]uuid.UUID, 0, len(audience.RoleTargets)), make([]uuid.UUID, 0, len(audience.RoleTargets))
	for _, target := range audience.RoleTargets {
		roleScopes, roleIDs = append(roleScopes, target.ScopeID), append(roleIDs, target.RoleID)
	}
	userScopes, userIDs := make([]uuid.UUID, 0, len(audience.UserTargets)), make([]uuid.UUID, 0, len(audience.UserTargets))
	for _, target := range audience.UserTargets {
		userScopes, userIDs = append(userScopes, target.ScopeID), append(userIDs, target.UserID)
	}
	return audience.TenantScopeIDs, roleScopes, roleIDs, userScopes, userIDs
}

func loadGlobalAnnouncement(ctx context.Context, tx pgx.Tx, platformScopeID, id uuid.UUID, lock bool) (GlobalAnnouncement, error) {
	query := `SELECT item.id,item.platform_scope_id,item.version,item.revision,item.status,item.title,item.body,
		item.content_format,item.link_url,item.sort_order,item.is_visible,item.is_popup,item.style_red,item.style_bold,item.audience,
		item.withdrawal_visibility,(SELECT count(*) FROM platform_announcement_recipients_141 recipient WHERE recipient.announcement_id=item.id),
		item.published_at,item.withdrawn_at,item.created_at,greatest(item.updated_at,archive.changed_at),
		archive.archived,archive.revision,archive.archived_at
		FROM platform_announcements_141 item JOIN platform_announcement_archive_255 archive
		ON archive.platform_scope_id=item.platform_scope_id AND archive.announcement_id=item.id
		WHERE item.platform_scope_id=$1 AND item.id=$2`
	if lock {
		query += " FOR UPDATE OF item,archive"
	}
	item, err := scanGlobalAnnouncement(tx.QueryRow(ctx, query, platformScopeID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return GlobalAnnouncement{}, ErrNotFound
	}
	return item, err
}

func scanGlobalAnnouncement(row interface{ Scan(...any) error }) (GlobalAnnouncement, error) {
	var item GlobalAnnouncement
	var audience []byte
	var linkURL *string
	err := row.Scan(&item.ID, &item.PlatformScopeID, &item.Version, &item.Revision, &item.Status,
		&item.Title, &item.Body, &item.Format, &linkURL, &item.SortOrder, &item.Visible, &item.Popup, &item.Red, &item.Bold,
		&audience, &item.WithdrawalVisibility, &item.RecipientCount,
		&item.PublishedAt, &item.WithdrawnAt, &item.CreatedAt, &item.StateChangedAt,
		&item.Archived, &item.LifecycleRevision, &item.ArchivedAt)
	if err != nil {
		return GlobalAnnouncement{}, err
	}
	if err := json.Unmarshal(audience, &item.Audience); err != nil {
		return GlobalAnnouncement{}, err
	}
	if linkURL != nil {
		item.LinkURL = *linkURL
	}
	item.Audience = canonicalGlobalAudience(item.Audience)
	return item, nil
}

func (s *Store) authorizeGlobalManage(ctx context.Context, tx pgx.Tx, actor Actor) error {
	if actor.ScopeID == uuid.Nil || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil {
		return ErrPermissionDenied
	}
	var kind, accountStatus, membershipStatus string
	var revokedAt *time.Time
	var expiresAt time.Time
	var granted bool
	err := tx.QueryRow(ctx, `SELECT scope.kind,account.status,membership.status,session_row.revoked_at,session_row.expires_at,
		EXISTS(SELECT 1 FROM role_assignments assignment
			JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
			JOIN role_permissions permission ON permission.role_id=role.id
			WHERE assignment.scope_id=$1 AND assignment.user_id=$2
			  AND permission.permission_name IN ('announcements.manage','platform.admin'))
		FROM auth_sessions session_row
		JOIN access_scopes scope ON scope.id=session_row.scope_id
		JOIN users account ON account.id=session_row.user_id
		JOIN memberships membership ON membership.scope_id=session_row.scope_id AND membership.user_id=session_row.user_id
		WHERE session_row.id=$3 AND session_row.scope_id=$1 AND session_row.user_id=$2
		FOR UPDATE OF session_row,account,membership`, actor.ScopeID, actor.UserID, actor.SessionID).
		Scan(&kind, &accountStatus, &membershipStatus, &revokedAt, &expiresAt, &granted)
	if err != nil || kind != "platform" || accountStatus != "active" || membershipStatus != "active" ||
		revokedAt != nil || !storeTime(s.now()).Before(expiresAt) || !granted {
		return ErrPermissionDenied
	}
	return nil
}

func validateGlobalDraftInput(content Content, presentation Presentation, audience GlobalAudience, visibility, key, requestID string) error {
	if err := ValidateContent(Content{Title: content.Title, Body: "content"}); err != nil {
		return err
	}
	if presentation.Format == FormatContent {
		// The global body may carry links (not ValidateContent's markup rules).
		switch {
		case presentation.LinkURL != "":
			return fielderr.New(ErrInvalidContent, "link_url", fielderr.Invalid)
		case presentation.SortOrder < 0 || presentation.SortOrder > 999999:
			return fielderr.New(ErrInvalidContent, "sort_order", fielderr.OutOfRange)
		case strings.TrimSpace(content.Body) == "":
			return fielderr.New(ErrInvalidContent, "body", fielderr.Required)
		case len(content.Body) > MaxBodyBytes:
			return fielderr.New(ErrInvalidContent, "body", fielderr.TooLong)
		case !utf8.ValidString(content.Body) || hasForbiddenControl(content.Body, true):
			return fielderr.New(ErrInvalidContent, "body", fielderr.Invalid)
		}
	} else if err := ValidatePresentation(presentation, content); err != nil {
		return err
	}
	if err := ValidateGlobalAudience(audience); err != nil {
		return err
	}
	if visibility != VisibilityRetain && visibility != VisibilityHide {
		return fielderr.New(ErrInvalidInput, "withdrawal_visibility", fielderr.Invalid)
	}
	if !validMeta(key, requestID) {
		return ErrInvalidInput
	}
	return nil
}

func validGlobalStatus(status string) bool {
	return status == "" || status == StatusDraft || status == StatusPublished || status == StatusWithdrawn || status == StatusArchived
}

func (s *Store) appendGlobalAudit(ctx context.Context, tx pgx.Tx, actor Actor, item GlobalAnnouncement, requestID, action string) error {
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: action,
		ResourceType: "platform_announcement", ResourceID: item.ID.String(), RequestID: requestID, Result: "success",
		Payload: map[string]any{"version": item.Version, "revision": item.Revision, "status": item.Status, "recipient_count": item.RecipientCount, "archived": item.Archived, "lifecycle_revision": item.LifecycleRevision},
	})
}
