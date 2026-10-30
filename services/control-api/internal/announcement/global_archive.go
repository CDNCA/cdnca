package announcement

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ArchiveGlobal(ctx context.Context, actor Actor, request ArchiveRequest) (GlobalAnnouncement, error) {
	return s.changeGlobalArchive(ctx, actor, request, true)
}

func (s *Store) RestoreGlobal(ctx context.Context, actor Actor, request RestoreRequest) (GlobalAnnouncement, error) {
	return s.changeGlobalArchive(ctx, actor, ArchiveRequest(request), false)
}

func (s *Store) changeGlobalArchive(ctx context.Context, actor Actor, request ArchiveRequest, archive bool) (GlobalAnnouncement, error) {
	if request.AnnouncementID == uuid.Nil || request.ExpectedLifecycleRevision < 1 || !validMeta(request.IdempotencyKey, request.RequestID) {
		return GlobalAnnouncement{}, ErrInvalidInput
	}
	operation := operationGlobalRestore
	if archive {
		operation = operationGlobalArchive
	}
	digestInput := request
	digestInput.RequestID = ""
	digest, err := requestDigest(digestInput)
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
		if current.LifecycleRevision != request.ExpectedLifecycleRevision {
			return ErrRevisionConflict
		}
		if current.Archived == archive {
			return ErrInvalidTransition
		}
		command, err := tx.Exec(ctx, `UPDATE platform_announcement_archive_255 SET
			archived=$3,revision=revision+1,changed_at=$4,changed_by_user_id=$5,
			archived_at=CASE WHEN $3 THEN $4::timestamptz ELSE NULL END,archived_by_user_id=CASE WHEN $3 THEN $5::uuid ELSE NULL END
			WHERE platform_scope_id=$1 AND announcement_id=$2 AND revision=$6`, actor.ScopeID, current.ID,
			archive, storeTime(s.now()), actor.UserID, request.ExpectedLifecycleRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
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
		return GlobalAnnouncement{}, fmt.Errorf("global announcement lifecycle: %w", err)
	}
	return result, nil
}

func decodeGlobalReplay(encoded []byte, result *GlobalAnnouncement) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return err
	}
	_, hasArchived := fields["archived"]
	_, hasRevision := fields["lifecycle_revision"]
	_, hasArchivedAt := fields["archived_at"]
	legacy := !hasArchived && !hasRevision && !hasArchivedAt
	if !legacy && (!hasArchived || !hasRevision || string(fields["archived"]) == "null" || string(fields["lifecycle_revision"]) == "null") {
		return fmt.Errorf("invalid global announcement replay lifecycle")
	}
	if err := decodeReplay(encoded, result); err != nil {
		return err
	}
	if legacy {
		if result.ID == uuid.Nil || result.PlatformScopeID == uuid.Nil || result.Version < 1 || result.Revision < 1 ||
			(result.Status != StatusDraft && result.Status != StatusPublished && result.Status != StatusWithdrawn) {
			return fmt.Errorf("invalid legacy global announcement replay")
		}
		result.LifecycleRevision = 1
	}
	if result.LifecycleRevision < 1 || result.Archived != (result.ArchivedAt != nil) {
		return fmt.Errorf("invalid global announcement replay lifecycle")
	}
	return nil
}
