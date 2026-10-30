package tickets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func validFileName(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 128 ||
		strings.ContainsAny(value, `/\`) || value == "." || value == ".." {
		return "", false
	}
	return value, strings.IndexFunc(value, unicode.IsControl) < 0
}

// sniffMatches requires the body to look like the declared type, so a script
// cannot be stored as "image/png". Downloads are always served as
// attachments with nosniff on top of this.
func sniffMatches(declared string, body []byte) bool {
	if !contains(AttachmentTypes, declared) {
		return false
	}
	if declared == "text/plain" {
		return utf8.Valid(body) && bytes.IndexByte(body, 0) < 0
	}
	detected := strings.TrimSpace(strings.SplitN(http.DetectContentType(body), ";", 2)[0])
	return detected == declared
}

// Upload stores a pending attachment owned by the caller. It becomes visible
// on a ticket only once a create or reply binds it.
func (service *Service) Upload(ctx context.Context, actor Actor, staff bool, requestID string, input UploadInput) (Attachment, error) {
	if service.objects == nil {
		return Attachment{}, ErrAttachmentsDisabled
	}
	name, ok := validFileName(input.FileName)
	if !ok || !keyPattern.MatchString(requestID) {
		return Attachment{}, ErrInvalidInput
	}
	if len(input.Body) == 0 {
		return Attachment{}, ErrInvalidInput
	}
	if len(input.Body) > MaxAttachmentSize {
		return Attachment{}, ErrAttachmentTooLarge
	}
	if !sniffMatches(input.MIMEType, input.Body) {
		return Attachment{}, ErrAttachmentType
	}
	now := service.clock()
	check := func(tx pgx.Tx) error {
		if err := service.authorize(ctx, tx, actor, staff, now, PermissionManage); err != nil {
			return err
		}
		var pending int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ticket_attachments WHERE owner_user_id=$1
			AND message_id IS NULL AND created_at>$2`, actor.UserID, now.Add(-PendingUploadWindow)).Scan(&pending); err != nil {
			return err
		}
		if pending >= MaxPendingUploads {
			return ErrUploadLimit
		}
		return nil
	}
	if err := pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, check); err != nil {
		return Attachment{}, err
	}
	if service.scanner != nil {
		if err := service.scanner.Scan(ctx, input.Body); err != nil {
			if errors.Is(err, ErrAttachmentRejected) {
				return Attachment{}, ErrAttachmentRejected
			}
			return Attachment{}, ErrUnavailable
		}
	}
	// The object key has its own random component: knowing an attachment id
	// says nothing about where the body is stored.
	id := uuid.New()
	key := "ticket-attachments/" + actor.UserID.String() + "/" + uuid.NewString()
	token, err := service.objects.Put(ctx, actor.ScopeID, key, input.Body, input.MIMEType)
	if err != nil {
		service.logf("ticket attachment %s store failed: %v", id, err)
		return Attachment{}, ErrUnavailable
	}
	digest := sha256.Sum256(input.Body)
	attachment := Attachment{ID: id.String(), FileName: name, MIMEType: input.MIMEType, SizeBytes: int64(len(input.Body)),
		SHA256: hex.EncodeToString(digest[:]), CreatedAt: now}
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if err := check(tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ticket_attachments(id,owner_scope_id,owner_user_id,file_name,mime_type,
			size_bytes,sha256,object_key,immutable_token,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			id, actor.ScopeID, actor.UserID, name, input.MIMEType, len(input.Body), digest[:], key, token, now); err != nil {
			return err
		}
		return service.audit(ctx, tx, actor, "ticket.attachment.upload", id, requestID, map[string]any{
			"mime_type": input.MIMEType, "size_bytes": len(input.Body), "scanned": service.scanner != nil})
	})
	if err != nil {
		return Attachment{}, err
	}
	return attachment, nil
}

// Open streams an attachment the caller may see: customers their own
// tickets' customer-visible attachments, staff any bound attachment, and
// everyone their own pending uploads.
func (service *Service) Open(ctx context.Context, actor Actor, staff bool, rawID string) (Download, error) {
	if service.objects == nil {
		return Download{}, ErrNotFound
	}
	id, err := parseID(rawID)
	if err != nil {
		return Download{}, err
	}
	var download Download
	var scopeID uuid.UUID
	var key, token string
	now := service.clock()
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := service.authorize(ctx, tx, actor, staff, now, PermissionRead, PermissionManage); err != nil {
			return err
		}
		var digest []byte
		err := tx.QueryRow(ctx, `SELECT attachment.file_name,attachment.mime_type,attachment.size_bytes,attachment.sha256,
			attachment.created_at,attachment.owner_scope_id,attachment.object_key,attachment.immutable_token
			FROM ticket_attachments attachment
			LEFT JOIN ticket_messages message ON message.id=attachment.message_id
			LEFT JOIN tickets ticket ON ticket.id=attachment.ticket_id
			WHERE attachment.id=$1 AND (attachment.message_id IS NULL OR ticket.deleted_at IS NULL) AND (
				(attachment.message_id IS NULL AND attachment.owner_user_id=$2 AND attachment.owner_scope_id=$3) OR
				($4 AND attachment.message_id IS NOT NULL) OR
				(NOT $4 AND ticket.tenant_scope_id=$3 AND ticket.user_id=$2 AND NOT message.internal))`,
			id, actor.UserID, actor.ScopeID, staff).Scan(&download.FileName, &download.MIMEType, &download.SizeBytes,
			&digest, &download.CreatedAt, &scopeID, &key, &token)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		download.ID, download.SHA256 = id.String(), hex.EncodeToString(digest)
		return err
	})
	if err != nil {
		return Download{}, err
	}
	body, err := service.objects.Open(ctx, scopeID, key, token)
	if err != nil {
		service.logf("ticket attachment %s open failed: %v", id, err)
		return Download{}, ErrUnavailable
	}
	download.Body = body
	return download, nil
}
