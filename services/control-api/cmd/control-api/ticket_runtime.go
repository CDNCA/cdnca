package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpageobjectstore"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagescanner"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/tickets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ticketObjectStore keeps attachments in the brand asset bucket under
// <prefix>/tenants|platform/.../ticket-attachments/<user>/<random>.
type ticketObjectStore struct {
	store *errorpageobjectstore.Store
}

func (s ticketObjectStore) Put(ctx context.Context, scopeID uuid.UUID, key string, body []byte, mimeType string) (string, error) {
	staging := errorpagecontrol.ObjectRef{ScopeID: scopeID, LogicalKey: key + ".staging"}
	object := errorpagecontrol.ObjectRef{ScopeID: scopeID, LogicalKey: key}
	info, err := s.store.PutStaging(ctx, staging, body, mimeType)
	if err != nil {
		return "", err
	}
	finalized, err := s.store.Finalize(ctx, staging, object, info)
	if err != nil {
		return "", err
	}
	return finalized.ImmutableToken, nil
}

func (s ticketObjectStore) Open(ctx context.Context, scopeID uuid.UUID, key, token string) (io.ReadCloser, error) {
	return s.store.Open(ctx, errorpagecontrol.ObjectRef{ScopeID: scopeID, LogicalKey: key}, token)
}

func (s ticketObjectStore) Delete(ctx context.Context, scopeID uuid.UUID, key string) error {
	err := s.store.Delete(ctx, errorpagecontrol.ObjectRef{ScopeID: scopeID, LogicalKey: key})
	if errors.Is(err, errorpagecontrol.ErrObjectNotFound) {
		return nil
	}
	return err
}

// ticketScanner reuses the error page ClamAV scanner.
type ticketScanner struct {
	scanner *errorpagescanner.Scanner
}

func (s ticketScanner) Scan(ctx context.Context, body []byte) error {
	err := s.scanner.Scan(ctx, errorpagecontrol.ScanInput{Size: int64(len(body)), Body: bytes.NewReader(body)})
	if errors.Is(err, errorpagecontrol.ErrScanRejected) {
		return fmt.Errorf("%w: %w", tickets.ErrAttachmentRejected, err)
	}
	return err
}

// ticketAttachmentCleanupInterval is how often expired pending uploads are
// removed (they expire after tickets.PendingUploadWindow).
const ticketAttachmentCleanupInterval = 10 * time.Minute

// ticketOverdueReminderInterval is how often tickets past the first-response
// SLA are looked for (fix-ticket2, ticket.staff.overdue).
const ticketOverdueReminderInterval = 5 * time.Minute

// buildTicketRuntime builds the ticket service and its handler factory.
// Attachments need the brand asset object store; when the error page ClamAV
// scanner is running every attachment is scanned before it is stored.
func buildTicketRuntime(pool *pgxpool.Pool, identityService *identity.Service,
	objects *errorpageobjectstore.Store, scanner *errorpagescanner.Scanner,
) (*tickets.Service, httpapi.MountedHandlerFactory, error) {
	if pool == nil || identityService == nil || !identityService.Configured() {
		return nil, nil, tickets.ErrInvalidInput
	}
	notifications, err := notification.NewStore(pool)
	if err != nil {
		return nil, nil, err
	}
	config := tickets.Config{Pool: pool, Notifier: notifications, Now: time.Now}
	if objects != nil {
		config.Objects = ticketObjectStore{store: objects}
	}
	if scanner != nil {
		config.Scanner = ticketScanner{scanner: scanner}
	}
	service, err := tickets.New(config)
	if err != nil {
		return nil, nil, err
	}
	return service, func() (http.Handler, error) {
		return tickets.NewHandler(service, func(ctx context.Context, raw string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(ctx), raw)
		})
	}, nil
}
