package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/auditlog"
	"github.com/cdnca/cdnca/services/control-api/internal/auditloghttp"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildAuditLogHandler mounts the log center reader (unified-log).
func buildAuditLogHandler(pool *pgxpool.Pool, identityService *identity.Service) (http.Handler, error) {
	if pool == nil || identityService == nil {
		return nil, errors.New("audit log runtime dependencies are unavailable")
	}
	auditor := audit.New(pool)
	reader := auditlog.NewStore(pool)
	// log-merge: the admin log center shows 国家-省-市 from the IP library, like B6.
	reader.SetIPIntelLookup(analyticslog.NewPostgresIPIntelLookup(pool, slog.Default()))
	return auditloghttp.NewHandler(auditloghttp.Dependencies{
		Reader:       reader,
		Authenticate: identityService.AuthenticateSession,
		Audit: func(ctx context.Context, event audit.Event) error {
			return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error { return auditor.Append(ctx, tx, event) })
		},
	})
}
