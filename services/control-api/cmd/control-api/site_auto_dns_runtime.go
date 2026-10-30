package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildSiteAutoDNSWorker: nil (logged) without the DNS credential cipher.
func buildSiteAutoDNSWorker(pool *pgxpool.Pool, cipher *dnsacme.AESGCMCredentialCipher) (*site.AutoDNSWorker, error) {
	if !configuredRuntimePool(pool) {
		return nil, nil
	}
	if cipher == nil {
		slog.Warn("site auto DNS does not run: the DNS credential cipher is not configured")
		return nil, nil
	}
	writer, err := dnsproviderremotesource.NewSiteAutoDNSWriter(dnsproviderremotesource.New(pool, cipher),
		dnsproviderremote.NewReconcileRemote().(dnsproviderremotesource.LineRemote))
	if err != nil {
		return nil, err
	}
	return site.NewAutoDNSWorker(site.NewStoreWithClock(pool, time.Now, nil), siteAutoDNSPointer(writer), slog.Default()), nil
}

func siteAutoDNSPointer(writer *dnsproviderremotesource.SiteAutoDNSWriter) site.AutoDNSPointer {
	return func(ctx context.Context, scopeID, siteID, providerID uuid.UUID, domain, target string) (string, string, bool) {
		change, err := writer.Point(ctx, scopeID, siteID, providerID, domain, target)
		if err != nil {
			return change.Before, dnsproviderremotesource.CNAMEFailureCode(err), dnsproviderremotesource.AutoDNSFailureTemporary(err)
		}
		return change.Before, "", false
	}
}
