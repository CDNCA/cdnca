package main

import (
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnamelines"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/jackc/pgx/v5/pgxpool"
)

const cnameCarrierLineInterval = 30 * time.Second

// buildCNAMECarrierLines wires the site CNAME per carrier line through the tenants' per-line DNS writer. In the
// commercial edition the aggregated edge runtime builds it next to its own
// line writer; the community edition builds it alone.
func buildCNAMECarrierLines(pool *pgxpool.Pool, cipher *dnsacme.AESGCMCredentialCipher) (*cnamelines.Worker, error) {
	lines, err := dnsproviderremotesource.NewLineRecords(dnsproviderremotesource.New(pool, cipher),
		dnsproviderremote.NewReconcileRemote().(dnsproviderremotesource.LineRemote))
	if err != nil {
		return nil, err
	}
	return cnamelines.NewWorker(pool, lines, time.Now, slog.Default().With("component", "cname_carrier_lines"))
}
