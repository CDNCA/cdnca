package plugininstallation

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// a lifecycle receipt (install, upgrade, pause, resume, uninstall) is committed locally before it
// is reported to the license service. The local state is in force from the commit on; a report that fails is kept
// pending in the ledger (migration 684) and replayed: right after the write, when the details are read, and by
// RunLicenseReports in the background. A replay sends the same signed request (same payload, deterministic Ed25519
// proof), so the license service records it once and answers repeats from its stored receipt.
//
// the background takes the oldest pending receipt of each authorization and
// delivers that authorization in revision order; a failure backs off that receipt alone (licenseReportRetryBase
// doubling up to licenseReportMaxBackoff), so one authorization that keeps failing never starves the others.

const (
	licenseReportBatch  = 20
	licenseReportRounds = 10
	// licenseReportDueBatch is how many authorizations one background round delivers.
	licenseReportDueBatch = 100
	// licenseReportRetryBase and licenseReportMaxBackoff bound the wait before a failed receipt is tried again in
	// the background, and between rounds while the ledger itself cannot be read.
	licenseReportRetryBase  = 30 * time.Second
	licenseReportMaxBackoff = 10 * time.Minute
)

var errLicenseReportBacklog = errors.New("plugin installation license report backlog")

func (domain *ProductionDomain) ledger() (LicenseReportLedger, bool) {
	ledger, ok := domain.repository.(LicenseReportLedger)
	return ledger, ok
}

// reportReceipt delivers a committed receipt (and any older one of the same authorization still pending) and
// returns the license_sync state of the head. Without a ledger only this receipt is reported, once.
func (domain *ProductionDomain) reportReceipt(ctx context.Context, request MutationRequest, receipt Receipt) string {
	var err error
	if ledger, ok := domain.ledger(); ok {
		err = domain.deliver(ctx, ledger, receipt.AuthorizationID)
	} else {
		_, err = domain.activation.ReportLifecycle(ctx, LifecycleReportRequest{Receipt: receipt})
	}
	if err != nil {
		logLicenseReportPending(request.RequestID, request.Action, receipt.AuthorizationID, err)
		return LicenseSyncPending
	}
	return LicenseSyncSynced
}

// syncLicense delivers what is pending for one authorization and returns its license_sync state ("" without a
// ledger).
func (domain *ProductionDomain) syncLicense(ctx context.Context, requestID, operation string,
	authorizationID uuid.UUID) string {
	ledger, ok := domain.ledger()
	if !ok {
		return ""
	}
	if err := domain.deliver(ctx, ledger, authorizationID); err != nil {
		logLicenseReportPending(requestID, operation, authorizationID, err)
		return LicenseSyncPending
	}
	return LicenseSyncSynced
}

// deliver replays the authorization's unacknowledged receipts in revision order and stops at the first failure:
// a later report would only be refused as stale before the earlier one arrives. The failed receipt backs off in
// the background (not here: a write or an opened detail page always tries at once).
func (domain *ProductionDomain) deliver(ctx context.Context, ledger LicenseReportLedger, authorizationID uuid.UUID) error {
	for range licenseReportRounds {
		receipts, err := ledger.UnreportedReceipts(ctx, domain.installationID, authorizationID, licenseReportBatch)
		if err != nil || len(receipts) == 0 {
			return err
		}
		for _, receipt := range receipts {
			if err := domain.reportOne(ctx, ledger, receipt); err != nil {
				if ctx.Err() == nil {
					if _, _, recordErr := ledger.RecordReportFailure(ctx, receipt.ID, licenseReportRetryBase,
						licenseReportMaxBackoff); recordErr != nil {
						slog.Warn("plugin installation license report backoff not recorded",
							"authorization_id", authorizationID.String(), "cause", LicenseReportCause(recordErr), "error", recordErr.Error())
					}
				}
				return err
			}
		}
	}
	// the last round may have delivered the last receipt; only one still pending
	// after every round is a backlog (a read failure keeps it pending).
	remaining, err := ledger.UnreportedReceipts(ctx, domain.installationID, authorizationID, 1)
	if err != nil {
		return err
	}
	if len(remaining) == 0 {
		return nil
	}
	return errLicenseReportBacklog
}

func (domain *ProductionDomain) reportOne(ctx context.Context, ledger LicenseReportLedger, receipt Receipt) error {
	result, err := domain.activation.ReportLifecycle(ctx, LifecycleReportRequest{Receipt: receipt})
	if err != nil {
		return err
	}
	return ledger.MarkReported(ctx, receipt.ID, result.LifecycleRevision)
}

// annotateLicenseSync marks the local heads of a page synced or pending without contacting the license service
// (a list stays as fast as before; the details and the background deliver). It asks the ledger about exactly the
// page's authorizations; when the ledger cannot be read the page shows pending,
// never synced.
func (domain *ProductionDomain) annotateLicenseSync(ctx context.Context, items []InstallationView) {
	ledger, ok := domain.ledger()
	if !ok || len(items) == 0 {
		return
	}
	ids := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.Installation.AuthorizationID)
	}
	pending, err := ledger.PendingAuthorizations(ctx, domain.installationID, ids)
	for index := range items {
		items[index].LicenseSync = LicenseSyncSynced
		if err != nil || pending[items[index].Installation.AuthorizationID] {
			items[index].LicenseSync = LicenseSyncPending
		}
	}
	if err != nil {
		logLicenseReportPending("", "list", uuid.Nil, err)
	}
}

// RunLicenseReports replays pending lifecycle reports until ctx ends: a round every interval (each failed receipt
// backs off on its own, see deliverAll), backing off up to licenseReportMaxBackoff only while the ledger itself
// cannot be read.
func (domain *ProductionDomain) RunLicenseReports(ctx context.Context, interval time.Duration) error {
	ledger, ok := domain.ledger()
	if ctx == nil || !ok || interval <= 0 {
		return ErrInvalidInput
	}
	wait, failures := time.Duration(0), 0
	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		authorizationID, err := domain.deliverAll(ctx, ledger)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil || authorizationID != uuid.Nil {
			// Delivery failures were logged per authorization; only those authorizations wait longer.
			wait, failures = interval, 0
			continue
		}
		failures++
		wait = interval << min(failures, 5)
		if wait > licenseReportMaxBackoff {
			wait = licenseReportMaxBackoff
		}
		logLicenseReportPending("", "background", authorizationID, err, "failures", failures, "retry_in", wait.String())
	}
}

// deliverAll is one background round: each authorization whose oldest pending receipt is due is delivered in
// revision order up to its first failure, which backs off that receipt alone. It returns the first delivery
// failure and its authorization, or uuid.Nil and the error when the ledger cannot be read.
func (domain *ProductionDomain) deliverAll(ctx context.Context, ledger LicenseReportLedger) (uuid.UUID, error) {
	heads, err := ledger.DueReports(ctx, domain.installationID, licenseReportDueBatch)
	if err != nil {
		return uuid.Nil, err
	}
	var firstID uuid.UUID
	var firstErr error
	for _, head := range heads {
		if ctx.Err() != nil {
			return firstID, ctx.Err()
		}
		if err := domain.deliver(ctx, ledger, head.AuthorizationID); err != nil {
			logLicenseReportPending("", "background", head.AuthorizationID, err)
			if firstErr == nil {
				firstID, firstErr = head.AuthorizationID, err
			}
		}
	}
	return firstID, firstErr
}

func logLicenseReportPending(requestID, operation string, authorizationID uuid.UUID, err error, extra ...any) {
	attrs := []any{"operation", operation, "cause", LicenseReportCause(err)}
	if requestID != "" {
		attrs = append(attrs, "request_ref", requestReference(requestID))
	}
	if authorizationID != uuid.Nil {
		attrs = append(attrs, "authorization_id", authorizationID.String())
	}
	if reason := ActivationInvalidReason(err); reason != "" {
		attrs = append(attrs, "activation_reason", reason)
	}
	slog.Warn("plugin installation license report pending; local state is in force", append(attrs, extra...)...)
}

// LicenseReportCause is the stable, loggable cause of a failed lifecycle report: the transport failure, the
// license refusal code, a refused signed answer, or a local failure.
func LicenseReportCause(err error) string {
	var call licenseCallError
	switch {
	case errors.As(err, &call):
		return call.cause
	case errors.Is(err, context.DeadlineExceeded):
		return "context_deadline"
	case errors.Is(err, context.Canceled):
		return "context_canceled"
	case errors.Is(err, ErrActivationInvalid):
		return "response_invalid"
	case errors.Is(err, ErrStorageUnavailable):
		return "storage"
	case errors.Is(err, errLicenseReportBacklog):
		return "backlog"
	case errors.Is(err, ErrInvalidInput):
		return "receipt_invalid"
	default:
		return "internal"
	}
}
