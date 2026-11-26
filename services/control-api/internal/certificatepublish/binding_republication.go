package certificatepublish

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RequestBindingRepublicationTx republishes the site's scope once a binding
// the tenant changed (bound, rebound, a version activated) reached every node
// (certificateasset.PublicationIntentStoreConfig.Published): the site object
// names the certificate version, a certificate publication only puts the
// material on the nodes, so without it the nodes kept serving the old
// certificate (control 1129 rev3). Material first, then the site objects:
// it runs in the transaction that settles the publication succeeded. It is
// the renewal's republication (trigger certificate_renewal: content change,
// due at once, the stop overlay swaps in the site's current certificate), for
// manual and automatic scopes alike; a new trigger value would leave a
// database that used it unable to go back to the previous release.
// A binding that is not the site's latest is left to the latest one, which
// republishes when its own publication settles.
func RequestBindingRepublicationTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, bindingRevision int64) error {
	if ctx == nil || tx == nil || scopeID == uuid.Nil || siteID == uuid.Nil || bindingRevision < 1 {
		return ErrInvalidInput
	}
	// The scope's configuration row first (publication lock order), and the
	// revision before the advance, so the republication is attributed to it.
	var current int64
	err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
		scopeID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // nothing was ever published for the scope
	}
	if err != nil {
		return err
	}
	var latest int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(sequence),0) FROM certificate_site_binding_facts
		WHERE tenant_scope_id=$1 AND site_id=$2`, scopeID, siteID).Scan(&latest); err != nil {
		return err
	}
	if latest != bindingRevision {
		return nil
	}
	if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, scopeID); err != nil {
		return err
	}
	_, err = edgeautopublish.RequestRepublicationTx(ctx, tx, edgeautopublish.RepublishRequest{
		ScopeID: scopeID, Trigger: edgepublish.SystemTriggerCertificateRenewal, SourceResourceID: siteID,
		Operation: "site.update", SourceRequestID: edgepublish.CertificateBindingRequestID(siteID, bindingRevision),
		FromRevision: current,
	})
	return err
}

// republishStaleBindingTx queues the republication of a scope whose latest
// publication still names a certificate version its sites no longer use
// although the new one reached the nodes (edgepublish.StaleCertificateBindingTx:
// bindings that settled before RequestBindingRepublicationTx existed).
func republishStaleBindingTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	siteID, bindingRevision, found, err := edgepublish.StaleCertificateBindingTx(ctx, tx, scopeID)
	if err != nil || !found {
		return err
	}
	return RequestBindingRepublicationTx(ctx, tx, scopeID, siteID, bindingRevision)
}
