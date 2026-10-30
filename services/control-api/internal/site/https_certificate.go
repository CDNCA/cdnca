package site

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ReasonCertificateRequired is the FieldError reason of a site update that
// turns HTTPS or forced HTTPS on while the site has no bound certificate
// (be-gap-2, WEB-C01/C05): the listener would serve no certificate.
const ReasonCertificateRequired = "certificate_required"

type certificateBindingQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// siteCertificateBound: the site's current certificate binding fact is a bind
// (the same reading as the list projection, status_recovery.go).
func siteCertificateBound(ctx context.Context, q certificateBindingQueryer, siteID uuid.UUID) (bool, error) {
	var bound bool
	err := q.QueryRow(ctx, `SELECT COALESCE((SELECT action='bind' FROM certificate_site_binding_facts
		WHERE site_id=$1 ORDER BY sequence DESC LIMIT 1),false)`, siteID).Scan(&bound)
	return bound, err
}

// checkHTTPSCertificate refuses turning HTTPS or forced HTTPS on without a
// bound certificate. Keeping a value that is already on, or turning it off,
// is never refused (unbinding later must not lock the site's other edits).
func checkHTTPSCertificate(ctx context.Context, q certificateBindingQueryer, siteID uuid.UUID,
	httpsBefore, forceBefore bool, fields SiteFields) error {
	enablesHTTPS := fields.HTTPSEnabled && !httpsBefore
	enablesForce := fields.ForceHTTPS != nil && *fields.ForceHTTPS && !forceBefore
	if !enablesHTTPS && !enablesForce {
		return nil
	}
	bound, err := siteCertificateBound(ctx, q, siteID)
	if err != nil || bound {
		return err
	}
	if enablesHTTPS {
		return fieldError("https_enabled", ReasonCertificateRequired)
	}
	return fieldError("force_https", ReasonCertificateRequired)
}
