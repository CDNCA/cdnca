package edgepublish

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CertificateBindingRequestPrefix names the automatic publication requests
// a certificate binding republication queues (source_request_id
// "certificate-binding/<site>/<binding revision>").
const CertificateBindingRequestPrefix = "certificate-binding/"

// CertificateBindingRequestID is the source request ID of the republication
// a site's binding revision queues.
func CertificateBindingRequestID(siteID uuid.UUID, bindingRevision int64) string {
	return fmt.Sprintf("%s%s/%d", CertificateBindingRequestPrefix, siteID, bindingRevision)
}

// StaleCertificateBindingTx finds one site of the scope whose latest content
// publication still names a certificate version other than its current one
// although that one already reached the nodes: the site's latest binding is
// a default bind of its asset's active version whose publication succeeded,
// and no certificate republication was asked for since (a pending
// certificate_renewal head or such an attempt of the scope after the
// publication settled, or the automatic request of that binding). Bindings
// that settled before a binding republished its sites were left so (control
// 1129 rev3: the node kept serving the old certificate).
func StaleCertificateBindingTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (uuid.UUID, int64, bool, error) {
	if ctx == nil || tx == nil || scopeID == uuid.Nil {
		return uuid.Nil, 0, false, ErrInvalidInput
	}
	var siteID uuid.UUID
	var bindingRevision int64
	err := tx.QueryRow(ctx, `SELECT site.id,binding.sequence
		FROM (SELECT inputs.site_runtime_v2 FROM edge_config_publications publication
		  LEFT JOIN edge_publication_compile_inputs inputs ON inputs.config_version_id=publication.config_version_id
		  WHERE publication.configuration_scope_id=$1 AND publication.contract_version=1
		    AND publication.publication_kind='content'
		  ORDER BY publication.source_revision DESC LIMIT 1) latest
		CROSS JOIN LATERAL jsonb_array_elements(COALESCE(latest.site_runtime_v2->'document'->'sites','[]'::jsonb)) published
		CROSS JOIN LATERAL jsonb_array_elements(COALESCE(published->'listeners','[]'::jsonb)) listener
		JOIN sites site ON site.scope_id=$1 AND site.id=(published->>'id')::uuid AND site.deleted_at IS NULL
		CROSS JOIN LATERAL (SELECT sequence,action,asset_id,version_id,is_default FROM certificate_site_binding_facts
		  WHERE tenant_scope_id=$1 AND site_id=site.id ORDER BY sequence DESC LIMIT 1) binding
		CROSS JOIN LATERAL (SELECT state,occurred_at FROM certificate_publication_intent_state_facts state
		  WHERE state.tenant_scope_id=$1 AND state.site_id=site.id AND state.binding_revision=binding.sequence
		  ORDER BY state.sequence DESC LIMIT 1) settled
		WHERE listener->'tls'->>'certificate_version_id' IS NOT NULL
		  AND binding.action='bind' AND binding.is_default AND settled.state='succeeded'
		  AND binding.version_id::text<>listener->'tls'->>'certificate_version_id'
		  AND binding.version_id=(SELECT activation.version_id FROM certificate_asset_activation_facts activation
		    WHERE activation.tenant_scope_id=$1 AND activation.asset_id=binding.asset_id
		    ORDER BY activation.sequence DESC LIMIT 1)
		  AND NOT EXISTS(SELECT 1 FROM edge_system_republication_heads head
		    WHERE head.scope_id=$1 AND head.state IN ('pending','leased') AND $2=ANY(head.triggers))
		  AND NOT EXISTS(SELECT 1 FROM edge_system_republication_attempts attempt
		    WHERE attempt.scope_id=$1 AND $2=ANY(attempt.triggers) AND attempt.occurred_at>=settled.occurred_at)
		  AND NOT EXISTS(SELECT 1 FROM edge_automatic_publication_requests request
		    WHERE request.target_scope_id=$1 AND request.source_request_id=$3||site.id::text||'/'||binding.sequence::text)
		ORDER BY site.id LIMIT 1`, scopeID, SystemTriggerCertificateRenewal, CertificateBindingRequestPrefix).
		Scan(&siteID, &bindingRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, 0, false, nil
	}
	if err != nil {
		return uuid.Nil, 0, false, fmt.Errorf("%w: read stale certificate bindings", ErrPersistence)
	}
	return siteID, bindingRevision, true, nil
}
