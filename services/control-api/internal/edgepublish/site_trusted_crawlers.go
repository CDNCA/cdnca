package edgepublish

import (
	"context"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig/crawlerdefaults"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// attachSiteTrustedCrawlers gives every CC binding the downloaded official
// crawler IP ranges dataset (dataset/trusted-crawlers):
// securitypublication merges it by crawler name into the
// policy's trusted crawlers. Nothing is read without CC bindings; without a
// downloaded dataset the crawlers verify as configured.
func attachSiteTrustedCrawlers(ctx context.Context, tx pgx.Tx, bindings map[uuid.UUID][]securityBindingFact) error {
	needed := false
	for _, siteBindings := range bindings {
		for _, binding := range siteBindings {
			needed = needed || binding.policy.Kind == securitypolicy.KindCC
		}
	}
	if !needed {
		return nil
	}
	dataset, err := LoadTrustedCrawlerDatasetTx(ctx, tx)
	if err != nil || dataset == nil {
		return err
	}
	for siteID := range bindings {
		for index := range bindings[siteID] {
			if bindings[siteID][index].policy.Kind == securitypolicy.KindCC {
				bindings[siteID][index].trustedCrawlers = dataset
			}
		}
	}
	return nil
}

// LoadTrustedCrawlerDatasetTx is the downloaded trusted crawler dataset of
// an active catalog entry; nil when there is none.
func LoadTrustedCrawlerDatasetTx(ctx context.Context, tx pgx.Tx) (*crawlerdefaults.Dataset, error) {
	var content []byte
	err := tx.QueryRow(ctx, `SELECT object.content FROM local_artifacts local
		JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id AND entry.status='active'
		JOIN artifact_objects object ON object.sha256=local.current_sha256
		WHERE local.artifact_id=$1 AND local.current_revision IS NOT NULL`, artifactcatalog.TrustedCrawlersID).Scan(&content)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read trusted crawler dataset", ErrPersistence)
	}
	dataset, err := crawlerdefaults.DecodeDataset(content)
	if err != nil {
		return nil, fmt.Errorf("%w: trusted crawler dataset: %v", ErrPersistence, err)
	}
	return &dataset, nil
}

// TrustedCrawlerScopesTx are the tenant scopes with a site bound to a CC
// policy that trusts crawlers: their compiled CC policies carry the
// official crawler ranges, so a new dataset republishes them.
func TrustedCrawlerScopesTx(ctx context.Context, tx pgx.Tx) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT binding.tenant_scope_id FROM security_policy_site_bindings binding
		JOIN security_policies policy ON policy.id=binding.policy_id AND policy.scope_id=binding.tenant_scope_id
		  AND policy.deleted_at IS NULL
		JOIN access_scopes scope ON scope.id=binding.tenant_scope_id AND scope.kind='tenant'
		WHERE binding.policy_kind='cc' AND jsonb_array_length(COALESCE(policy.cc_settings->'trusted_crawlers','[]'::jsonb))>0
		ORDER BY binding.tenant_scope_id`)
	if err != nil {
		return nil, fmt.Errorf("%w: read trusted crawler scopes", ErrPersistence)
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("%w: scan trusted crawler scopes", ErrPersistence)
	}
	return scopes, nil
}
