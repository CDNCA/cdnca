package edgedeployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SiteRuntimeV2ConfigCapabilitiesTx reports whether configID is a site
// runtime release (a v2 site object root with per-node key envelopes) and, if
// so, the capabilities its release requires (the document's with
// site_runtime 9): a rollout of it, rollback included, must require exactly
// these (requireReleasableConfig).
func SiteRuntimeV2ConfigCapabilitiesTx(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, configID uuid.UUID,
) ([]*agentv1.Capability, bool, error) {
	if tx == nil || scopeID == uuid.Nil || configID == uuid.Nil {
		return nil, false, ErrInvalidInput
	}
	var canonical []byte
	var dynamicRouting bool
	err := tx.QueryRow(ctx, `SELECT version.canonical_snapshot,EXISTS(
		SELECT 1 FROM configuration_artifacts artifact
		WHERE artifact.config_version_id=version.id AND artifact.kind='configuration'
		  AND artifact.media_type=$3)
		FROM config_versions version WHERE version.configuration_scope_id=$1 AND version.id=$2`,
		scopeID, configID, siteObjectRootMediaTypeV2).Scan(&canonical, &dynamicRouting)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, ErrConfigNotFound
	}
	if err != nil {
		return nil, false, fmt.Errorf("read config site runtime: %w", err)
	}
	if !dynamicRouting {
		return nil, false, nil
	}
	var document siteRuntimeV2BundleDocument
	if err := json.Unmarshal(canonical, &document); err != nil || document.Schema != "cdnca.edge.site-runtime/v2" {
		return nil, false, ErrConfigNotReleasable
	}
	capabilities, err := decodeSiteRuntimeV2Capabilities(document.RequiredCapabilities)
	if err != nil {
		return nil, false, ErrConfigNotReleasable
	}
	if capabilities, err = DynamicRoutingDeliveryCapabilities(capabilities); err != nil {
		return nil, false, ErrConfigNotReleasable
	}
	return capabilities, true, nil
}
