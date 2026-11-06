package edgeautopublish

import (
	"context"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LocalPluginSourceID is the source resource of local plugin stop / enable
// republications: this controller's stop list, not a row of its own.
var LocalPluginSourceID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("cdnca.plugin.local_disables"))

// RepublishLocalPluginChangeTx runs in the transaction that stopped or enabled
// plugin codes on this controller. Site objects carry the rule pack mounts and
// publication leaves out a mount whose pack needs a stopped code
// (edgepublish withholdMarketPluginMounts), so every scope whose sites mount a
// pack needing one of codes is republished through the system channel at once
// (trigger module_entitlement). Other codes (module.*) are read by their
// runtime on each use and need no republication; CRS profile packs follow
// through artifact materialization. It returns the scopes asked, in scope
// order (the publication lock order).
func RepublishLocalPluginChangeTx(ctx context.Context, tx pgx.Tx, codes []string) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	if len(codes) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT site.scope_id FROM site_security_mounts mount
		JOIN sites site ON site.id=mount.site_id AND site.deleted_at IS NULL
		CROSS JOIN LATERAL jsonb_array_elements(COALESCE(mount.security->'mounts','[]'::jsonb)) item
		JOIN artifact_catalog_entries entry ON entry.artifact_id='rule_pack/'||replace(item->>'pack_id','/',':')
		WHERE entry.requires_feature=ANY($1::text[])
		ORDER BY site.scope_id`, codes)
	if err != nil {
		return nil, fmt.Errorf("find scopes mounting stopped packs: %w", err)
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("find scopes mounting stopped packs: %w", err)
	}
	stamp := time.Now().UnixNano()
	for _, scopeID := range scopes {
		if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
			ScopeID: scopeID, Trigger: edgepublish.SystemTriggerModuleEntitlement, SourceResourceID: LocalPluginSourceID,
			SourceRequestID: fmt.Sprintf("plugin-local.%s.%d", scopeID, stamp), Immediate: true,
		}); err != nil {
			return nil, err
		}
	}
	return scopes, nil
}
