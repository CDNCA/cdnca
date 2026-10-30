package artifactsync

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/ruleintel"
)

// PackReceipts sums the latest node artifact set receipt of every node by
// official pack version (rule intel report section pack_receipts, ADR 0011
// §6.2: the license service pauses a rollout whose new version nodes
// reject). An item counts as applied when its node reports it applied and
// as rejected when the node rejected that item itself (set_rejected: the
// item was fine, another one failed — not counted). Official packs are the
// CRS profile packs (crs_profile/crs-<level> → system/crs-<level>) and the
// system-layer rule packs (rule_pack/<sha256> named by rule_pack_artifacts);
// nothing else leaves the control plane. Ordered by (pack_id, version);
// nil when there is nothing to report. The reporter (RI-08 ruleintelreport
// Collect) puts the result in Report.PackReceipts as is.
func (store *Store) PackReceipts(ctx context.Context) ([]ruleintel.PackReceipt, error) {
	rows, err := store.pool.Query(ctx, `SELECT item->>'artifact_id',COALESCE(item->>'version',''),COALESCE(item->>'result',''),
		COALESCE(item->>'reason',''),artifact.pack_id
		FROM node_artifact_set_receipts receipt
		CROSS JOIN LATERAL jsonb_array_elements(COALESCE(receipt.receipt->'items','[]'::jsonb)) item
		LEFT JOIN rule_pack_artifacts artifact ON artifact.sha256=item->>'sha256' AND artifact.pack_id LIKE 'system/%'
		WHERE item->>'artifact_id' LIKE 'crs_profile/%' OR item->>'artifact_id' LIKE 'rule_pack/%'`)
	if err != nil {
		return nil, fmt.Errorf("read node artifact set receipts: %w", err)
	}
	defer rows.Close()
	type key struct{ pack, version string }
	counts := map[key]*ruleintel.PackReceipt{}
	for rows.Next() {
		var artifactID, version, result, reason string
		var systemPack *string
		if err := rows.Scan(&artifactID, &version, &result, &reason, &systemPack); err != nil {
			return nil, err
		}
		pack := ""
		if name, ok := strings.CutPrefix(artifactID, artifactcatalog.KindCRSProfile+"/"); ok {
			pack = "system/" + name
		} else if systemPack != nil {
			pack = *systemPack
		}
		applied := result == artifactset.ResultApplied
		rejected := result == artifactset.ResultRejected && reason != artifactset.ReasonSetRejected
		if pack == "" || !applied && !rejected {
			continue
		}
		entry := counts[key{pack, version}]
		if entry == nil {
			entry = &ruleintel.PackReceipt{PackID: pack, Version: version}
			counts[key{pack, version}] = entry
		}
		if applied {
			entry.Applied++
		} else {
			entry.Rejected++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(counts) == 0 {
		return nil, nil
	}
	result := make([]ruleintel.PackReceipt, 0, len(counts))
	for _, entry := range counts {
		result = append(result, *entry)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].PackID != result[j].PackID {
			return result[i].PackID < result[j].PackID
		}
		return result[i].Version < result[j].Version
	})
	return result, nil
}
