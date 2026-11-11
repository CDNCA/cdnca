package edgepublish

import (
	"context"
	"encoding/json"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// siteRuntimeV2URLAuthBinding is a site's enabled URL auth policy version. The policy and its keys reach the site's nodes only in
// the URL auth secret rollout (urlauthpolicy); the site object names the
// version (edgesite.Security.URLAuth).
type siteRuntimeV2URLAuthBinding struct {
	PolicyID      string `json:"policy_id"`
	PolicyVersion int64  `json:"policy_version"`
	// FallbackFloor is the lowest older version a node may verify with while
	// PolicyVersion's artifact has not reached it (edgesite.Security
	// .URLAuthFallbackFloor); 0 = none.
	FallbackFloor int64 `json:"fallback_floor,omitempty"`
}

// bindSiteRuntimeV2URLAuth gives every site with an enabled URL auth policy
// (url_auth_policies, one per site) its policy version and requires
// url_auth v1 (CAPABILITY_NAME_URL_AUTH): a node without it is refused, so
// a site is never served unsigned by a node that cannot verify.
func bindSiteRuntimeV2URLAuth(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, document *siteRuntimeV2Document) error {
	if len(document.Sites) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT site_id,id,revision FROM url_auth_policies WHERE scope_id=$1 AND enabled`, scopeID)
	if err != nil {
		return ErrPersistence
	}
	bySite := map[string]siteRuntimeV2URLAuthBinding{}
	for rows.Next() {
		var siteID, policyID uuid.UUID
		var revision int64
		if err := rows.Scan(&siteID, &policyID, &revision); err != nil {
			rows.Close()
			return ErrPersistence
		}
		bySite[siteID.String()] = siteRuntimeV2URLAuthBinding{PolicyID: policyID.String(), PolicyVersion: revision}
	}
	if rows.Err() != nil {
		return ErrPersistence
	}
	for siteID, binding := range bySite {
		floor, err := urlAuthFallbackFloor(ctx, tx, binding.PolicyID, binding.PolicyVersion)
		if err != nil {
			return err
		}
		binding.FallbackFloor = floor
		bySite[siteID] = binding
	}
	bound := false
	for index := range document.Sites {
		if binding, ok := bySite[document.Sites[index].ID]; ok {
			document.Sites[index].URLAuth = &binding
			bound = true
		}
	}
	if bound {
		requireSiteRuntimeV2Capability(document, siteobject.URLAuthCapability, siteobject.URLAuthAPIVersion)
	}
	return nil
}

func validateSiteRuntimeV2URLAuth(site siteRuntimeV2Site, inferred map[string]uint32) error {
	if site.URLAuth == nil {
		return nil
	}
	if !canonicalSiteRuntimeV2UUID(site.URLAuth.PolicyID) || site.URLAuth.PolicyVersion < 1 ||
		site.URLAuth.FallbackFloor < 0 || (site.URLAuth.FallbackFloor > 0 && site.URLAuth.FallbackFloor >= site.URLAuth.PolicyVersion) {
		return ErrInvalidInput
	}
	inferred[siteobject.URLAuthCapability] = siteobject.URLAuthAPIVersion
	return nil
}

// urlAuthFallbackSteps bounds the fallback range (edgeskeleton
// .URLAuthFallbackSteps).
const urlAuthFallbackSteps = 64

// urlAuthFallbackFloor is the lowest version of the policy a node may verify
// with while version's artifact has not reached it: walking down from
// version-1, every version whose snapshot equals version's except for the
// keys, and whose keys version still trusts (current or previous), is safe;
// the first version that is not (a revoked key, a changed parameter, a
// missing snapshot) ends the walk. A plain rotation keeps the previous key,
// so the node verifies with the old version until the new one lands; a
// revocation or any other change leaves no fallback (0).
func urlAuthFallbackFloor(ctx context.Context, tx pgx.Tx, policyID string, version int64) (int64, error) {
	rows, err := tx.Query(ctx, `SELECT revision,edge_snapshot FROM url_auth_policy_versions
		WHERE policy_id=$1 AND revision<=$2 AND revision>=$3 ORDER BY revision DESC`,
		policyID, version, max(int64(1), version-urlAuthFallbackSteps))
	if err != nil {
		return 0, ErrPersistence
	}
	defer rows.Close()
	snapshots := map[int64][]byte{}
	for rows.Next() {
		var revision int64
		var raw []byte
		if err := rows.Scan(&revision, &raw); err != nil {
			return 0, ErrPersistence
		}
		snapshots[revision] = raw
	}
	if rows.Err() != nil {
		return 0, ErrPersistence
	}
	floor, err := urlAuthFloorFromSnapshots(version, snapshots)
	if err != nil {
		return 0, ErrPersistence
	}
	return floor, nil
}

// urlAuthFloorFromSnapshots is the walk of urlAuthFallbackFloor over the
// edge snapshots by revision.
func urlAuthFloorFromSnapshots(version int64, snapshots map[int64][]byte) (int64, error) {
	split := func(raw []byte) (string, map[string]bool, error) {
		document := map[string]any{}
		if err := json.Unmarshal(raw, &document); err != nil {
			return "", nil, err
		}
		keys := map[string]bool{}
		for _, name := range []string{"current_key", "previous_key"} {
			if key, ok := document[name].(map[string]any); ok {
				if id, ok := key["key_id"].(string); ok {
					keys[id] = true
				}
			}
			delete(document, name)
		}
		delete(document, "policy_version")
		encoded, err := json.Marshal(document)
		return string(encoded), keys, err
	}
	raw, ok := snapshots[version]
	if !ok {
		return 0, nil
	}
	remainder, trusted, err := split(raw)
	if err != nil {
		return 0, err
	}
	floor := int64(0)
	for revision := version - 1; revision >= 1 && version-revision <= urlAuthFallbackSteps; revision-- {
		raw, ok := snapshots[revision]
		if !ok {
			break
		}
		other, keys, err := split(raw)
		if err != nil {
			return 0, err
		}
		if other != remainder {
			break
		}
		for id := range keys {
			if !trusted[id] {
				return floor, nil
			}
		}
		floor = revision
	}
	return floor, nil
}
