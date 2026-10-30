package entitlementguard

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/jackc/pgx/v5"
)

// cdncaCE community edition: free, no activation and no lease. The control
// plane grants itself a fixed community entitlement. Quotas are unlimited;
// the official modules this edition keeps are granted. Commercial modules
// (automatic defense, aggregated edge, migration import, attack escalation),
// payments and the billing bridge are never granted. Official rule packs and
// themes (pack.*, theme.*) are granted only once bought on the plugin market
// (communityPurchasedCodes).

// StatusCommunity is the validation status the community entitlement reports.
const StatusCommunity = "community"

// CommunityLeaseSerial is the lease serial of the built-in community entitlement.
const CommunityLeaseSerial = 1

// communityExcludedModules are the catalog codes of commercial-only modules.
var communityExcludedModules = []string{
	entitlement.ModuleAutoDefense,
	entitlement.ModuleAutoDefenseAuto,
	// 攻击自动升级: its policies are per package; the community edition has none.
	entitlement.ModuleEscalate,
	"module.aggregated_edge",
	"module.migrate.import",
	"module.billing.bridge",
	"module.payment.alipay",
	"module.payment.codepay",
	"module.payment.epay",
	"module.payment.wechat",
}

// communityExcluded reports a code the community edition never grants:
// the commercial modules above, every official rule pack (pack.*) and every
// official theme (theme.*).
func communityExcluded(code string) bool {
	if kind, _, ok := entitlement.ParseModuleFeatureCode(code); ok && (kind == entitlement.ModuleKindPack || kind == entitlement.ModuleKindTheme) {
		return true
	}
	return slices.Contains(communityExcludedModules, code)
}

// communityModuleCodes are the catalog modules granted in the community edition.
func communityModuleCodes() []string {
	codes := []string{}
	for _, module := range entitlement.ModuleCatalog() {
		if !communityExcluded(module.Code) {
			codes = append(codes, module.Code)
		}
	}
	sort.Strings(codes)
	return codes
}

// communityGrants reports whether the community entitlement grants feature
// (base features and quotas are always granted; module codes follow the
// community module list).
func communityGrants(feature string) bool {
	if _, _, ok := entitlement.ParseModuleFeatureCode(feature); ok {
		return slices.Contains(communityModuleCodes(), feature)
	}
	return true
}

// communityFeatures is ReadValidFeatures for the community edition.
func communityFeatures() map[string]bool {
	features := map[string]bool{
		FeatureSitesManage: true, FeatureNodesManage: true, FeatureCertificatesIssue: true,
		FeatureExtensionsWebhooks: true, "packages.manage": true, "builtin.node_monitoring": true,
	}
	for _, code := range communityModuleCodes() {
		features[code] = true
	}
	return features
}

// communityPurchasedCodes are the official pack.* / theme.* codes this
// installation bought on the plugin market. The license service signs a
// per-installation artifact catalog that lists a paid entry only when the
// installation holds its feature (a community installation: only what it
// bought); artifactsync verifies that signature before storing the entries.
// So an active catalog entry requiring a pack/theme code is the purchase,
// but only while the stored catalog is still trustworthy: when the latest
// delivery failed verification (CommunityCatalogRejections) or the verified
// catalog expired (offline past its validity), no purchase is granted. The
// previous catalog is never kept as a grant; the next verified delivery
// restores it.
func communityPurchasedCodes(ctx context.Context, tx pgx.Tx, now time.Time) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT e.requires_feature FROM artifact_catalog_entries e, artifact_catalog_state s
		WHERE e.status='active' AND (e.requires_feature LIKE 'pack.%' OR e.requires_feature LIKE 'theme.%')
		  AND s.delivery_id IS NOT NULL AND s.expires_at > $1 AND NOT (s.last_error_code = ANY($2::text[]))
		ORDER BY 1`, now.UTC(), CommunityCatalogRejections)
	if err != nil {
		return nil, err
	}
	codes, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	purchased := codes[:0]
	for _, code := range codes {
		if kind, _, ok := entitlement.ParseModuleFeatureCode(code); ok &&
			(kind == entitlement.ModuleKindPack || kind == entitlement.ModuleKindTheme) {
			purchased = append(purchased, code)
		}
	}
	return purchased, nil
}

// CommunityCatalogRejections are the artifact_catalog_state.last_error_code
// values artifactsync records when a delivery fails verification
// (artifactsync.RejectionCode; its test keeps the two in step). Transport
// failures (resolve_failed) and local apply failures do not revoke: the
// catalog expiry bounds them.
var CommunityCatalogRejections = []string{"unknown_signing_key", "invalid_signature", "catalog_digest_mismatch",
	"target_mismatch", "expired", "revision_out_of_order", "supersedes_mismatch", "invalid_envelope"}

// communityFeaturesWithPurchases is communityFeatures plus the market purchases.
func communityFeaturesWithPurchases(ctx context.Context, tx pgx.Tx, now time.Time) (map[string]bool, error) {
	features := communityFeatures()
	purchased, err := communityPurchasedCodes(ctx, tx, now)
	if err != nil {
		return nil, err
	}
	for _, code := range purchased {
		features[code] = true
	}
	return features, nil
}

// communityFeatureDecision is checkFeature for the community edition: no
// lease, no audit of a denial, unlimited quota. A commercial module code is
// denied as feature_missing so its callers keep their existing "not
// licensed" behavior.
func (g *Guard) communityFeatureDecision(ctx context.Context, tx pgx.Tx, check FeatureCheck) (FeatureDecision, error) {
	decision := FeatureDecision{TargetScopeID: check.TargetScopeID, ActorScopeID: check.ActorScopeID,
		ActorUserID: check.ActorUserID, ResourceType: check.ResourceType, ResourceID: check.ResourceID,
		RequestID: check.RequestID, Operation: check.Operation, Feature: check.Feature, Quota: check.Quota,
		EvaluatedAt: g.now().UTC(), Limit: -1}
	// The built-in entitlement is lease serial 1, valid for a year from each
	// evaluation, so callers that require a verified lease (edge and ACME
	// publication: serial > 0, not in grace) accept it.
	decision.LeaseSerial = CommunityLeaseSerial
	decision.NotBefore = decision.EvaluatedAt
	decision.ExpiresAt = decision.EvaluatedAt.AddDate(1, 0, 0)
	decision.GraceUntil = decision.ExpiresAt
	granted := communityGrants(check.Feature)
	if !granted && check.Feature != "" {
		// A pack/theme the installation bought on the plugin market.
		purchased, err := communityPurchasedCodes(ctx, tx, g.now())
		if err != nil {
			return FeatureDecision{}, err
		}
		granted = slices.Contains(purchased, check.Feature)
	}
	if !granted {
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, ErrFeatureDenied, StatusCommunity, "feature_missing")
	}
	if check.Quota != "" {
		decision.Limit = entitlement.MaxQuotaLimit
		if check.Count != nil {
			current, err := check.Count(ctx, tx)
			if err != nil {
				return FeatureDecision{}, err
			}
			decision.Current = current
		}
	}
	return decision, nil
}
