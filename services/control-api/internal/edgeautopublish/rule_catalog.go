package edgeautopublish

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RuleCatalogRepublicationDebounce merges the CRS rule package changes one
// scope receives within it (a sync catching up several revisions) into one
// republication.
const RuleCatalogRepublicationDebounce = 30 * time.Second

// RuleCatalogPublisher requests the republication of every published scope
// whose release loads a CRS rule file the new CRS rule package
// (crs_profile/crs_rules) changed; artifactsync.Store.Materialize calls it in
// the transaction that materializes a package whose digest changed. Manual
// scopes go through the system channel, automatic scopes through their
// policy; nodes lacking a gated capability are left out there, as for every
// system republication.
type RuleCatalogPublisher struct{}

// RepublishCRSPackageChangeTx is triggered by the package digest: an
// unchanged digest requests nothing. Otherwise only the scopes loading a file
// whose text differs between the previous and the next package body are
// republished. sourceID is the catalog delivery that brought the package. It
// returns the scopes it requested a republication for, in scope order.
func (RuleCatalogPublisher) RepublishCRSPackageChangeTx(
	ctx context.Context, tx pgx.Tx, sourceID uuid.UUID, previousSHA256, nextSHA256 string, previous, next []byte,
) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil || sourceID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	if previousSHA256 == nextSHA256 {
		return nil, nil
	}
	changed := edgepublish.ChangedCRSRuleFiles(previous, next)
	if len(changed) == 0 {
		return nil, nil
	}
	scopes, err := edgepublish.CRSRuleCatalogScopesTx(ctx, tx, changed)
	if err != nil {
		return nil, err
	}
	for _, scopeID := range scopes {
		if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
			ScopeID: scopeID, Trigger: edgepublish.SystemTriggerRuleCatalog, SourceResourceID: sourceID,
			SourceRequestID: "rule-catalog." + sourceID.String(), Debounce: RuleCatalogRepublicationDebounce,
		}); err != nil {
			return nil, err
		}
	}
	return scopes, nil
}

// RepublishCRSProfilePackChangeTx republishes the scopes whose latest release
// selects a CRS profile pack by one of previousSHA256: the pack's new
// downloaded revision (or its loss) reaches them only through a new release.
func (RuleCatalogPublisher) RepublishCRSProfilePackChangeTx(
	ctx context.Context, tx pgx.Tx, sourceID uuid.UUID, previousSHA256 []string,
) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil || sourceID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	scopes, err := edgepublish.CRSProfilePackScopesTx(ctx, tx, previousSHA256)
	if err != nil {
		return nil, err
	}
	for _, scopeID := range scopes {
		if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
			ScopeID: scopeID, Trigger: edgepublish.SystemTriggerRuleCatalog, SourceResourceID: sourceID,
			SourceRequestID: "crs-profile." + sourceID.String(), Debounce: RuleCatalogRepublicationDebounce,
		}); err != nil {
			return nil, err
		}
	}
	return scopes, nil
}

// TrustedCrawlerRepublicationDebounce merges dataset revisions a sync
// catches up into one republication per scope.
const TrustedCrawlerRepublicationDebounce = 30 * time.Second

// RepublishTrustedCrawlersChangeTx republishes every scope whose latest
// release has a site CC policy with trusted crawlers: a new official
// crawler ranges dataset (dataset/trusted-crawlers) changes their compiled
// networks.
func (RuleCatalogPublisher) RepublishTrustedCrawlersChangeTx(ctx context.Context, tx pgx.Tx, sourceID uuid.UUID) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil || sourceID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	scopes, err := edgepublish.TrustedCrawlerScopesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	for _, scopeID := range scopes {
		if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
			ScopeID: scopeID, Trigger: edgepublish.SystemTriggerRuleCatalog, SourceResourceID: sourceID,
			SourceRequestID: "trusted-crawlers." + sourceID.String(), Debounce: TrustedCrawlerRepublicationDebounce,
		}); err != nil {
			return nil, err
		}
	}
	return scopes, nil
}

// IPListRepublicationDebounce merges a burst of edits of one IP list into one
// republication per scope.
const IPListRepublicationDebounce = 5 * time.Second

// RepublishIPListChangeTx republishes every tenant scope whose bound ACL /
// WAF policy references the IP list listID: the rules
// carry the list's contents, written in this transaction at revision. A
// manual scope goes through the system channel (its source revision advances
// once, a system segment); an automatic scope publishes each referencing
// site as its policy's actor (site.update, as a quick block override does).
// It returns the scopes, in scope order.
func RepublishIPListChangeTx(ctx context.Context, tx pgx.Tx, listID uuid.UUID, revision int64) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil || listID == uuid.Nil || revision < 1 {
		return nil, ErrInvalidInput
	}
	sites, err := edgepublish.IPListSitesTx(ctx, tx, listID)
	if err != nil {
		return nil, err
	}
	requestID := "ip-list." + listID.String() + "." + strconv.FormatInt(revision, 10)
	var scopes []uuid.UUID
	for index, site := range sites {
		if index > 0 && sites[index-1].ScopeID == site.ScopeID {
			continue
		}
		var from int64
		err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
			site.ScopeID).Scan(&from)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // never published: its first publication reads the list
		}
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, site.ScopeID); err != nil {
			return nil, err
		}
		_, automatic, err := automaticPolicyActor(ctx, tx, site.ScopeID)
		if err != nil {
			return nil, err
		}
		if automatic {
			for _, other := range sites[index:] {
				if other.ScopeID != site.ScopeID {
					break
				}
				if _, err := EnqueueSiteSettingTx(ctx, tx, site.ScopeID, other.SiteID, requestID); err != nil {
					return nil, err
				}
			}
		} else if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
			ScopeID: site.ScopeID, Trigger: edgepublish.SystemTriggerIPList, SourceResourceID: listID,
			SourceRequestID: requestID, FromRevision: from, Debounce: IPListRepublicationDebounce,
		}); err != nil {
			return nil, err
		}
		scopes = append(scopes, site.ScopeID)
	}
	return scopes, nil
}

// DefaultOnPackRepublicationDebounce merges the mount recomputes of one
// catalog sync into one republication per scope.
const DefaultOnPackRepublicationDebounce = 30 * time.Second

// RepublishDefaultOnPackMountsTx is called with the scopes whose sites'
// rule pack mounts the control plane recomputed for a default-on official
// pack (rulepackcontrol.RecomputeDefaultOnMountsTx): the
// mounts are part of the site objects, so each scope goes out again through
// the system channel (manual scopes; the advances since FromRevision are the
// system's) or its policy (automatic scopes). sourceID names the catalog
// delivery or recompute run.
func (RuleCatalogPublisher) RepublishDefaultOnPackMountsTx(ctx context.Context, tx pgx.Tx, sourceID uuid.UUID,
	scopes []rulepackcontrol.DefaultOnScope) error {
	if ctx == nil || tx == nil || sourceID == uuid.Nil {
		return ErrInvalidInput
	}
	for _, scope := range scopes {
		if scope.FromRevision == 0 {
			continue // never published: its first publication reads the mounts
		}
		if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
			ScopeID: scope.ScopeID, Trigger: edgepublish.SystemTriggerRuleCatalog, SourceResourceID: sourceID,
			SourceRequestID: "default-on-pack." + sourceID.String(), FromRevision: scope.FromRevision,
			Debounce: DefaultOnPackRepublicationDebounce,
		}); err != nil {
			return err
		}
	}
	return nil
}
