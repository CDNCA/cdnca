package artifactsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CRSRuleSystemKey is the system rule carrying the CRS rule text
// (artifact crs_profile/crs_rules).
const CRSRuleSystemKey = "waf_set:crs_rules"

// Materialize makes security_system_rules follow the usable downloaded
// ruleset / crs_profile artifacts: an artifact whose downloaded digest is not
// the materialized one is written as active; one that is no longer usable
// (withdrawn entry, lease feature lost) is frozen as withdrawn (never
// deleted, so sites keep their references; the UI shows it "已下线").
// CRS profile packs (crs_profile/crs-*) are not system rules: the managed WAF
// reads them from local_artifacts (CRSProfiles).
// When the CRS rule package digest changes, the republisher is asked to
// republish the scopes that load a changed file. It returns how many system
// rules changed.
func (store *Store) Materialize(ctx context.Context) (int, error) {
	now := store.now().UTC()
	changed := 0
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, catalogLockKey); err != nil {
			return err
		}
		features, err := store.readFeatures(ctx, tx)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+entryColumns+`,entry.status,entry.delivery_id,local.current_revision,
			local.current_sha256,local.materialized_sha256,object.content
			FROM local_artifacts local
			JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id
			JOIN artifact_objects object ON object.sha256=local.current_sha256
			WHERE entry.kind IN ('ruleset','crs_profile') AND entry.media_type<>$1 AND local.current_revision IS NOT NULL
			ORDER BY local.artifact_id FOR UPDATE OF local`, artifactcatalog.MediaTypeCRSProfilePack)
		if err != nil {
			return err
		}
		type candidate struct {
			entry        artifactcatalog.Entry
			status       string
			deliveryID   uuid.UUID
			revision     int64
			sha256       string
			materialized *string
			content      []byte
		}
		candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (candidate, error) {
			var item candidate
			entry, err := scanEntry(row, &item.status, &item.deliveryID, &item.revision, &item.sha256, &item.materialized, &item.content)
			item.entry = entry
			return item, err
		})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('cdnca.security_rule_catalog_apply','on',true)`); err != nil {
			return err
		}
		packs, defaultOn, err := store.materializeRulePacks(ctx, tx, features)
		if err != nil {
			return err
		}
		changed += packs
		if err := store.recomputeDefaultOnMounts(ctx, tx, defaultOn); err != nil {
			return err
		}
		for _, item := range candidates {
			usable := item.status == "active" && permitted(features, item.entry.RequiresFeature)
			upToDate := item.materialized != nil && *item.materialized == item.sha256
			if usable && upToDate || !usable && item.materialized == nil {
				continue
			}
			// The downloaded bytes, checked against the entry they were
			// downloaded for (revision and digest of the local artifact).
			downloaded := item.entry
			downloaded.Revision, downloaded.SHA256, downloaded.Size = uint64(item.revision), item.sha256, int64(len(item.content))
			rule, err := artifactcatalog.DecodeRulesetItem(downloaded, item.content)
			if err != nil {
				return fmt.Errorf("stored artifact %s: %w", item.entry.ArtifactID, err)
			}
			var previous []byte
			if rule.SystemKey == CRSRuleSystemKey {
				if previous, err = activeSystemRuleBody(ctx, tx, rule.SystemKey); err != nil {
					return err
				}
			}
			next := []byte(nil)
			if usable {
				if next, err = upsertSystemRule(ctx, tx, rule, item.deliveryID, now); err != nil {
					return err
				}
				_, err = tx.Exec(ctx, `UPDATE local_artifacts SET materialized_sha256=$2,updated_at=$3 WHERE artifact_id=$1`,
					item.entry.ArtifactID, item.sha256, now)
			} else {
				if _, err = tx.Exec(ctx, `UPDATE security_system_rules SET status='withdrawn',withdrawn_at=$2,updated_at=$2
					WHERE system_key=$1 AND status='active'`, rule.SystemKey, now); err != nil {
					return err
				}
				_, err = tx.Exec(ctx, `UPDATE local_artifacts SET materialized_sha256=NULL,updated_at=$2 WHERE artifact_id=$1`,
					item.entry.ArtifactID, now)
			}
			if err != nil {
				return err
			}
			changed++
			if rule.SystemKey != CRSRuleSystemKey || store.republisher == nil {
				continue
			}
			// Releases embed the CRS rule text when built: a new package
			// reaches the nodes only through their republication.
			previousSHA, nextSHA := "", ""
			if item.materialized != nil {
				previousSHA = *item.materialized
			}
			if usable {
				nextSHA = item.sha256
			}
			if _, err := store.republisher.RepublishCRSPackageChangeTx(ctx, tx, item.deliveryID, previousSHA, nextSHA,
				previous, next); err != nil {
				return fmt.Errorf("request CRS rule package republication: %w", err)
			}
		}
		crsPacks, err := store.materializeCRSProfilePacks(ctx, tx, features, now)
		changed += crsPacks
		if err != nil {
			return err
		}
		crawlers, err := store.materializeTrustedCrawlers(ctx, tx, now)
		changed += crawlers
		if err != nil {
			return err
		}
		var dataPacks int
		dataPacks, err = store.materializeDataPacks(ctx, tx, now)
		changed += dataPacks
		if err != nil {
			return err
		}
		var pages int
		pages, err = store.materializePluginUIPages(ctx, tx, now)
		changed += pages
		if err != nil {
			return err
		}
		var providers int
		providers, err = store.materializePluginProviders(ctx, tx, now)
		changed += providers
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("materialize system rules: %w", err)
	}
	return changed, nil
}

func activeSystemRuleBody(ctx context.Context, tx pgx.Tx, systemKey string) ([]byte, error) {
	var body []byte
	err := tx.QueryRow(ctx, `SELECT body FROM security_system_rules WHERE system_key=$1 AND status='active'`, systemKey).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return body, err
}

// upsertSystemRule writes rule as active and returns its stored body.
func upsertSystemRule(ctx context.Context, tx pgx.Tx, rule rulecatalog.Item, deliveryID uuid.UUID, now time.Time) ([]byte, error) {
	body, err := json.Marshal(rule.Body)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security_system_rules(system_key,kind,legacy_id,name,description,sort,hidden,
		revision,body,status,delivery_id,first_seen_at,updated_at,withdrawn_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,$11,NULL)
		ON CONFLICT (system_key) DO UPDATE SET kind=EXCLUDED.kind,legacy_id=EXCLUDED.legacy_id,name=EXCLUDED.name,
		description=EXCLUDED.description,sort=EXCLUDED.sort,hidden=EXCLUDED.hidden,revision=EXCLUDED.revision,
		body=EXCLUDED.body,status='active',delivery_id=EXCLUDED.delivery_id,updated_at=EXCLUDED.updated_at,withdrawn_at=NULL`,
		rule.SystemKey, rule.Kind, rule.LegacyID, rule.Name, rule.Description, rule.Sort, rule.Hidden, rule.Revision, body,
		deliveryID, now); err != nil {
		return nil, err
	}
	// The body as jsonb stores it, so the republisher compares like with like.
	return activeSystemRuleBody(ctx, tx, rule.SystemKey)
}

// materializeCRSProfilePacks tracks the CRS profile pack bytes the managed
// WAF may use (materialized_sha256 = the usable downloaded digest, NULL when
// unusable). A pack whose usable digest changed republishes the scopes that
// selected its previous digest (they would otherwise keep running it). It
// returns how many packs changed.
func (store *Store) materializeCRSProfilePacks(ctx context.Context, tx pgx.Tx, features map[string]bool, now time.Time) (int, error) {
	rows, err := tx.Query(ctx, `SELECT local.artifact_id,entry.status,entry.requires_feature,entry.delivery_id,
		local.current_sha256,local.materialized_sha256
		FROM local_artifacts local
		JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id
		WHERE entry.kind='crs_profile' AND entry.media_type=$1 AND local.current_revision IS NOT NULL
		ORDER BY local.artifact_id FOR UPDATE OF local`, artifactcatalog.MediaTypeCRSProfilePack)
	if err != nil {
		return 0, err
	}
	type pack struct {
		artifactID, status, feature string
		deliveryID                  uuid.UUID
		sha256                      string
		materialized                *string
	}
	packs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (pack, error) {
		var item pack
		return item, row.Scan(&item.artifactID, &item.status, &item.feature, &item.deliveryID, &item.sha256, &item.materialized)
	})
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, item := range packs {
		var next *string
		if item.status == "active" && permitted(features, item.feature) {
			next = &item.sha256
		}
		if item.materialized == nil && next == nil || item.materialized != nil && next != nil && *item.materialized == *next {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE local_artifacts SET materialized_sha256=$2,updated_at=$3 WHERE artifact_id=$1`,
			item.artifactID, next, now); err != nil {
			return changed, err
		}
		changed++
		if item.materialized == nil || store.republisher == nil {
			continue // nothing selected the pack before
		}
		if _, err := store.republisher.RepublishCRSProfilePackChangeTx(ctx, tx, item.deliveryID, []string{*item.materialized}); err != nil {
			return changed, fmt.Errorf("request CRS profile pack republication: %w", err)
		}
	}
	return changed, nil
}

// materializeTrustedCrawlers marks the downloaded trusted crawler dataset
// (dataset/trusted-crawlers) as in use and, when the bytes in use changed
// (a new revision, or the entry withdrawn), republishes the scopes with CC
// policies: edgepublish merges the dataset into their trusted crawlers.
func (store *Store) materializeTrustedCrawlers(ctx context.Context, tx pgx.Tx, now time.Time) (int, error) {
	var status, sha256 string
	var deliveryID uuid.UUID
	var materialized *string
	err := tx.QueryRow(ctx, `SELECT entry.status,entry.delivery_id,local.current_sha256,local.materialized_sha256
		FROM local_artifacts local JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id
		WHERE local.artifact_id=$1 AND local.current_revision IS NOT NULL FOR UPDATE OF local`,
		artifactcatalog.TrustedCrawlersID).Scan(&status, &deliveryID, &sha256, &materialized)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var next *string
	if status == "active" {
		next = &sha256
	}
	if materialized == nil && next == nil || materialized != nil && next != nil && *materialized == *next {
		return 0, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE local_artifacts SET materialized_sha256=$2,updated_at=$3 WHERE artifact_id=$1`,
		artifactcatalog.TrustedCrawlersID, next, now); err != nil {
		return 0, err
	}
	if republisher, ok := store.republisher.(TrustedCrawlerRepublisher); ok {
		if _, err := republisher.RepublishTrustedCrawlersChangeTx(ctx, tx, deliveryID); err != nil {
			return 1, fmt.Errorf("request trusted crawler republication: %w", err)
		}
	}
	return 1, nil
}
