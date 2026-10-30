package rulepackcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Suspended mounts (pack-suspend): changing a site's CRS profile
// never waits for its rule packs. In the profile change's transaction every
// published modsecurity mount the new profile does not cover is taken out of
// site_security_mounts (the profile goes out with the automatic publication)
// and kept in rule_pack_mount_suspensions; a suspended mount the profile
// covers again is put back. Publishing the site's mounts replaces both.

// SuspensionOutOfProfile is the only suspension reason.
const SuspensionOutOfProfile = "out_of_profile"

// Audit actions of suspensions (catalog_rule_pack.go).
const (
	AuditMountSuspend = "rule.pack.mount.suspend"
	AuditMountRestore = "rule.pack.mount.restore"
)

// Suspension is a suspended mount as the pages show it.
type Suspension struct {
	PackID      string    `json:"pack_id"`
	Version     string    `json:"version"`
	Reason      string    `json:"reason"`
	CRSProfile  string    `json:"crs_profile"`
	Detail      string    `json:"detail"`
	SuspendedAt time.Time `json:"suspended_at"`
}

// ProfileChange is what one CRS profile change did to the site's mounts.
type ProfileChange struct {
	Suspended []Suspension `json:"suspended"`
	Restored  []Suspension `json:"restored"`
}

// ProfileChangeInput names the write and its caller (audit fields).
type ProfileChangeInput struct {
	ScopeID        uuid.UUID
	SiteID         uuid.UUID
	ActorUserID    uuid.UUID
	ActorScopeKind string
	SourceIP       string
	RequestID      string
	Now            time.Time
}

type suspendedRow struct {
	Suspension
	mount rulepack.Mount
}

// ApplySiteProfileChangeTx suspends and restores the site's modsecurity
// mounts for its CRS profile as the transaction now sees it (the caller has
// written the profile and locked the site). Nothing changes without a
// published modsecurity mount or suspension.
func ApplySiteProfileChangeTx(ctx context.Context, tx pgx.Tx, input ProfileChangeInput) (ProfileChange, error) {
	change := ProfileChange{Suspended: []Suspension{}, Restored: []Suspension{}}
	published, err := lockPublished(ctx, tx, input.SiteID)
	if err != nil || published == nil {
		return change, err
	}
	suspended, err := loadSuspended(ctx, tx, input.SiteID)
	if err != nil {
		return change, err
	}
	candidates := append([]rulepack.Mount{}, published.Security.Mounts...)
	for _, row := range suspended {
		candidates = append(candidates, row.mount)
	}
	hasModSecurity := false
	for _, mount := range candidates {
		hasModSecurity = hasModSecurity || mount.Engine == rulepack.EngineModSecurity
	}
	if !hasModSecurity {
		return change, nil
	}
	packs, err := loadMountPacks(ctx, tx, candidates)
	if err != nil {
		return change, err
	}
	manifest, profile, profileName, exclusions, err := siteCRSProfile(ctx, tx, input.ScopeID, input.SiteID)
	if err != nil {
		return change, err
	}
	covered := func(mount rulepack.Mount) error {
		_, _, err := rulepack.SiteCRSExclusions([]rulepack.Mount{mount}, packs, manifest, profile, exclusions)
		return err
	}

	active := []rulepack.Mount{}
	modSecurityActive := false
	for _, mount := range published.Security.Mounts {
		if mount.Engine != rulepack.EngineModSecurity {
			active = append(active, mount)
			continue
		}
		if err := covered(mount); err != nil {
			change.Suspended = append(change.Suspended, Suspension{PackID: mount.PackID, Version: mount.Version,
				Reason: SuspensionOutOfProfile, CRSProfile: profileName, Detail: truncate(err.Error(), 1000), SuspendedAt: input.Now})
			if err := insertSuspension(ctx, tx, input, mount, change.Suspended[len(change.Suspended)-1]); err != nil {
				return change, err
			}
			continue
		}
		active, modSecurityActive = append(active, mount), true
	}
	for _, row := range suspended {
		if modSecurityActive || covered(row.mount) != nil {
			continue
		}
		if _, err := tx.Exec(ctx, `DELETE FROM rule_pack_mount_suspensions WHERE site_id=$1 AND pack_id=$2`,
			input.SiteID, row.PackID); err != nil {
			return change, err
		}
		active, modSecurityActive = append(active, row.mount), true
		change.Restored = append(change.Restored, row.Suspension)
	}
	if len(change.Suspended) == 0 && len(change.Restored) == 0 {
		return change, nil
	}
	security, err := rulepack.SecurityOf(active, packs)
	if err != nil {
		return change, fmt.Errorf("rebuild site rule pack mounts: %w", err)
	}
	document, err := json.Marshal(security)
	if err != nil {
		return change, err
	}
	if _, err := tx.Exec(ctx, `UPDATE site_security_mounts SET revision=revision+1, security=$2, resolved_sha256=$3,
		published_by_user_id=$4, published_at=$5 WHERE site_id=$1`, input.SiteID, document, security.ResolvedSHA256,
		input.ActorUserID, input.Now); err != nil {
		return change, err
	}
	if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, input.ScopeID); err != nil {
		return change, fmt.Errorf("advance rule pack mounts edge source revision: %w", err)
	}
	before := map[string]any{"revision": published.Revision, "resolved_sha256": published.Security.ResolvedSHA256,
		"mounts": mountNames(published.Security.Mounts)}
	after := map[string]any{"revision": published.Revision + 1, "resolved_sha256": security.ResolvedSHA256,
		"mounts": mountNames(security.Mounts)}
	for _, item := range change.Suspended {
		if err := appendSuspensionAudit(ctx, tx, input, AuditMountSuspend, item, before, after); err != nil {
			return change, err
		}
	}
	for _, item := range change.Restored {
		if err := appendSuspensionAudit(ctx, tx, input, AuditMountRestore, item, before, after); err != nil {
			return change, err
		}
	}
	return change, nil
}

// SiteSuspensionsTx lists the site's suspended mounts.
func SiteSuspensionsTx(ctx context.Context, q querier, siteID uuid.UUID) ([]Suspension, error) {
	rows, err := loadSuspended(ctx, q, siteID)
	if err != nil {
		return nil, err
	}
	out := make([]Suspension, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Suspension)
	}
	return out, nil
}

func lockPublished(ctx context.Context, tx pgx.Tx, siteID uuid.UUID) (*PublishedMounts, error) {
	var locked uuid.UUID
	err := tx.QueryRow(ctx, `SELECT site_id FROM site_security_mounts WHERE site_id=$1 FOR UPDATE`, siteID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return loadPublished(ctx, tx, siteID)
}

func loadSuspended(ctx context.Context, q querier, siteID uuid.UUID) ([]suspendedRow, error) {
	rows, err := q.Query(ctx, `SELECT pack_id, version, reason, crs_profile, detail, suspended_at, mount
		FROM rule_pack_mount_suspensions WHERE site_id=$1 ORDER BY pack_id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []suspendedRow{}
	for rows.Next() {
		var row suspendedRow
		var mount []byte
		if err := rows.Scan(&row.PackID, &row.Version, &row.Reason, &row.CRSProfile, &row.Detail, &row.SuspendedAt,
			&mount); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(mount, &row.mount); err != nil {
			return nil, fmt.Errorf("decode suspended mount %s: %w", row.PackID, err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// loadMountPacks compiles the stored artifacts of mounts (sealed: manifest).
func loadMountPacks(ctx context.Context, q querier, mounts []rulepack.Mount) (map[string]*rulepack.CompiledPack, error) {
	packs := make(map[string]*rulepack.CompiledPack, len(mounts))
	for _, mount := range mounts {
		var content []byte
		if err := q.QueryRow(ctx, `SELECT content FROM rule_pack_artifacts WHERE pack_id=$1 AND version=$2 AND sha256=$3`,
			mount.PackID, mount.Version, mount.SHA256).Scan(&content); err != nil {
			return nil, fmt.Errorf("read mounted rule pack %s@%s: %w", mount.PackID, mount.Version, err)
		}
		if content == nil {
			return nil, fmt.Errorf("mounted rule pack %s@%s is not downloaded", mount.PackID, mount.Version)
		}
		load := rulepack.Load
		if rulepack.IsSealed(content) {
			load = rulepack.OpenManifest
		}
		compiled, err := load(content, mount.SHA256)
		if err != nil {
			return nil, fmt.Errorf("stored rule pack %s does not compile: %w", mount.PackID, err)
		}
		packs[mount.SHA256] = compiled
	}
	return packs, nil
}

// siteCRSProfile is the site's effective CRS profile as crsProfileCheck reads
// it (nil profile: no managed WAF or the profile pack is not downloaded).
func siteCRSProfile(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) (*edgeconfig.CRSManifest,
	*edgeconfig.CRSProfile, string, []int, error) {
	effective, err := securitypolicy.SiteManagedWAFTx(ctx, tx, scopeID, siteID)
	if err != nil {
		return nil, nil, "", nil, err
	}
	manifest, err := securitypolicy.LoadCRSManifestTx(ctx, tx)
	if err != nil {
		return nil, nil, "", nil, err
	}
	if effective == nil {
		return manifest, nil, "", nil, nil
	}
	profiles, err := securitypolicy.LoadCRSProfilesTx(ctx, tx, nil)
	if err != nil {
		return nil, nil, "", nil, err
	}
	selected, ok := profiles[effective.Profile]
	if !ok {
		return manifest, nil, effective.Profile, nil, nil
	}
	return manifest, &selected.Profile, effective.Profile, effective.Exclusions, nil
}

func insertSuspension(ctx context.Context, tx pgx.Tx, input ProfileChangeInput, mount rulepack.Mount, item Suspension) error {
	document, err := json.Marshal(mount)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO rule_pack_mount_suspensions(site_id,pack_id,version,sha256,mount,reason,crs_profile,
		detail,suspended_by_user_id,suspended_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, input.SiteID, mount.PackID,
		mount.Version, mount.SHA256, document, item.Reason, item.CRSProfile, item.Detail, input.ActorUserID, input.Now)
	return err
}

func appendSuspensionAudit(ctx context.Context, tx pgx.Tx, input ProfileChangeInput, action string, item Suspension,
	before, after map[string]any) error {
	userID := input.ActorUserID
	requestID := input.RequestID
	if requestID == "" {
		requestID = "rule-pack-" + uuid.NewString()
	}
	return audit.NewWithClock(nil, func() time.Time { return input.Now }).Append(ctx, tx, audit.Event{
		ScopeID: input.ScopeID, ActorUserID: &userID, Action: action, ResourceType: "site", ResourceID: input.SiteID.String(),
		RequestID: requestID, Result: "success", Payload: map[string]any{
			"ip": input.SourceIP, "actor_scope_kind": input.ActorScopeKind, "site_id": input.SiteID.String(),
			"pack_id": item.PackID, "version": item.Version, "reason": item.Reason, "crs_profile": item.CRSProfile,
			"changes": map[string]any{
				"revision":        change(before["revision"], after["revision"]),
				"resolved_sha256": change(before["resolved_sha256"], after["resolved_sha256"]),
				"mounts":          change(before["mounts"], after["mounts"]),
			},
		}})
}

func truncate(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

// A WAF library edit changing its CRS profile suspends / restores the
// mounts of its sites like a site profile change (securitypolicy calls this
// in the edit's transaction).
func init() {
	securitypolicy.SiteProfileChangeHook = func(ctx context.Context, tx pgx.Tx, change securitypolicy.SiteProfileChange) error {
		_, err := ApplySiteProfileChangeTx(ctx, tx, ProfileChangeInput{ScopeID: change.ScopeID, SiteID: change.SiteID,
			ActorUserID: change.ActorUserID, ActorScopeKind: change.ActorScopeKind, RequestID: change.RequestID, Now: change.Now})
		return err
	}
}
