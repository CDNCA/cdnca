package edgepublish

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type siteIPv6RolloutTarget struct {
	siteID         uuid.UUID
	desiredEnabled bool
	siteRevision   int64
}

func persistSiteIPv6RolloutTargets(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, configID uuid.UUID,
	sourceRevision int64,
	snapshot []byte,
	now time.Time,
) error {
	if err := validateSiteIPv6SnapshotBinding(snapshot, scopeID, configID, sourceRevision); err != nil {
		return err
	}
	targets, err := siteIPv6TargetsFromSnapshot(snapshot)
	if err != nil {
		return err
	}
	for _, target := range targets {
		command, err := tx.Exec(ctx, `INSERT INTO site_ipv6_rollout_targets (
			config_version_id,configuration_scope_id,site_id,source_revision,
			desired_enabled,site_revision,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (config_version_id,site_id) DO NOTHING`, configID, scopeID, target.siteID, sourceRevision,
			target.desiredEnabled, target.siteRevision, now)
		if err != nil {
			return fmt.Errorf("%w: persist site IPv6 rollout target", ErrPersistence)
		}
		if command.RowsAffected() == 0 {
			var exact bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(
				SELECT 1 FROM site_ipv6_rollout_targets
				WHERE config_version_id=$1 AND configuration_scope_id=$2 AND site_id=$3
				  AND source_revision=$4 AND desired_enabled=$5 AND site_revision=$6
			)`, configID, scopeID, target.siteID, sourceRevision, target.desiredEnabled, target.siteRevision).Scan(&exact); err != nil || !exact {
				return fmt.Errorf("%w: verify site IPv6 rollout target replay", ErrPersistence)
			}
		}
	}
	return nil
}

func validateSiteIPv6SnapshotBinding(snapshot []byte, scopeID, configID uuid.UUID, sourceRevision int64) error {
	var binding struct {
		Schema               string `json:"schema"`
		ConfigurationScopeID string `json:"configuration_scope_id"`
		ConfigVersionID      string `json:"config_version_id"`
		SourceRevision       int64  `json:"source_revision"`
	}
	if err := json.Unmarshal(snapshot, &binding); err != nil ||
		binding.ConfigurationScopeID != scopeID.String() || binding.SourceRevision != sourceRevision {
		return ErrInvalidInput
	}
	if binding.Schema != siteRuntimeV2Schema || binding.ConfigVersionID != configID.String() {
		return ErrInvalidInput
	}
	return nil
}

func siteIPv6TargetsFromSnapshot(snapshot []byte) ([]siteIPv6RolloutTarget, error) {
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(snapshot, &header); err != nil {
		return nil, fmt.Errorf("%w: decode site IPv6 snapshot", ErrInvalidInput)
	}
	switch header.Schema {
	case siteRuntimeV2Schema:
		var document siteRuntimeV2Document
		if err := json.Unmarshal(snapshot, &document); err != nil {
			return nil, fmt.Errorf("%w: decode runtime-v2 site IPv6 snapshot", ErrInvalidInput)
		}
		result := make([]siteIPv6RolloutTarget, len(document.Sites))
		for index, site := range document.Sites {
			siteID, err := uuid.Parse(site.ID)
			if err != nil || site.Revision < 1 || len(site.Listeners) == 0 {
				return nil, ErrInvalidInput
			}
			enabled, ok := siteRuntimeV2IPv6Enabled(site.Listeners[0].AddressFamily)
			if !ok {
				return nil, ErrInvalidInput
			}
			for _, listener := range site.Listeners {
				listenerEnabled, valid := siteRuntimeV2IPv6Enabled(listener.AddressFamily)
				if !valid || listenerEnabled != enabled {
					return nil, ErrInvalidInput
				}
			}
			result[index] = siteIPv6RolloutTarget{siteID: siteID, desiredEnabled: enabled, siteRevision: site.Revision}
		}
		return result, nil
	default:
		return nil, ErrInvalidInput
	}
}

func siteRuntimeV2IPv6Enabled(addressFamily string) (enabled, valid bool) {
	switch addressFamily {
	case "ipv4":
		return false, true
	case "ipv6", "dual_stack":
		return true, true
	default:
		return false, false
	}
}
