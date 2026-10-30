package edgedeployment

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func projectSiteIPv6RolloutTerminalTx(
	ctx context.Context,
	tx pgx.Tx,
	rolloutID uuid.UUID,
	forceFailure bool,
	now time.Time,
) error {
	var configID uuid.UUID
	var action string
	var total, succeeded, terminal int
	err := tx.QueryRow(ctx, `WITH latest AS (
		SELECT DISTINCT ON (deployment.id) deployment.id,deployment.state
		FROM node_deployments deployment
		WHERE deployment.rollout_id=$1
		ORDER BY deployment.id,deployment.attempt DESC
	)
	SELECT rollout.config_version_id,rollout.action,count(latest.id),
	       count(*) FILTER (WHERE (rollout.action='apply' AND latest.state='healthy') OR
	                              (rollout.action='rollback' AND latest.state='reverted')),
	       count(*) FILTER (WHERE latest.state IN ('healthy','failed','reverted','rollback_failed','cancelled'))
	FROM rollouts rollout
	LEFT JOIN latest ON true
	WHERE rollout.id=$1
	GROUP BY rollout.config_version_id,rollout.action`, rolloutID).Scan(
		&configID, &action, &total, &succeeded, &terminal,
	)
	if err != nil {
		return fmt.Errorf("project site IPv6 rollout progress: %w", err)
	}
	if action != "apply" && action != "rollback" {
		return ErrInvalidTransition
	}
	success, ready := siteIPv6RolloutTerminal(total, succeeded, terminal, forceFailure)
	if !ready {
		return nil
	}
	_, err = tx.Exec(ctx, `UPDATE sites site
		SET ipv6_runtime_state=CASE WHEN $2::boolean THEN
		        CASE WHEN target.desired_enabled THEN 'active' ELSE 'disabled' END
		    ELSE 'failed' END,
		    ipv6_runtime_source_revision=target.source_revision,
		    updated_at=GREATEST(site.updated_at,$3)
		FROM site_ipv6_rollout_targets target
		WHERE target.config_version_id=$1
		  AND site.id=target.site_id
		  AND site.scope_id=target.configuration_scope_id
		  AND site.revision=target.site_revision
		  AND site.ipv6_enabled=target.desired_enabled
		  AND target.source_revision>=site.ipv6_runtime_source_revision`, configID, success, now)
	if err != nil {
		return fmt.Errorf("project site IPv6 rollout terminal state: %w", err)
	}
	return nil
}

func siteIPv6RolloutTerminal(total, succeeded, terminal int, forceFailure bool) (success, ready bool) {
	if total < 1 {
		return false, false
	}
	if forceFailure {
		return false, true
	}
	if terminal != total {
		return false, false
	}
	return succeeded == total, true
}
