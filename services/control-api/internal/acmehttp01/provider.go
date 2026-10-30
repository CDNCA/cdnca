package acmehttp01

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeedge"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/idna"
)

type Provider struct {
	pool    *pgxpool.Pool
	overlay *acmeedge.Service
	config  ProviderConfig
}

func NewProvider(pool *pgxpool.Pool, overlay *acmeedge.Service, config ProviderConfig) (*Provider, error) {
	if pool == nil || overlay == nil || config.Clock == nil || config.ChallengeLifetime <= 0 ||
		config.ChallengeLifetime > 24*time.Hour || config.HealthPoll <= 0 || config.HealthPoll > time.Minute ||
		config.MaxAttempts < 1 || config.MaxAttempts > 10 || config.MaxTargets < 1 || config.MaxTargets > 10000 {
		return nil, ErrInvalidConfig
	}
	return &Provider{pool: pool, overlay: overlay, config: config}, nil
}

func (p *Provider) Publish(ctx context.Context, challenge acmeworker.ChallengeIdentity) error {
	return p.mutate(ctx, challenge, true)
}

func (p *Provider) Delete(ctx context.Context, challenge acmeworker.ChallengeIdentity) error {
	return p.mutate(ctx, challenge, false)
}

func (p *Provider) mutate(ctx context.Context, challenge acmeworker.ChallengeIdentity, add bool) error {
	domain, err := normalizeChallenge(challenge)
	if err != nil || ctx == nil {
		return ErrInvalidChallenge
	}
	now := p.config.Clock().UTC().Truncate(time.Microsecond)
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	siteID, revision, err := lockSiteOverlay(ctx, tx, challenge.TenantID, domain, now)
	if err != nil {
		return err
	}
	references, nodes, err := loadCurrentOverlay(ctx, tx, challenge.TenantID, siteID, revision)
	if err != nil {
		return err
	}
	reference := acmeedge.ChallengeReference{OperationID: challenge.OperationID, AttemptID: challenge.AttemptID}
	found := false
	for _, current := range references {
		if current == reference {
			found = true
			break
		}
	}
	if add == found {
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		if revision == 0 {
			return nil
		}
		effective, err := p.latestHealthySatisfies(ctx, challenge.TenantID, siteID, reference, add)
		if err != nil {
			return err
		}
		if effective {
			return nil
		}
		return p.awaitHealthy(ctx, challenge.TenantID, siteID, revision)
	}
	if add {
		references = append(references, reference)
		if revision == 0 {
			nodes, err = p.resolveInitialTargets(ctx, tx, challenge.TenantID)
			if err != nil {
				return err
			}
		}
	} else {
		filtered := references[:0]
		for _, current := range references {
			if current != reference {
				filtered = append(filtered, current)
			}
		}
		references = filtered
	}
	action := "cleanup"
	mode := acmeedge.ModeCleanup
	if add {
		action = "publish"
		mode = acmeedge.ModeApply
	}
	requestID := uuid.NewSHA1(challenge.AttemptID, []byte(fmt.Sprintf("acme-http01/%s/%d", action, revision+1)))
	request := acmeedge.PublishRequest{
		Mode: mode, TenantScopeID: challenge.TenantID, SiteID: siteID,
		ExpectedRevision: revision, Challenges: references, MaxAttempts: p.config.MaxAttempts,
		Deadline:       now.Add(p.config.ChallengeLifetime),
		IdempotencyKey: fmt.Sprintf("http01-%s-%s-r%d", action, challenge.AttemptID.String(), revision+1),
		RequestID:      requestID.String(),
	}
	if add {
		request.NodeIDs = nodes
	}
	publication, err := p.overlay.PublishSnapshotTx(ctx, tx, request)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return p.awaitHealthy(ctx, publication.TenantScopeID, publication.SiteID, publication.Revision)
}

func (p *Provider) awaitHealthy(ctx context.Context, tenantScopeID, siteID uuid.UUID, revision int64) error {
	health, err := p.overlay.AwaitHealthy(ctx, tenantScopeID, siteID, revision, p.config.HealthPoll)
	if err != nil {
		return err
	}
	if !health.Healthy {
		return fmt.Errorf("ACME HTTP-01 overlay revision failed")
	}
	return nil
}

func (p *Provider) latestHealthySatisfies(
	ctx context.Context,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	reference acmeedge.ChallengeReference,
	wantPresent bool,
) (bool, error) {
	latest, err := p.overlay.LatestHealthy(ctx, tenantScopeID, siteID)
	if errors.Is(err, acmeedge.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var present bool
	err = p.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM acme_http01_overlay_token_facts
			WHERE version_id=$1 AND operation_id=$2 AND challenge_attempt_id=$3
		)`, latest.VersionID, reference.OperationID, reference.AttemptID).Scan(&present)
	if err != nil {
		return false, err
	}
	return present == wantPresent, nil
}

func normalizeChallenge(challenge acmeworker.ChallengeIdentity) (string, error) {
	if challenge.TenantID == uuid.Nil || challenge.OperationID == "" || challenge.AttemptID == uuid.Nil ||
		challenge.ProviderRef != "" || challenge.ChallengeType != acmeworker.ChallengeHTTP01 || challenge.Wildcard ||
		challenge.Identifier == "" || challenge.Identifier != strings.TrimSpace(challenge.Identifier) {
		return "", ErrInvalidChallenge
	}
	domain, err := idna.Lookup.ToASCII(challenge.Identifier)
	if err != nil || domain == "" || len(domain) > 253 || strings.HasSuffix(domain, ".") {
		return "", ErrInvalidChallenge
	}
	return strings.ToLower(domain), nil
}

func lockSiteOverlay(ctx context.Context, tx pgx.Tx, tenantScopeID uuid.UUID, domain string, now time.Time) (uuid.UUID, int64, error) {
	var siteID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id FROM sites
		WHERE scope_id=$1 AND lower(domain)=$2 AND deleted_at IS NULL
		  AND enabled=true AND status='active'`, tenantScopeID, domain).Scan(&siteID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, 0, ErrInvalidChallenge
	}
	if err != nil {
		return uuid.Nil, 0, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO acme_http01_overlay_states(
			tenant_scope_id,site_id,current_revision,created_at,updated_at
		) VALUES($1,$2,0,$3,$3)
		ON CONFLICT (tenant_scope_id,site_id) DO NOTHING`, tenantScopeID, siteID, now); err != nil {
		return uuid.Nil, 0, err
	}
	var revision int64
	if err := tx.QueryRow(ctx, `
		SELECT current_revision FROM acme_http01_overlay_states
		WHERE tenant_scope_id=$1 AND site_id=$2 FOR UPDATE`, tenantScopeID, siteID).Scan(&revision); err != nil {
		return uuid.Nil, 0, err
	}
	return siteID, revision, nil
}

func loadCurrentOverlay(ctx context.Context, tx pgx.Tx, tenantScopeID, siteID uuid.UUID, revision int64) ([]acmeedge.ChallengeReference, []uuid.UUID, error) {
	if revision == 0 {
		return nil, nil, nil
	}
	var versionID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id FROM acme_http01_overlay_versions
		WHERE tenant_scope_id=$1 AND site_id=$2 AND revision=$3`, tenantScopeID, siteID, revision).Scan(&versionID); err != nil {
		return nil, nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT operation_id,challenge_attempt_id
		FROM acme_http01_overlay_token_facts
		WHERE version_id=$1 ORDER BY operation_id,challenge_attempt_id`, versionID)
	if err != nil {
		return nil, nil, err
	}
	var references []acmeedge.ChallengeReference
	for rows.Next() {
		var value acmeedge.ChallengeReference
		if err := rows.Scan(&value.OperationID, &value.AttemptID); err != nil {
			rows.Close()
			return nil, nil, err
		}
		references = append(references, value)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	rows.Close()
	nodeRows, err := tx.Query(ctx, `
		SELECT node_id FROM acme_http01_overlay_targets
		WHERE version_id=$1 ORDER BY node_id`, versionID)
	if err != nil {
		return nil, nil, err
	}
	defer nodeRows.Close()
	var nodes []uuid.UUID
	for nodeRows.Next() {
		var nodeID uuid.UUID
		if err := nodeRows.Scan(&nodeID); err != nil {
			return nil, nil, err
		}
		nodes = append(nodes, nodeID)
	}
	return references, nodes, nodeRows.Err()
}

func (p *Provider) resolveInitialTargets(ctx context.Context, tx pgx.Tx, tenantScopeID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `
		SELECT node.id
		FROM nodes node
		JOIN node_config_state state ON state.node_id=node.id
		WHERE node.admin_state='active'
		  AND state.configuration_scope_id=$1 AND state.current_config_version_id IS NOT NULL
		ORDER BY node.id
		LIMIT $2`, tenantScopeID, p.config.MaxTargets+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []uuid.UUID
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			return nil, err
		}
		nodes = append(nodes, nodeID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(nodes) == 0 || len(nodes) > p.config.MaxTargets {
		return nil, ErrNoTarget
	}
	return nodes, nil
}
