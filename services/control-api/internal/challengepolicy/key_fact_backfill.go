package challengepolicy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BackfillKeyFacts gives every enabled policy that predates the key fact
// writer its current-revision HMAC key fact. A
// migration cannot do it because the KEK is not available there, so
// control-api runs it once after startup. It writes through the same
// KeyFactIssuer path as Create/Update, so an earlier revision's secret is
// carried over. It is idempotent (policies that already have the fact are
// not selected, and IssueTx leaves an existing revision alone), takes a
// per-tenant advisory lock plus the policy row lock, and records a failure
// per policy in the log without stopping the others. It returns the number
// of policies that got a fact and the number that failed.
func BackfillKeyFacts(ctx context.Context, pool *pgxpool.Pool, issuer KeyFactIssuer, logger *slog.Logger) (issued, failed int, err error) {
	if isNilDependency(pool) || isNilDependency(issuer) {
		return 0, 0, ErrInvalidStoreConfig
	}
	if logger == nil {
		logger = slog.Default()
	}
	rows, err := pool.Query(ctx, `
		SELECT policy.tenant_scope_id, policy.id
		FROM challenge_policies policy
		WHERE policy.deleted_at IS NULL AND policy.current_enabled AND NOT EXISTS (
			SELECT 1 FROM challenge_key_facts_138 fact
			WHERE fact.policy_id = policy.id AND fact.policy_revision = policy.current_revision
			  AND fact.role = 'current' AND fact.active)
		ORDER BY policy.tenant_scope_id, policy.created_at, policy.id`)
	if err != nil {
		return 0, 0, err
	}
	type candidate struct{ scopeID, policyID uuid.UUID }
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.scopeID, &item.policyID); err != nil {
			rows.Close()
			return 0, 0, err
		}
		candidates = append(candidates, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	store := &Store{keyFacts: issuer}
	for _, item := range candidates {
		if ctx.Err() != nil {
			return issued, failed, ctx.Err()
		}
		wrote, err := backfillPolicyKeyFact(ctx, pool, store, item.scopeID, item.policyID)
		switch {
		case err != nil:
			failed++
			logger.Error("challenge policy key fact backfill failed",
				"tenant_scope_id", item.scopeID, "policy_id", item.policyID, "error", err)
		case wrote:
			issued++
		}
	}
	logger.Info("challenge policy key fact backfill finished",
		"candidates", len(candidates), "issued", issued, "failed", failed)
	return issued, failed, nil
}

func backfillPolicyKeyFact(ctx context.Context, pool *pgxpool.Pool, store *Store, scopeID, policyID uuid.UUID) (bool, error) {
	wrote := false
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			fmt.Sprintf("challenge-key-fact-backfill:%s", scopeID)); err != nil {
			return err
		}
		item, err := lockPolicy(ctx, tx, scopeID, policyID)
		if err != nil {
			if err == ErrNotFound {
				return nil // deleted since the scan
			}
			return err
		}
		if !item.Enabled || item.Deleted {
			return nil
		}
		// The fact records who wrote it and the writer requires an active
		// membership: prefer the policy's creator, else any active member.
		var actor Actor
		actor.ScopeID = scopeID
		if err := tx.QueryRow(ctx, `
			SELECT user_id FROM memberships WHERE scope_id = $1 AND status = 'active'
			ORDER BY (user_id = $2) DESC, user_id LIMIT 1`, scopeID, item.CreatedByUserID).Scan(&actor.UserID); err != nil {
			return fmt.Errorf("no active member to attribute the key fact to: %w", err)
		}
		if err := store.issueKeyFact(ctx, tx, actor, item); err != nil {
			return err
		}
		wrote = true
		return nil
	})
	return wrote, err
}
