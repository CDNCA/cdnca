package domaintrust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ValidMetadata checks idempotency keys and request IDs.
func ValidMetadata(value string) bool { return metadataPattern.MatchString(value) }

type Querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// BlockedDomain returns the first canonical domain the platform blocklist
// covers. A root pattern covers the name and every subdomain (a wildcard is
// covered when its base is); an exact pattern covers that host name only.
func BlockedDomain(ctx context.Context, query Querier, domains []string) (string, bool, error) {
	if len(domains) == 0 {
		return "", false, nil
	}
	roots := make([]string, 0, len(domains)*3)
	exacts := make([]string, 0, len(domains))
	for _, domain := range domains {
		roots = append(roots, suffixes(strings.TrimPrefix(domain, "*."))...)
		if !IsWildcard(domain) {
			exacts = append(exacts, domain)
		}
	}
	rows, err := query.Query(ctx, `SELECT pattern,match_type FROM platform_domain_blocklist
		WHERE (match_type='root' AND pattern=ANY($1::text[])) OR (match_type='exact' AND pattern=ANY($2::text[]))`,
		roots, exacts)
	if err != nil {
		return "", false, fmt.Errorf("match domain blocklist: %w", err)
	}
	defer rows.Close()
	rootSet, exactSet := map[string]struct{}{}, map[string]struct{}{}
	for rows.Next() {
		var pattern, matchType string
		if err := rows.Scan(&pattern, &matchType); err != nil {
			return "", false, err
		}
		if matchType == "root" {
			rootSet[pattern] = struct{}{}
		} else {
			exactSet[pattern] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	for _, domain := range domains {
		if _, hit := exactSet[domain]; hit && !IsWildcard(domain) {
			return domain, true, nil
		}
		for _, suffix := range suffixes(strings.TrimPrefix(domain, "*.")) {
			if _, hit := rootSet[suffix]; hit {
				return domain, true, nil
			}
		}
	}
	return "", false, nil
}

// ReadPolicy returns the platform ownership policy stored in the other
// settings document; a missing row or key keeps the default.
func ReadPolicy(ctx context.Context, query Querier) (Policy, error) {
	var raw *string
	err := query.QueryRow(ctx, `SELECT settings.settings->>'domain_ownership_policy'
		FROM platform_system_other_settings settings
		JOIN access_scopes scope ON scope.id=settings.platform_scope_id AND scope.kind='platform' AND scope.tenant_id IS NULL
		ORDER BY settings.updated_at DESC LIMIT 1`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && raw == nil {
		return DefaultPolicy, nil
	}
	if err != nil {
		return "", fmt.Errorf("read domain ownership policy: %w", err)
	}
	if !ValidPolicy(*raw) {
		return "", fmt.Errorf("%w: stored domain ownership policy %q", ErrInvalidInput, *raw)
	}
	return Policy(*raw), nil
}

// Write is one idempotent mutation in domain_trust_write_requests.
type Write struct {
	ActorUserID, ActorScopeID uuid.UUID
	Operation, Key            string
	Digest                    [32]byte
}

// Digest hashes the canonical JSON of a request.
func Digest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// ClaimWrite records the request or, when the key was already completed with
// the same input, decodes the stored response into replay and returns true.
func ClaimWrite(ctx context.Context, tx pgx.Tx, write Write, now time.Time, replay any) (bool, error) {
	if write.ActorUserID == uuid.Nil || write.ActorScopeID == uuid.Nil || !ValidMetadata(write.Key) {
		return false, ErrInvalidInput
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('domain-trust-write:' || $1::text || ':' || $2 || ':' || $3,0))`,
		write.ActorUserID, write.Operation, write.Key); err != nil {
		return false, err
	}
	var digest, body []byte
	err := tx.QueryRow(ctx, `SELECT request_digest,response_body FROM domain_trust_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`,
		write.ActorUserID, write.Operation, write.Key).Scan(&digest, &body)
	if err == nil {
		if !bytes.Equal(digest, write.Digest[:]) || len(body) == 0 {
			return false, ErrIdempotencyConflict
		}
		if err := json.Unmarshal(body, replay); err != nil {
			return false, fmt.Errorf("decode stored domain trust response: %w", err)
		}
		return true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO domain_trust_write_requests(
		id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.New(), write.ActorUserID, write.ActorScopeID, write.Operation,
		write.Key, write.Digest[:], now)
	return false, err
}

// CompleteWrite stores the response a replay of the same request returns.
func CompleteWrite(ctx context.Context, tx pgx.Tx, write Write, status int, response any, now time.Time) error {
	body, err := json.Marshal(response)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE domain_trust_write_requests SET response_status=$4,response_body=$5,completed_at=$6
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`,
		write.ActorUserID, write.Operation, write.Key, status, body, now)
	return err
}
