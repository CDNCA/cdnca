package nodednspupprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Errors are the plugin's, so its handler maps them (dnspupprobe.writeServiceError).
var (
	ErrUnauthenticated  = dnspupprobe.ErrUnauthenticated
	ErrPermissionDenied = dnspupprobe.ErrPermissionDenied
	ErrIdempotency      = dnspupprobe.ErrIdempotency
)

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// ReadSettings reads the settings row and the budget state.
func ReadSettings(ctx context.Context, db queryRower) (Settings, string, error) {
	var value Settings
	var budget string
	err := db.QueryRow(ctx, `SELECT interval_seconds,groups,points_per_group,failure_percent,failure_rounds,
		recovery_rounds,low_balance,budget_state FROM node_dnspup_probe_settings WHERE singleton`).Scan(
		&value.IntervalSeconds, &value.Groups, &value.PointsPerGroup, &value.FailurePercent, &value.FailureRounds,
		&value.RecoveryRounds, &value.LowBalance, &budget)
	return value, budget, err
}

// Actor is the authenticated platform administrator of a write.
type Actor = dnspupprobe.Actor

// Status is the settings page view.
type Status struct {
	Settings
	Revision int64 `json:"revision"`
	// Plugin is installed (module in the lease), enabled and has a key pair.
	PluginActive bool   `json:"plugin_active"`
	Licensed     bool   `json:"licensed"`
	BudgetState  string `json:"budget_state"`
	// EffectiveIntervalSeconds after the budget (0: no dnspup probing).
	EffectiveIntervalSeconds int        `json:"effective_interval_seconds"`
	MonthlyLimit             int64      `json:"monthly_limit"`
	MonthlyUsed              int64      `json:"monthly_used"`
	AccountCheckedAt         *time.Time `json:"account_checked_at"`
	PausedUntil              *time.Time `json:"paused_until"`
	// BalanceUnit: dnspup meters requests (one per probed address and
	// round, any checkpoint count); there is no points balance API.
	BalanceUnit string     `json:"balance_unit"`
	Estimate    Estimation `json:"estimate"`
	// MaxAddressesPerRound: more addresses rotate across rounds.
	MaxAddressesPerRound int `json:"max_addresses_per_round"`
}

// Store serves the settings page.
type Store struct {
	pool     *pgxpool.Pool
	features dnspupprobe.FeatureReader
	auditor  *audit.Log
	now      func() time.Time
}

func NewStore(pool *pgxpool.Pool, features dnspupprobe.FeatureReader, now func() time.Time) (*Store, error) {
	if pool == nil || features == nil {
		return nil, ErrInvalidSettings
	}
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, features: features, auditor: audit.NewWithClock(pool, now), now: now}, nil
}

func (store *Store) clock() time.Time { return store.now().UTC().Truncate(time.Second) }

// Status reads the page view (dnspup manage permission).
func (store *Store) Status(ctx context.Context, actor Actor) (Status, error) {
	var status Status
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, store.clock()); err != nil {
			return err
		}
		var err error
		status, err = store.readStatus(ctx, tx)
		return err
	})
	return status, err
}

func (store *Store) readStatus(ctx context.Context, tx pgx.Tx) (Status, error) {
	var status Status
	var enabled, secret bool
	if err := tx.QueryRow(ctx, `SELECT node.interval_seconds,node.groups,node.points_per_group,node.failure_percent,
			node.failure_rounds,node.recovery_rounds,node.low_balance,node.budget_state,node.revision,
			plugin.enabled,plugin.secret_ciphertext IS NOT NULL,state.monthly_limit,state.monthly_used,
			state.account_checked_at,CASE WHEN state.paused_until>$1 THEN state.paused_until END
		FROM node_dnspup_probe_settings node,probe_dnspup_settings plugin,probe_dnspup_state state
		WHERE node.singleton AND plugin.singleton AND state.singleton`, store.clock()).Scan(&status.IntervalSeconds,
		&status.Groups, &status.PointsPerGroup, &status.FailurePercent, &status.FailureRounds, &status.RecoveryRounds,
		&status.LowBalance, &status.BudgetState, &status.Revision, &enabled, &secret, &status.MonthlyLimit,
		&status.MonthlyUsed, &status.AccountCheckedAt, &status.PausedUntil); err != nil {
		return Status{}, err
	}
	features, err := store.features.ReadValidFeatures(ctx, tx)
	if err != nil {
		return Status{}, err
	}
	status.Licensed = features[dnspupprobe.Feature]
	status.PluginActive = status.Licensed && enabled && secret && status.PausedUntil == nil
	status.EffectiveIntervalSeconds = int(EffectiveInterval(status.Settings, status.BudgetState) / time.Second)
	status.BalanceUnit = "request"
	status.MaxAddressesPerRound = MaxAddressesPerRound
	var addresses int
	if err := tx.QueryRow(ctx, `SELECT count(DISTINCT (published.node_id,published.address))
		FROM node_line_endpoint_published published
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=published.tenant_scope_id
		 AND line_group.id=published.line_group_id AND line_group.current_revision=published.config_revision
		 AND line_group.deleted_at IS NULL
		JOIN nodes node ON node.id=published.node_id AND node.admin_state IN ('active','draining')
		WHERE published.node_id IS NOT NULL`).Scan(&addresses); err != nil {
		return Status{}, err
	}
	status.Estimate = Estimate(status.Settings, addresses)
	return status, nil
}

// NodeProbeStatus serves GET /v1/admin/probe-dnspup/node-monitoring.
func (store *Store) NodeProbeStatus(ctx context.Context, actor Actor) (any, error) {
	return store.Status(ctx, actor)
}

// UpdateNodeProbe serves PUT /v1/admin/probe-dnspup/node-monitoring (every
// field required, unknown fields refused).
func (store *Store) UpdateNodeProbe(ctx context.Context, actor Actor, key string, body []byte) (any, error) {
	var input struct {
		IntervalSeconds *int     `json:"interval_seconds"`
		Groups          []string `json:"groups"`
		PointsPerGroup  *int     `json:"points_per_group"`
		FailurePercent  *int     `json:"failure_percent"`
		FailureRounds   *int     `json:"failure_rounds"`
		RecoveryRounds  *int     `json:"recovery_rounds"`
		LowBalance      *int64   `json:"low_balance"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input.IntervalSeconds == nil || input.Groups == nil ||
		input.PointsPerGroup == nil || input.FailurePercent == nil || input.FailureRounds == nil ||
		input.RecoveryRounds == nil || input.LowBalance == nil {
		return nil, ErrInvalidSettings
	}
	return store.Update(ctx, actor, key, Settings{IntervalSeconds: *input.IntervalSeconds, Groups: input.Groups,
		PointsPerGroup: *input.PointsPerGroup, FailurePercent: *input.FailurePercent, FailureRounds: *input.FailureRounds,
		RecoveryRounds: *input.RecoveryRounds, LowBalance: *input.LowBalance})
}

// Update saves the settings (idempotent per session + key) and audits the
// change.
func (store *Store) Update(ctx context.Context, actor Actor, key string, input Settings) (Status, error) {
	status, err := store.update(ctx, actor, key, input)
	if err != nil && !errors.Is(err, ErrUnauthenticated) && actor.ScopeID != uuid.Nil {
		reason := "internal_error"
		switch {
		case errors.Is(err, ErrPermissionDenied):
			reason = "permission_denied"
		case errors.Is(err, ErrInvalidSettings):
			reason = "invalid_input"
		case errors.Is(err, ErrIdempotency):
			reason = "idempotency_conflict"
		}
		ctx = context.WithoutCancel(ctx)
		_ = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
			return store.appendAudit(ctx, tx, actor, "failure", map[string]any{"reason_code": reason})
		})
	}
	return status, err
}

func (store *Store) update(ctx context.Context, actor Actor, key string, input Settings) (Status, error) {
	if !validKey(key) {
		return Status{}, ErrInvalidSettings
	}
	input.Groups = sortedGroups(input.Groups)
	if err := Validate(input); err != nil {
		return Status{}, err
	}
	encoded, _ := json.Marshal([]any{"node_settings", input})
	digest := sha256.Sum256(encoded)
	now := store.clock()
	var body []byte
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, now); err != nil {
			return err
		}
		var storedDigest []byte
		err := tx.QueryRow(ctx, `SELECT request_digest_sha256,response_body FROM probe_dnspup_write_requests
			WHERE actor_session_id=$1 AND idempotency_key=$2`, actor.SessionID, key).Scan(&storedDigest, &body)
		switch {
		case err == nil && !bytes.Equal(storedDigest, digest[:]):
			return ErrIdempotency
		case err == nil:
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		before, _, err := ReadSettings(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE node_dnspup_probe_settings SET interval_seconds=$1,groups=$2,points_per_group=$3,
			failure_percent=$4,failure_rounds=$5,recovery_rounds=$6,low_balance=$7,revision=revision+1,
			updated_by_user_id=$8,updated_at=$9 WHERE singleton`, input.IntervalSeconds, input.Groups, input.PointsPerGroup,
			input.FailurePercent, input.FailureRounds, input.RecoveryRounds, input.LowBalance, actor.UserID, now); err != nil {
			return err
		}
		changes := map[string]any{}
		add := func(name string, before, after any) {
			left, _ := json.Marshal(before)
			right, _ := json.Marshal(after)
			if !bytes.Equal(left, right) {
				changes[name] = map[string]any{"before": before, "after": after}
			}
		}
		add("interval_seconds", before.IntervalSeconds, input.IntervalSeconds)
		add("groups", before.Groups, input.Groups)
		add("points_per_group", before.PointsPerGroup, input.PointsPerGroup)
		add("failure_percent", before.FailurePercent, input.FailurePercent)
		add("failure_rounds", before.FailureRounds, input.FailureRounds)
		add("recovery_rounds", before.RecoveryRounds, input.RecoveryRounds)
		add("low_balance", before.LowBalance, input.LowBalance)
		if err := store.appendAudit(ctx, tx, actor, "success", map[string]any{"changes": changes}); err != nil {
			return err
		}
		status, err := store.readStatus(ctx, tx)
		if err != nil {
			return err
		}
		if body, err = json.Marshal(status); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO probe_dnspup_write_requests(actor_session_id,idempotency_key,operation,
			request_digest_sha256,response_body,created_at) VALUES($1,$2,'node_settings',$3,$4,$5)`,
			actor.SessionID, key, digest[:], body, now)
		return err
	})
	if err != nil {
		return Status{}, err
	}
	var status Status
	return status, json.Unmarshal(body, &status)
}

func (store *Store) appendAudit(ctx context.Context, tx pgx.Tx, actor Actor, result string, payload map[string]any) error {
	payload["ip"] = actor.IP
	return store.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
		Action: ActionNodeSettings, ResourceType: "probe_dnspup", ResourceID: "probe_dnspup",
		RequestID: ActionNodeSettings + "." + uuid.NewString(), Result: result, Payload: payload})
}

func authenticate(ctx context.Context, tx pgx.Tx, actor Actor, now time.Time) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.SessionID == uuid.Nil {
		return ErrUnauthenticated
	}
	var authenticated, permitted bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth_sessions session
		JOIN users account ON account.id=session.user_id AND account.status='active'
		JOIN memberships membership ON membership.scope_id=session.scope_id AND membership.user_id=session.user_id AND membership.status='active'
		JOIN access_scopes scope ON scope.id=session.scope_id AND scope.kind='platform'
		WHERE session.id=$1 AND session.scope_id=$2 AND session.user_id=$3 AND session.revoked_at IS NULL
		AND session.replaced_by_id IS NULL AND session.expires_at>$4),
		EXISTS(SELECT 1 FROM role_assignments assignment JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id
		WHERE assignment.scope_id=$2 AND assignment.user_id=$3 AND grant_row.permission_name IN ($5,'platform.admin'))`,
		actor.SessionID, actor.ScopeID, actor.UserID, now, dnspupprobe.PermissionManage).Scan(&authenticated, &permitted)
	if err != nil {
		return err
	}
	if !authenticated {
		return ErrUnauthenticated
	}
	if !permitted {
		return ErrPermissionDenied
	}
	return nil
}

func validKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for index, r := range key {
		alnum := r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if !alnum && (index == 0 || r != '.' && r != '_' && r != '-') {
			return false
		}
	}
	return true
}
