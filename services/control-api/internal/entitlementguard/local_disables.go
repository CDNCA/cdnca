package entitlementguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Local stop list (migration 644): the platform
// administrator stops a plugin on this controller, which takes its feature
// code out of the lease's grant here for every tenant. The lease, the licence
// and billing are untouched; enabling it again restores the grant. Every read
// the guard answers subtracts the list: ReadValidFeatures, GrantedModules and
// CheckFeature (feature_locally_disabled). Only plugin codes (module.*,
// pack.*, theme.*) can be stopped.

const (
	// ReasonLocallyDisabled is the entitlement.guard.reject reason of a code
	// the lease grants and this controller stopped.
	ReasonLocallyDisabled = "feature_locally_disabled"
	LocalDisableAction    = "plugin.local.disable"
	LocalEnableAction     = "plugin.local.enable"
)

var (
	ErrLocalDisableInvalid     = errors.New("invalid plugin local disable")
	ErrLocalDisableIdempotency = errors.New("plugin local disable idempotency key reused with another request")
)

var localPluginIDPattern = regexp.MustCompile(`^[a-z0-9]+([.-][a-z0-9]+)+$`)

type rowQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// LocallyDisabledCodes is the set of plugin feature codes this controller
// stopped.
func LocallyDisabledCodes(ctx context.Context, q rowQuerier) (map[string]bool, error) {
	rows, err := q.Query(ctx, `SELECT feature_code FROM plugin_local_disables`)
	if err != nil {
		return nil, fmt.Errorf("read plugin local disables: %w", err)
	}
	codes, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("read plugin local disables: %w", err)
	}
	set := make(map[string]bool, len(codes))
	for _, code := range codes {
		set[code] = true
	}
	return set, nil
}

// LocalDisable is one plugin's local state. Disabled false: not stopped here
// (the other fields are empty).
type LocalDisable struct {
	PluginID    string     `json:"plugin_id"`
	FeatureCode string     `json:"feature_code"`
	Disabled    bool       `json:"locally_disabled"`
	DisabledBy  *uuid.UUID `json:"disabled_by,omitempty"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty"`
}

type LocalDisableInput struct {
	PluginID    string `json:"plugin_id"`
	FeatureCode string `json:"feature_code"`
}

// LocalDisableActor is the platform administrator making the change.
type LocalDisableActor struct {
	UserID  uuid.UUID
	ScopeID uuid.UUID
	IP      string
}

// LocalDisableChange runs in the write's transaction with the codes whose
// grant changed (production: the system republication of the scopes whose
// sites mount a pack needing one of them).
type LocalDisableChange func(ctx context.Context, tx pgx.Tx, codes []string) error

type LocalDisableStore struct {
	pool    *pgxpool.Pool
	now     func() time.Time
	changed LocalDisableChange
	auditor *audit.Log
}

func NewLocalDisableStore(pool *pgxpool.Pool, now func() time.Time, changed LocalDisableChange) *LocalDisableStore {
	if now == nil {
		now = time.Now
	}
	return &LocalDisableStore{pool: pool, now: now, changed: changed, auditor: audit.New(pool)}
}

// List is every plugin stopped here, by plugin ID.
func (s *LocalDisableStore) List(ctx context.Context) ([]LocalDisable, error) {
	rows, err := s.pool.Query(ctx, `SELECT plugin_id,feature_code,disabled_by_user_id,disabled_at
		FROM plugin_local_disables ORDER BY plugin_id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (LocalDisable, error) {
		item := LocalDisable{Disabled: true}
		var by uuid.UUID
		var at time.Time
		err := row.Scan(&item.PluginID, &item.FeatureCode, &by, &at)
		item.DisabledBy, item.DisabledAt = &by, &at
		return item, err
	})
}

// Disable stops input.PluginID here. A plugin already stopped keeps its first
// stop (same answer, nothing written).
func (s *LocalDisableStore) Disable(ctx context.Context, actor LocalDisableActor, key string, input LocalDisableInput) (LocalDisable, error) {
	if _, _, ok := entitlement.ParseModuleFeatureCode(input.FeatureCode); !ok || !validLocalPluginID(input.PluginID) {
		return LocalDisable{}, ErrLocalDisableInvalid
	}
	return s.write(ctx, actor, key, "disable", input, func(tx pgx.Tx) (LocalDisable, bool, error) {
		if current, found, err := readLocalDisable(ctx, tx, input.PluginID); err != nil || found {
			return current, false, err
		}
		now := s.now().UTC()
		_, err := tx.Exec(ctx, `INSERT INTO plugin_local_disables(plugin_id,feature_code,disabled_by_user_id,disabled_at)
			VALUES($1,$2,$3,$4)`, input.PluginID, input.FeatureCode, actor.UserID, now)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return LocalDisable{}, false, ErrLocalDisableInvalid // the code is stopped under another plugin
		}
		if err != nil {
			return LocalDisable{}, false, err
		}
		by := actor.UserID
		return LocalDisable{PluginID: input.PluginID, FeatureCode: input.FeatureCode, Disabled: true, DisabledBy: &by,
			DisabledAt: &now}, true, nil
	})
}

// Enable lifts the stop of pluginID. A plugin not stopped answers its state.
func (s *LocalDisableStore) Enable(ctx context.Context, actor LocalDisableActor, key, pluginID string) (LocalDisable, error) {
	if !validLocalPluginID(pluginID) {
		return LocalDisable{}, ErrLocalDisableInvalid
	}
	return s.write(ctx, actor, key, "enable", LocalDisableInput{PluginID: pluginID}, func(tx pgx.Tx) (LocalDisable, bool, error) {
		var code string
		err := tx.QueryRow(ctx, `DELETE FROM plugin_local_disables WHERE plugin_id=$1 RETURNING feature_code`, pluginID).Scan(&code)
		if errors.Is(err, pgx.ErrNoRows) {
			return LocalDisable{PluginID: pluginID}, false, nil
		}
		return LocalDisable{PluginID: pluginID, FeatureCode: code}, err == nil, err
	})
}

func validLocalPluginID(id string) bool {
	return len(id) >= 3 && len(id) <= 128 && localPluginIDPattern.MatchString(id)
}

func readLocalDisable(ctx context.Context, tx pgx.Tx, pluginID string) (LocalDisable, bool, error) {
	item := LocalDisable{PluginID: pluginID, Disabled: true}
	var by uuid.UUID
	var at time.Time
	err := tx.QueryRow(ctx, `SELECT feature_code,disabled_by_user_id,disabled_at FROM plugin_local_disables
		WHERE plugin_id=$1 FOR UPDATE`, pluginID).Scan(&item.FeatureCode, &by, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return LocalDisable{}, false, nil
	}
	item.DisabledBy, item.DisabledAt = &by, &at
	return item, err == nil, err
}

// write runs apply once per (actor, key): a replay returns the stored answer,
// another body under the same key ErrLocalDisableIdempotency. A change is
// audited and passed to the change hook in the same transaction.
func (s *LocalDisableStore) write(ctx context.Context, actor LocalDisableActor, key, operation string, input LocalDisableInput,
	apply func(pgx.Tx) (LocalDisable, bool, error)) (LocalDisable, error) {
	if key == "" || len(key) > 128 || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil {
		return LocalDisable{}, ErrLocalDisableInvalid
	}
	digest := sha256.Sum256([]byte(operation + "\x00" + input.PluginID + "\x00" + input.FeatureCode))
	var result LocalDisable
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// One writer per (actor, key): a concurrent retry waits and then replays.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,644))`,
			actor.UserID.String()+"|"+key); err != nil {
			return err
		}
		var stored, body []byte
		err := tx.QueryRow(ctx, `SELECT request_digest_sha256,response_body FROM plugin_local_disable_requests
			WHERE actor_user_id=$1 AND idempotency_key=$2`, actor.UserID, key).Scan(&stored, &body)
		if err == nil {
			if !bytes.Equal(stored, digest[:]) {
				return ErrLocalDisableIdempotency
			}
			return json.Unmarshal(body, &result)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		item, changed, err := apply(tx)
		if err != nil {
			return err
		}
		result = item
		if changed {
			action := LocalDisableAction
			if operation == "enable" {
				action = LocalEnableAction
			}
			payload := map[string]any{"actor": actor.UserID.String(), "scope": "platform", "ip": actor.IP,
				"object_type": "plugin", "object_id": item.PluginID, "plugin_id": item.PluginID, "feature_code": item.FeatureCode}
			user := actor.UserID
			if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &user, Action: action,
				ResourceType: "plugin", ResourceID: item.PluginID, RequestID: "plugin-local-" + key, Result: "success",
				SourceIP: actor.IP, Payload: payload,
				Changes: []audit.Change{{Field: "locally_disabled", Before: operation == "enable", After: operation == "disable"}},
			}); err != nil {
				return err
			}
			if s.changed != nil {
				if err := s.changed(ctx, tx, []string{item.FeatureCode}); err != nil {
					return err
				}
			}
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO plugin_local_disable_requests(actor_user_id,idempotency_key,operation,
			request_digest_sha256,response_body,created_at) VALUES($1,$2,$3,$4,$5,$6)`,
			actor.UserID, key, operation, digest[:], encoded, s.now().UTC())
		return err
	})
	return result, err
}
