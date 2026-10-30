package nodeserving

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Line group backup IP alerts (fix-backupnotify, migration 571). Whether a
// line group publishes standby IPs is computed by node_line_endpoint_published
// (migration 501, per carrier and address family); node_line_group_backup_states
// keeps the last observed state per line group and address family so a change
// is announced once. Online means serving and not held by a system serving
// hold, so the hold sources' consecutive-count thresholds already debounce it.
const (
	EventTypeLineBackupActivated = notification.EventTypeLineBackupActivated
	EventTypeLineBackupRestored  = notification.EventTypeLineBackupRestored

	LineBackupNormal = "normal"
	LineBackupActive = "backup_active"

	lineBackupSourcePrefix = "node-line-backup/"
	maxLineBackupAddresses = 512
	lineBackupAddressShown = 5
)

// LineBackupKey is one line group address family.
type LineBackupKey struct {
	ScopeID uuid.UUID
	GroupID uuid.UUID
	Family  int
}

// LineBackupState is the stored state; Found is false before the first change.
type LineBackupState struct {
	Found    bool
	State    string
	Sequence int64
}

// LineBackupObservation is the current revision's view: Present is false when
// the line group is deleted or the family no longer has endpoints; Backups
// are the standby IPs that are online and published now.
type LineBackupObservation struct {
	Present  bool
	Revision int64
	Backups  []string
}

// LineBackupDecision is the state write, if any, and the alert it sends.
type LineBackupDecision struct {
	Write     bool
	State     string
	Sequence  int64
	EventType string
}

// DecideLineBackup compares the stored state with the observation. A family
// never seen in backup stays without a row; a family that disappeared while
// in backup goes back to normal silently (nobody's primary came back).
func DecideLineBackup(current LineBackupState, observed LineBackupObservation) LineBackupDecision {
	active := current.Found && current.State == LineBackupActive
	next := current.Sequence + 1
	switch {
	case observed.Present && len(observed.Backups) > 0 && !active:
		return LineBackupDecision{Write: true, State: LineBackupActive, Sequence: next, EventType: EventTypeLineBackupActivated}
	case observed.Present && len(observed.Backups) == 0 && active:
		return LineBackupDecision{Write: true, State: LineBackupNormal, Sequence: next, EventType: EventTypeLineBackupRestored}
	case !observed.Present && active:
		return LineBackupDecision{Write: true, State: LineBackupNormal, Sequence: next}
	default:
		return LineBackupDecision{}
	}
}

func lineBackupSourceEventID(eventType string, groupID uuid.UUID, family int, sequence int64) string {
	kind := "activated"
	if eventType == EventTypeLineBackupRestored {
		kind = "restored"
	}
	return lineBackupSourcePrefix + kind + "/" + groupID.String() + "/" + strconv.Itoa(family) + "/" +
		strconv.FormatInt(sequence, 10)
}

func parseLineBackupSourceEventID(value string) (uuid.UUID, int, int64, bool) {
	rest, found := strings.CutPrefix(value, lineBackupSourcePrefix)
	parts := strings.Split(rest, "/")
	if !found || len(parts) != 4 || (parts[0] != "activated" && parts[0] != "restored") {
		return uuid.Nil, 0, 0, false
	}
	groupID, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, 0, 0, false
	}
	family, err := strconv.Atoi(parts[2])
	if err != nil || (family != 4 && family != 6) {
		return uuid.Nil, 0, 0, false
	}
	sequence, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || sequence < 1 {
		return uuid.Nil, 0, 0, false
	}
	return groupID, family, sequence, true
}

func lineBackupFamilyText(family int) string {
	if family == 6 {
		return "IPv6"
	}
	return "IPv4"
}

// lineBackupAddressText lists the first few standby IPs for the alert.
func lineBackupAddressText(addresses []string) string {
	if len(addresses) == 0 {
		return "-"
	}
	if len(addresses) <= lineBackupAddressShown {
		return strings.Join(addresses, "、")
	}
	return strings.Join(addresses[:lineBackupAddressShown], "、") + " 等 " + strconv.Itoa(len(addresses)) + " 个"
}

// lineBackupObservedSQL reads the current revision of every general line
// group per address family; $1/$2 narrow it to one line group when not null.
const lineBackupObservedSQL = `SELECT published.tenant_scope_id,published.line_group_id,published.address_family::integer,
		published.config_revision,
		COALESCE(array_agg(host(published.address) ORDER BY published.address)
			FILTER (WHERE published.published AND published.standby AND NOT serving.held), '{}')
	FROM node_line_endpoint_published published
	JOIN node_line_groups line_group ON line_group.tenant_scope_id=published.tenant_scope_id
	 AND line_group.id=published.line_group_id AND line_group.current_revision=published.config_revision
	 AND line_group.deleted_at IS NULL AND line_group.purpose='general'
	JOIN node_line_endpoint_serving serving ON serving.tenant_scope_id=published.tenant_scope_id
	 AND serving.line_group_id=published.line_group_id AND serving.config_revision=published.config_revision
	 AND serving.endpoint_id=published.endpoint_id
	WHERE ($1::uuid IS NULL OR published.tenant_scope_id=$1) AND ($2::uuid IS NULL OR published.line_group_id=$2)
	GROUP BY published.tenant_scope_id,published.line_group_id,published.address_family,published.config_revision`

type lineBackupQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func readLineBackupObservations(ctx context.Context, querier lineBackupQuerier, scopeID, groupID *uuid.UUID) (
	map[LineBackupKey]LineBackupObservation, error) {
	rows, err := querier.Query(ctx, lineBackupObservedSQL, scopeID, groupID)
	if err != nil {
		return nil, fmt.Errorf("read line group backup IPs: %w", err)
	}
	defer rows.Close()
	result := map[LineBackupKey]LineBackupObservation{}
	for rows.Next() {
		var key LineBackupKey
		observation := LineBackupObservation{Present: true}
		if err := rows.Scan(&key.ScopeID, &key.GroupID, &key.Family, &observation.Revision, &observation.Backups); err != nil {
			return nil, fmt.Errorf("scan line group backup IPs: %w", err)
		}
		if len(observation.Backups) > maxLineBackupAddresses {
			observation.Backups = observation.Backups[:maxLineBackupAddresses]
		}
		result[key] = observation
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate line group backup IPs: %w", err)
	}
	return result, nil
}

// LineBackupCandidate is one family whose state may change.
type LineBackupCandidate struct {
	Key      LineBackupKey
	Current  LineBackupState
	Observed LineBackupObservation
}

// LineBackupCandidates reads, in one snapshot, the families whose stored state
// differs from the current view.
func (store *Store) LineBackupCandidates(ctx context.Context) ([]LineBackupCandidate, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	observed, err := readLineBackupObservations(ctx, tx, nil, nil)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT tenant_scope_id,line_group_id,address_family::integer,state,sequence
		FROM node_line_group_backup_states`)
	if err != nil {
		return nil, fmt.Errorf("read line group backup states: %w", err)
	}
	states := map[LineBackupKey]LineBackupState{}
	for rows.Next() {
		var key LineBackupKey
		state := LineBackupState{Found: true}
		if err := rows.Scan(&key.ScopeID, &key.GroupID, &key.Family, &state.State, &state.Sequence); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan line group backup state: %w", err)
		}
		states[key] = state
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate line group backup states: %w", err)
	}
	var candidates []LineBackupCandidate
	for key, observation := range observed {
		if DecideLineBackup(states[key], observation).Write {
			candidates = append(candidates, LineBackupCandidate{Key: key, Current: states[key], Observed: observation})
		}
	}
	for key, state := range states {
		if _, ok := observed[key]; !ok && DecideLineBackup(state, LineBackupObservation{}).Write {
			candidates = append(candidates, LineBackupCandidate{Key: key, Current: state})
		}
	}
	return candidates, tx.Commit(ctx)
}

// ApplyLineBackup re-reads the family under the state row lock, CASes the
// sequence and, for a real activation or restore, enqueues the alert in the
// same transaction. It reports whether the state changed.
func (store *Store) ApplyLineBackup(ctx context.Context, key LineBackupKey, expectedSequence int64) (bool, error) {
	if store == nil || ctx == nil || key.ScopeID == uuid.Nil || key.GroupID == uuid.Nil || (key.Family != 4 && key.Family != 6) {
		return false, ErrInvalidInput
	}
	changed := false
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		current := LineBackupState{Found: true}
		var revision int64
		err := tx.QueryRow(ctx, `SELECT state,sequence,config_revision FROM node_line_group_backup_states
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND address_family=$3 FOR UPDATE`,
			key.ScopeID, key.GroupID, key.Family).Scan(&current.State, &current.Sequence, &revision)
		if errors.Is(err, pgx.ErrNoRows) {
			current = LineBackupState{}
		} else if err != nil {
			return err
		}
		if current.Sequence != expectedSequence {
			return nil
		}
		observations, err := readLineBackupObservations(ctx, tx, &key.ScopeID, &key.GroupID)
		if err != nil {
			return err
		}
		observed := observations[key]
		decision := DecideLineBackup(current, observed)
		if !decision.Write {
			return nil
		}
		if observed.Present {
			revision = observed.Revision
		}
		addresses := observed.Backups
		if decision.State == LineBackupNormal || addresses == nil {
			addresses = []string{}
		}
		var tag interface{ RowsAffected() int64 }
		if current.Found {
			tag, err = tx.Exec(ctx, `UPDATE node_line_group_backup_states SET state=$4,config_revision=$5,sequence=$6,
				backup_addresses=$7::inet[],changed_at=$8
				WHERE tenant_scope_id=$1 AND line_group_id=$2 AND address_family=$3 AND sequence=$9`,
				key.ScopeID, key.GroupID, key.Family, decision.State, revision, decision.Sequence, addresses, now, current.Sequence)
		} else {
			tag, err = tx.Exec(ctx, `INSERT INTO node_line_group_backup_states(tenant_scope_id,line_group_id,address_family,
				state,config_revision,sequence,backup_addresses,changed_at) VALUES($1,$2,$3,$4,$5,$6,$7::inet[],$8)
				ON CONFLICT DO NOTHING`,
				key.ScopeID, key.GroupID, key.Family, decision.State, revision, decision.Sequence, addresses, now)
		}
		if err != nil {
			return fmt.Errorf("write line group backup state: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return nil
		}
		changed = true
		if decision.EventType != "" {
			store.enqueueLineBackupAlert(ctx, tx, key, decision, observed.Backups, now)
		}
		return nil
	})
	return changed, err
}

// enqueueLineBackupAlert runs under a savepoint: a notification failure is
// logged and never blocks the state.
func (store *Store) enqueueLineBackupAlert(ctx context.Context, tx pgx.Tx, key LineBackupKey, decision LineBackupDecision,
	backups []string, now time.Time) {
	if store.alerts == nil {
		return
	}
	err := func() error {
		savepoint, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = savepoint.Rollback(context.Background()) }()
		if err := store.enqueueLineBackupAlertTx(ctx, savepoint, key, decision, backups, now); err != nil {
			return err
		}
		return savepoint.Commit(ctx)
	}()
	if err != nil {
		slog.Warn("line group backup IP alert not enqueued", "line_group_id", key.GroupID, "address_family", key.Family,
			"event_type", decision.EventType, "error", err)
	}
}

func (store *Store) enqueueLineBackupAlertTx(ctx context.Context, tx pgx.Tx, key LineBackupKey, decision LineBackupDecision,
	backups []string, now time.Time) error {
	var name string
	var platform bool
	if err := tx.QueryRow(ctx, `SELECT line_group.name,scope.kind='platform' AND scope.tenant_id IS NULL
		FROM node_line_groups line_group JOIN access_scopes scope ON scope.id=line_group.tenant_scope_id
		WHERE line_group.tenant_scope_id=$1 AND line_group.id=$2`, key.ScopeID, key.GroupID).Scan(&name, &platform); err != nil {
		return fmt.Errorf("read alerted line group: %w", err)
	}
	if !platform {
		// Tenant line groups are not alerted yet, like tenant-owned nodes.
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id
		FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active'
		ORDER BY membership.user_id`, key.ScopeID, alertRecipientPermission)
	if err != nil {
		return fmt.Errorf("read line group alert recipients: %w", err)
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return fmt.Errorf("read line group alert recipients: %w", err)
	}
	sourceEventID := lineBackupSourceEventID(decision.EventType, key.GroupID, key.Family, decision.Sequence)
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: decision.EventType + ".zh-cn", Version: alertTemplateVersion, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: decision.EventType + ".zh-cn", Version: alertTemplateVersion, Channel: notification.ChannelEmail},
	}
	values := notification.TemplateContext{
		"line_group_name": notification.PublicValue(name),
		"address_family":  notification.PublicValue(lineBackupFamilyText(key.Family)),
		"occurred_at":     notification.PublicValue(now.UTC().Format(time.RFC3339)),
	}
	if decision.EventType == EventTypeLineBackupActivated {
		values["backup_addresses"] = notification.PublicValue(lineBackupAddressText(backups))
	}
	for _, recipient := range recipients {
		if _, err := store.alerts.EnqueueTx(ctx, tx, notification.EnqueueRequest{
			ScopeID: key.ScopeID, RecipientID: recipient, SourceEventID: sourceEventID, EventType: decision.EventType,
			Policy: notification.DeliverySystemRequired, Templates: templates,
			Contexts:       map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: values, notification.ChannelEmail: values},
			AuditRequestID: sourceEventID,
		}); err != nil {
			return fmt.Errorf("enqueue %s: %w", decision.EventType, err)
		}
	}
	return nil
}

// LineBackupReplayGuard keeps a scheduled repeat only while the state
// transition that produced it is still the family's current one.
func LineBackupReplayGuard(ctx context.Context, tx pgx.Tx, candidate notification.ReplayCandidate) (bool, error) {
	groupID, family, sequence, ok := parseLineBackupSourceEventID(candidate.SourceEventID)
	if !ok {
		return false, nil
	}
	var current int64
	err := tx.QueryRow(ctx, `SELECT sequence FROM node_line_group_backup_states
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND address_family=$3`, candidate.ScopeID, groupID, family).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read line group backup state: %w", err)
	}
	return current == sequence, nil
}

// RegisterLineBackupReplayGuards installs the guard for both events.
func RegisterLineBackupReplayGuards(store *notification.Store) error {
	for _, eventType := range []string{EventTypeLineBackupActivated, EventTypeLineBackupRestored} {
		if err := store.RegisterReplayGuard(eventType, LineBackupReplayGuard); err != nil {
			return fmt.Errorf("register line group backup replay guard %s: %w", eventType, err)
		}
	}
	return nil
}

// LineBackupEvaluator records backup IP state changes each worker tick, after
// the hold sources have run.
type LineBackupEvaluator struct {
	store *Store
}

func NewLineBackupEvaluator(store *Store) *LineBackupEvaluator {
	return &LineBackupEvaluator{store: store}
}

func (evaluator *LineBackupEvaluator) Evaluate(ctx context.Context) error {
	candidates, err := evaluator.store.LineBackupCandidates(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, candidate := range candidates {
		if _, err := evaluator.store.ApplyLineBackup(ctx, candidate.Key, candidate.Current.Sequence); err != nil && first == nil {
			first = err
		}
	}
	return first
}
