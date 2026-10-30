package retentioncleanup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/systemcleanup"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AuditTTLAction marks each ClickHouse TTL change made to follow the settings.
const AuditTTLAction = "system_cleanup.retention.clickhouse_ttl"

const clickHouseTTLTable = "clickhouse_ttl"

// ClickHouse is the minimal client the TTL sync needs. The runtime identity
// holds only table-scoped ALTER MODIFY TTL on the managed tables.
type ClickHouse interface {
	// Exec runs one statement in the analytics database and returns the body.
	Exec(ctx context.Context, statement string) ([]byte, error)
}

// ttlTarget is one ClickHouse table whose TTL follows a cleanup setting.
type ttlTarget struct {
	table, setting, column string
}

// ttlTargets lists the history tables shown on the cleanup settings page.
// Billing facts (package_metric_*), realtime monitoring, ingest receipts and
// dedup/version state keep their fixed TTL: they back metering and
// idempotency, not the user-visible history.
var ttlTargets = []ttlTarget{
	{"access_events", "access_logs_days", "toDateTime(occurred_at, 'UTC')"},
	{"access_event_latest_state_v1", "access_logs_days", "toDateTime(occurred_at, 'UTC')"},
	{"access_event_query_index_state_v1", "access_logs_days", "toDateTime(occurred_at, 'UTC')"},
	{"access_event_query_payload_state_v1", "access_logs_days", "toDateTime(occurred_at, 'UTC')"},
	{"security_events", "blacklist_history_days", "toDateTime(occurred_at, 'UTC')"},
	{"security_event_latest_state_v1", "blacklist_history_days", "toDateTime(occurred_at, 'UTC')"},
	{"security_event_query_index_state_v1", "blacklist_history_days", "toDateTime(occurred_at, 'UTC')"},
	{"security_event_query_payload_state_v1", "blacklist_history_days", "toDateTime(occurred_at, 'UTC')"},
	{"security_event_evidence_state_v1", "blacklist_history_days", "toDateTime(occurred_at, 'UTC')"},
	{"security_event_count_state_v1", "blacklist_history_days", "toDateTime(occurred_at, 'UTC')"},
	{"access_hourly_facts_v1", "bandwidth_history_days", "hour"},
	{"security_hourly_facts_v1", "bandwidth_history_days", "hour"},
}

// TTLChange is one table whose TTL was changed (Days 0: TTL removed).
type TTLChange struct {
	Table       string
	Setting     string
	FromDays    int // -1: there was no TTL
	Days        int
	Statement   string
	ApplyFailed error
}

// ttlSettings returns the effective days for every TTL setting; a missing
// settings row or key uses the page defaults (systemcleanup.DefaultSettings).
func ttlSettings(ctx context.Context, tx pgx.Tx) (map[string]int, error) {
	defaults := systemcleanup.DefaultSettings()
	result := map[string]int{"access_logs_days": defaults.AccessLogsDays,
		"blacklist_history_days": defaults.BlacklistHistoryDays, "bandwidth_history_days": defaults.BandwidthHistoryDays}
	for setting := range result {
		var days *int
		if err := tx.QueryRow(ctx, `SELECT max((settings->>$1)::integer) FROM platform_system_cleanup_settings
			WHERE settings ? $1`, setting).Scan(&days); err != nil {
			return nil, err
		}
		if days != nil {
			if *days < 0 || *days > 3650 {
				return nil, fmt.Errorf("retention setting %s is out of range", setting)
			}
			result[setting] = *days
		}
	}
	return result, nil
}

// ttlPattern matches the TTL clause system.tables prints for the managed
// tables, e.g. "TTL toDateTime(occurred_at, \'UTC\') + toIntervalDay(30)".
var ttlPattern = regexp.MustCompile(`\bTTL (.+?) \+ toIntervalDay\((\d+)\)(?: SETTINGS |$)`)

// currentTTLDays parses engine_full: -1 when there is no TTL, an error when
// the TTL is not the plain "<column> + N days" form this sync manages.
func currentTTLDays(engineFull, column string) (int, error) {
	if !strings.Contains(engineFull, " TTL ") {
		return -1, nil
	}
	match := ttlPattern.FindStringSubmatch(engineFull)
	if match == nil || strings.ReplaceAll(match[1], `\'`, "'") != column {
		return 0, errors.New("unrecognised TTL clause; left unchanged")
	}
	return strconv.Atoi(match[2])
}

// ttlStatement is the ALTER that makes the table keep days of history.
func ttlStatement(item ttlTarget, days int) string {
	if days == 0 {
		return "ALTER TABLE " + item.table + " REMOVE TTL"
	}
	return fmt.Sprintf("ALTER TABLE %s MODIFY TTL %s + INTERVAL %d DAY DELETE", item.table, item.column, days)
}

// SyncClickHouseTTL makes every managed ClickHouse table's TTL match the
// cleanup settings. Unchanged tables issue no ALTER; a failing table is
// reported and the others still run; every applied change is audited.
func (worker *Worker) SyncClickHouseTTL(ctx context.Context) ([]TTLChange, error) {
	if worker.config.ClickHouse == nil {
		return nil, nil
	}
	var changes []TTLChange
	var failures error
	err := pgx.BeginFunc(ctx, worker.pool, func(tx pgx.Tx) error {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, advisoryLockKey+1).Scan(&locked); err != nil || !locked {
			return err
		}
		settings, err := ttlSettings(ctx, tx)
		if err != nil {
			return err
		}
		names := make([]string, len(ttlTargets))
		for index, item := range ttlTargets {
			names[index] = "'" + item.table + "'"
		}
		body, err := worker.config.ClickHouse.Exec(ctx, `SELECT name, engine_full FROM system.tables
			WHERE database = currentDatabase() AND name IN (`+strings.Join(names, ",")+`) FORMAT JSONEachRow`)
		if err != nil {
			return fmt.Errorf("read ClickHouse TTL: %w", err)
		}
		engines := map[string]string{}
		scanner := bufio.NewScanner(bytes.NewReader(body))
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			var row struct {
				Name       string `json:"name"`
				EngineFull string `json:"engine_full"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
				return fmt.Errorf("decode ClickHouse TTL: %w", err)
			}
			engines[row.Name] = row.EngineFull
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		for _, item := range ttlTargets {
			engine, ok := engines[item.table]
			if !ok {
				// Missing, or invisible because the TTL grant is absent.
				failures = errors.Join(failures, fmt.Errorf("%s: table not visible to the ClickHouse identity", item.table))
				continue
			}
			from, err := currentTTLDays(engine, item.column)
			if err != nil {
				failures = errors.Join(failures, fmt.Errorf("%s: %w", item.table, err))
				continue
			}
			days := settings[item.setting]
			if from == days || (from == -1 && days == 0) {
				continue
			}
			change := TTLChange{Table: item.table, Setting: item.setting, FromDays: from, Days: days, Statement: ttlStatement(item, days)}
			if _, err := worker.config.ClickHouse.Exec(ctx, change.Statement); err != nil {
				change.ApplyFailed = err
				failures = errors.Join(failures, fmt.Errorf("%s: %w", item.table, err))
			}
			changes = append(changes, change)
		}
		// changes: retention days per table, before -> after (-1: no TTL).
		applied := make([]audit.Change, 0, len(changes))
		for _, change := range changes {
			if change.ApplyFailed == nil {
				applied = append(applied, audit.Change{Field: change.Setting + "." + change.Table,
					Before: change.FromDays, After: change.Days})
			}
		}
		if len(applied) == 0 {
			return nil
		}
		scopeID, err := platformAuditScope(ctx, tx)
		if err != nil {
			return err
		}
		return worker.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, Action: AuditTTLAction, ResourceType: "clickhouse_ttl", ResourceID: "analytics",
			RequestID: "retention-" + uuid.NewString(), Result: "success", Payload: map[string]any{}, Changes: applied,
		})
	})
	return changes, errors.Join(err, failures)
}

// ClickHouseHTTP runs statements over the ClickHouse HTTP interface.
type ClickHouseHTTP struct {
	endpoint           *url.URL
	username, password string
	client             *http.Client
}

// NewClickHouseHTTP accepts HTTPS, or loopback HTTP, endpoints without
// credentials in the URL; database selects the analytics database.
func NewClickHouseHTTP(endpoint, database, username, password string, timeout time.Duration) (*ClickHouseHTTP, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || database == "" || timeout <= 0 ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, errors.New("invalid ClickHouse TTL sync configuration")
	}
	parsed.Path = "/"
	parsed.RawQuery = url.Values{"database": {database}}.Encode()
	return &ClickHouseHTTP{endpoint: parsed, username: username, password: password, client: &http.Client{Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (clickHouse *ClickHouseHTTP) Exec(ctx context.Context, statement string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, clickHouse.endpoint.String(), strings.NewReader(statement))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if clickHouse.username != "" {
		request.SetBasicAuth(clickHouse.username, clickHouse.password)
	}
	response, err := clickHouse.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		message, _, _ := strings.Cut(strings.TrimSpace(string(body)), "\n")
		if len(message) > 300 {
			message = message[:300]
		}
		return nil, fmt.Errorf("clickhouse status %d: %s", response.StatusCode, message)
	}
	return body, nil
}
