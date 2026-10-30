package securityanalytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// ErrClickHouse: ClickHouse is unavailable or answered an error.
var ErrClickHouse = errors.New("security analytics ClickHouse unavailable")

var clickHouseDatabase = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

const clickHouseTime = "2006-01-02 15:04:05.000"

// ClickHouse writes NodeEventTable and reads the security tables over the HTTP
// interface. Queries bind every value as a server-side parameter.
type ClickHouse struct {
	endpoint           *url.URL
	database           string
	username, password string
	client             *http.Client
}

// NewClickHouse validates the endpoint (http/https, no credentials in the
// URL) and database name.
func NewClickHouse(endpoint, database, username, password string, timeout time.Duration) (*ClickHouse, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil ||
		!clickHouseDatabase.MatchString(database) || timeout <= 0 {
		return nil, ErrInvalidConfig
	}
	return &ClickHouse{endpoint: parsed, database: database, username: username, password: password,
		client: &http.Client{Timeout: timeout}}, nil
}

func (ch *ClickHouse) do(ctx context.Context, query string, params map[string]string, body []byte) ([]byte, error) {
	endpoint := *ch.endpoint
	values := endpoint.Query()
	values.Set("database", ch.database)
	values.Set("query", query)
	for name, value := range params {
		values.Set("param_"+name, value)
	}
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrClickHouse
	}
	if ch.username != "" {
		request.SetBasicAuth(ch.username, ch.password)
	}
	response, err := ch.client.Do(request)
	if err != nil {
		return nil, ErrClickHouse
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil || response.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%w: status %d", ErrClickHouse, response.StatusCode)
	}
	return data, nil
}

func (ch *ClickHouse) insert(ctx context.Context, table string, rows []any) error {
	if len(rows) == 0 {
		return nil
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			return err
		}
	}
	_, err := ch.do(ctx, "INSERT INTO "+table+" FORMAT JSONEachRow", nil, body.Bytes())
	return err
}

type verdictRow struct {
	TenantID         string `json:"tenant_id"`
	SiteID           string `json:"site_id"`
	NodeID           string `json:"node_id"`
	VerdictID        string `json:"verdict_id"`
	OccurredAt       string `json:"occurred_at"`
	TargetKind       string `json:"target_kind"`
	Target           string `json:"target"`
	Score            int64  `json:"score"`
	Level            int64  `json:"level"`
	Until            string `json:"until"`
	Reason           string `json:"reason"`
	SnapshotRevision uint64 `json:"snapshot_revision"`
	ReportSeq        uint64 `json:"report_seq"`
}

type nodeEventRow struct {
	NodeID          string `json:"node_id"`
	EventID         string `json:"event_id"`
	OccurredAt      string `json:"occurred_at"`
	Source          string `json:"source"`
	Kind            string `json:"kind"`
	PortGroup       string `json:"port_group"`
	ClientIP        string `json:"client_ip"`
	Count           int64  `json:"count"`
	DurationSeconds int64  `json:"duration_seconds"`
	Level           int64  `json:"level"`
	Reason          string `json:"reason"`
	Detail          string `json:"detail"`
}

// WriteFacts implements FactWriter.
func (ch *ClickHouse) WriteFacts(ctx context.Context, facts Facts) error {
	verdicts := make([]any, len(facts.Verdicts))
	for index, verdict := range facts.Verdicts {
		verdicts[index] = verdictRow{TenantID: verdict.TenantID.String(), SiteID: verdict.SiteID.String(),
			NodeID: verdict.NodeID.String(), VerdictID: verdict.ID.String(), OccurredAt: chTime(verdict.OccurredAt),
			TargetKind: verdict.TargetKind, Target: verdict.Target, Score: verdict.Score, Level: verdict.Level,
			Until: chTime(verdict.Until), Reason: verdict.Reason, SnapshotRevision: verdict.Revision, ReportSeq: verdict.Seq}
	}
	if err := ch.insert(ctx, VerdictTable, verdicts); err != nil {
		return err
	}
	events := make([]any, len(facts.NodeEvents))
	for index, event := range facts.NodeEvents {
		events[index] = nodeEventRow{NodeID: event.NodeID.String(), EventID: event.ID.String(), OccurredAt: chTime(event.OccurredAt),
			Source: event.Source, Kind: event.Kind, PortGroup: event.PortGroup, ClientIP: event.ClientIP, Count: event.Count,
			DurationSeconds: event.DurationSeconds, Level: event.Level, Reason: event.Reason, Detail: event.Detail}
	}
	return ch.insert(ctx, NodeEventTable, events)
}

func chTime(at time.Time) string { return at.UTC().Format(clickHouseTime) }

// ClickHouse tables (migrations autodefense_verdicts and cc_rule_stats).
const (
	VerdictTable   = "autodefense_verdicts_v1"
	NodeEventTable = "node_security_events_v1"
)

// ErrInvalidConfig: a constructor got an incomplete configuration.
var ErrInvalidConfig = errors.New("security analytics configuration invalid")
