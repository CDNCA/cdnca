package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	MaxDatabaseIdentifierBytes = 64
	defaultQueryTimeout        = 5 * time.Second
	defaultWriteTimeout        = 10 * time.Second
	maximumOperationTimeout    = 30 * time.Second
	defaultMaxResponse         = int64(4 << 20)
	defaultMaxBatchEvents      = 1000
	defaultMaxBatchBytes       = int64(8 << 20)
	nilUUIDValue               = "00000000-0000-0000-0000-000000000000"
	insertAccessEventsSQL      = "INSERT INTO access_events FORMAT JSONEachRow"
	insertSecurityEventSQL     = "INSERT INTO security_events FORMAT JSONEachRow"
	ingestSchemaSQL            = "SELECT name, type, default_kind FROM system.columns WHERE database = currentDatabase() AND table = {table:String} ORDER BY position FORMAT JSONEachRow"
)

type ingestColumn struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	DefaultKind string `json:"default_kind"`
}

var accessIngestSchema = []ingestColumn{
	{Name: "metric_version", Type: "UInt16"}, {Name: "event_id", Type: "String"},
	{Name: "occurred_at", Type: "DateTime64(3, 'UTC')"}, {Name: "ingested_at", Type: "DateTime64(3, 'UTC')", DefaultKind: "DEFAULT"},
	{Name: "tenant_id", Type: "UUID"}, {Name: "package_subscription_id", Type: "UUID"},
	{Name: "site_id", Type: "UUID"}, {Name: "node_id", Type: "UUID"},
	{Name: "request_id", Type: "String", DefaultKind: "DEFAULT"}, {Name: "trace_id", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "config_version_id", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "task_id", Type: "Nullable(String)", DefaultKind: "DEFAULT"},
	{Name: "installation_id", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "request_headers", Type: "Map(String, String)", DefaultKind: "DEFAULT"},
	{Name: "response_headers", Type: "Map(String, String)", DefaultKind: "DEFAULT"},
	{Name: "request_body", Type: "Nullable(String)", DefaultKind: "DEFAULT"},
	{Name: "response_body", Type: "Nullable(String)", DefaultKind: "DEFAULT"},
	{Name: "ja4", Type: "Nullable(String)", DefaultKind: "DEFAULT"},
	{Name: "origin_connect_us", Type: "Nullable(UInt64)", DefaultKind: "DEFAULT"},
	{Name: "origin_first_byte_us", Type: "Nullable(UInt64)", DefaultKind: "DEFAULT"},
	{Name: "origin_total_us", Type: "Nullable(UInt64)", DefaultKind: "DEFAULT"},
	{Name: "host", Type: "String"}, {Name: "listen_port", Type: "UInt16", DefaultKind: "DEFAULT"},
	{Name: "path", Type: "String"}, {Name: "client_ip", Type: "IPv6"},
	{Name: "country_code", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "carrier", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "province", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "method", Type: "LowCardinality(String)"}, {Name: "protocol", Type: "LowCardinality(String)"},
	{Name: "cache_status", Type: "LowCardinality(String)"},
	{Name: "upstream_result", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "upstream_addr", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "status_code", Type: "UInt16"}, {Name: "request_bytes", Type: "UInt64"},
	{Name: "response_bytes", Type: "UInt64"}, {Name: "duration_us", Type: "UInt64"},
	{Name: "blocked", Type: "Bool", DefaultKind: "DEFAULT"},
	{Name: "client_browser", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "client_os", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
}

var securityIngestSchema = []ingestColumn{
	{Name: "metric_version", Type: "UInt16"}, {Name: "event_id", Type: "String"},
	{Name: "occurred_at", Type: "DateTime64(3, 'UTC')"}, {Name: "ingested_at", Type: "DateTime64(3, 'UTC')", DefaultKind: "DEFAULT"},
	{Name: "tenant_id", Type: "UUID"}, {Name: "package_subscription_id", Type: "UUID"},
	{Name: "site_id", Type: "UUID"}, {Name: "node_id", Type: "UUID"},
	{Name: "request_id", Type: "String", DefaultKind: "DEFAULT"}, {Name: "trace_id", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "config_version_id", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "task_id", Type: "Nullable(String)", DefaultKind: "DEFAULT"},
	{Name: "installation_id", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "request_headers", Type: "Map(String, String)", DefaultKind: "DEFAULT"},
	{Name: "response_headers", Type: "Map(String, String)", DefaultKind: "DEFAULT"},
	{Name: "request_body", Type: "Nullable(String)", DefaultKind: "DEFAULT"},
	{Name: "response_body", Type: "Nullable(String)", DefaultKind: "DEFAULT"},
	{Name: "ja4", Type: "Nullable(String)", DefaultKind: "DEFAULT"},
	{Name: "origin_connect_us", Type: "Nullable(UInt64)", DefaultKind: "DEFAULT"},
	{Name: "origin_first_byte_us", Type: "Nullable(UInt64)", DefaultKind: "DEFAULT"},
	{Name: "origin_total_us", Type: "Nullable(UInt64)", DefaultKind: "DEFAULT"},
	{Name: "host", Type: "String"},
	{Name: "path", Type: "String"}, {Name: "client_ip", Type: "IPv6"},
	{Name: "country_code", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "carrier", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "province", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "event_type", Type: "LowCardinality(String)"}, {Name: "action", Type: "LowCardinality(String)"},
	{Name: "severity", Type: "LowCardinality(String)"}, {Name: "rule_id", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "status_code", Type: "UInt16"}, {Name: "request_bytes", Type: "UInt64"},
	{Name: "response_bytes", Type: "UInt64"},
	{Name: "method", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "listen_port", Type: "UInt16", DefaultKind: "DEFAULT"},
	{Name: "destination_port", Type: "UInt16", DefaultKind: "DEFAULT"},
	{Name: "protocol", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "request_class", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "policy_id", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "detector", Type: "LowCardinality(String)", DefaultKind: "DEFAULT"},
	{Name: "matched", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "user_agent", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "request_body_excerpt", Type: "String", DefaultKind: "DEFAULT"},
	{Name: "event_count", Type: "UInt32", DefaultKind: "DEFAULT"},
}

type accessInsertRow struct {
	MetricVersion         uint16            `json:"metric_version"`
	EventID               string            `json:"event_id"`
	OccurredAt            time.Time         `json:"occurred_at"`
	TenantID              string            `json:"tenant_id"`
	PackageSubscriptionID string            `json:"package_subscription_id"`
	SiteID                string            `json:"site_id"`
	NodeID                string            `json:"node_id"`
	RequestID             string            `json:"request_id"`
	TraceID               string            `json:"trace_id"`
	ConfigVersion         string            `json:"config_version_id"`
	TaskID                *string           `json:"task_id"`
	InstallationID        string            `json:"installation_id"`
	RequestHeaders        map[string]string `json:"request_headers"`
	ResponseHeaders       map[string]string `json:"response_headers"`
	RequestBody           *string           `json:"request_body"`
	ResponseBody          *string           `json:"response_body"`
	JA4                   *string           `json:"ja4"`
	OriginConnectUS       *uint64           `json:"origin_connect_us"`
	OriginFirstByteUS     *uint64           `json:"origin_first_byte_us"`
	OriginTotalUS         *uint64           `json:"origin_total_us"`
	Host                  string            `json:"host"`
	ListenPort            uint16            `json:"listen_port"`
	Path                  string            `json:"path"`
	ClientIP              string            `json:"client_ip"`
	CountryCode           string            `json:"country_code"`
	Carrier               string            `json:"carrier"`
	Method                string            `json:"method"`
	Protocol              string            `json:"protocol"`
	CacheStatus           string            `json:"cache_status"`
	UpstreamResult        string            `json:"upstream_result"`
	UpstreamAddr          string            `json:"upstream_addr"`
	StatusCode            uint16            `json:"status_code"`
	RequestBytes          uint64            `json:"request_bytes"`
	ResponseBytes         uint64            `json:"response_bytes"`
	DurationUS            uint64            `json:"duration_us"`
	Blocked               bool              `json:"blocked"`
	Province              string            `json:"province"`
	ClientBrowser         string            `json:"client_browser"`
	ClientOS              string            `json:"client_os"`
}

type securityInsertRow struct {
	MetricVersion         uint16            `json:"metric_version"`
	EventID               string            `json:"event_id"`
	OccurredAt            time.Time         `json:"occurred_at"`
	TenantID              string            `json:"tenant_id"`
	PackageSubscriptionID string            `json:"package_subscription_id"`
	SiteID                string            `json:"site_id"`
	NodeID                string            `json:"node_id"`
	RequestID             string            `json:"request_id"`
	TraceID               string            `json:"trace_id"`
	ConfigVersion         string            `json:"config_version_id"`
	TaskID                *string           `json:"task_id"`
	InstallationID        string            `json:"installation_id"`
	RequestHeaders        map[string]string `json:"request_headers"`
	ResponseHeaders       map[string]string `json:"response_headers"`
	RequestBody           *string           `json:"request_body"`
	ResponseBody          *string           `json:"response_body"`
	JA4                   *string           `json:"ja4"`
	OriginConnectUS       *uint64           `json:"origin_connect_us"`
	OriginFirstByteUS     *uint64           `json:"origin_first_byte_us"`
	OriginTotalUS         *uint64           `json:"origin_total_us"`
	Host                  string            `json:"host"`
	Path                  string            `json:"path"`
	ClientIP              string            `json:"client_ip"`
	CountryCode           string            `json:"country_code"`
	Carrier               string            `json:"carrier"`
	Province              string            `json:"province"`
	EventType             string            `json:"event_type"`
	Action                string            `json:"action"`
	Severity              string            `json:"severity"`
	RuleID                string            `json:"rule_id"`
	Method                string            `json:"method"`
	ListenPort            uint16            `json:"listen_port"`
	DestinationPort       uint16            `json:"destination_port"`
	Protocol              string            `json:"protocol"`
	RequestClass          string            `json:"request_class"`
	StatusCode            uint16            `json:"status_code"`
	RequestBytes          uint64            `json:"request_bytes"`
	ResponseBytes         uint64            `json:"response_bytes"`
	PolicyID              string            `json:"policy_id"`
	Detector              string            `json:"detector"`
	Matched               string            `json:"matched"`
	UserAgent             string            `json:"user_agent"`
	RequestBodyExcerpt    string            `json:"request_body_excerpt"`
	EventCount            uint32            `json:"event_count"`
}

var (
	ErrInvalidConfiguration = errors.New("invalid analytics configuration")
	ErrTransport            = errors.New("analytics transport failed")
	ErrResponseTooLarge     = errors.New("analytics response too large")
	ErrInvalidResponse      = errors.New("invalid analytics response")
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Config struct {
	Endpoint         string
	Database         string
	Username         string
	Password         string
	QueryTimeout     time.Duration
	WriteTimeout     time.Duration
	MaxResponseBytes int64
	MaxBatchEvents   int
	MaxBatchBytes    int64
}

type Client struct {
	endpoint         *url.URL
	database         string
	username         string
	password         string
	http             HTTPClient
	queryTimeout     time.Duration
	writeTimeout     time.Duration
	maxResponseBytes int64
	maxBatchEvents   int
	maxBatchBytes    int64
	// tenants maps scope IDs to the facts' tenant_id (scope_tenant.go).
	tenants TenantResolver
}

type HTTPError struct {
	StatusCode int
}

func (err *HTTPError) Error() string {
	return fmt.Sprintf("analytics storage returned HTTP %d", err.StatusCode)
}

func (err *HTTPError) Retryable() bool {
	return err.StatusCode == http.StatusTooManyRequests || err.StatusCode >= http.StatusInternalServerError
}

func NewClient(config Config, httpClient HTTPClient) (*Client, error) {
	endpoint, err := url.Parse(strings.TrimSpace(config.Endpoint))
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") || !validIdentifier(config.Database) ||
		(config.Username == "" && config.Password != "") ||
		(endpoint.Scheme == "http" && !loopbackHost(endpoint.Hostname())) {
		return nil, ErrInvalidConfiguration
	}
	config.QueryTimeout = durationDefault(config.QueryTimeout, defaultQueryTimeout)
	config.WriteTimeout = durationDefault(config.WriteTimeout, defaultWriteTimeout)
	config.MaxResponseBytes = int64Default(config.MaxResponseBytes, defaultMaxResponse)
	config.MaxBatchEvents = intDefault(config.MaxBatchEvents, defaultMaxBatchEvents)
	config.MaxBatchBytes = int64Default(config.MaxBatchBytes, defaultMaxBatchBytes)
	if config.QueryTimeout < time.Millisecond || config.QueryTimeout > maximumOperationTimeout ||
		config.WriteTimeout < time.Millisecond || config.WriteTimeout > maximumOperationTimeout || config.MaxResponseBytes <= 0 ||
		config.MaxBatchEvents <= 0 || config.MaxBatchBytes <= 0 {
		return nil, ErrInvalidConfiguration
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: max(config.QueryTimeout, config.WriteTimeout),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	} else if standardClient, ok := httpClient.(*http.Client); ok {
		redirectSafeClient := *standardClient
		redirectSafeClient.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		httpClient = &redirectSafeClient
	}
	endpoint.Path = "/"
	return &Client{
		endpoint: endpoint, database: config.Database, username: config.Username, password: config.Password,
		http: httpClient, queryTimeout: config.QueryTimeout, writeTimeout: config.WriteTimeout,
		maxResponseBytes: config.MaxResponseBytes, maxBatchEvents: config.MaxBatchEvents,
		maxBatchBytes: config.MaxBatchBytes,
	}, nil
}

func (client *Client) String() string {
	return "analytics.Client{endpoint:" + client.endpoint.Scheme + "://" + client.endpoint.Host + ",database:" + client.database + "}"
}

func (client *Client) GoString() string {
	return client.String()
}

func (client *Client) Check(ctx context.Context) error {
	if client == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	return client.execute(ctx, client.queryTimeout, []byte("SELECT 1 AS ok FORMAT JSONEachRow"), nil, true, func(encoded []byte) error {
		var rows []struct {
			OK uint8 `json:"ok"`
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		for {
			var row struct {
				OK uint8 `json:"ok"`
			}
			if err := decoder.Decode(&row); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return err
			}
			rows = append(rows, row)
		}
		if len(rows) != 1 || rows[0].OK != 1 {
			return ErrInvalidResponse
		}
		return nil
	})
}

func (client *Client) CheckIngest(ctx context.Context) error {
	if client == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	for _, target := range []struct {
		table  string
		query  string
		schema []ingestColumn
	}{
		{table: "access_events", query: insertAccessEventsSQL, schema: accessIngestSchema},
		{table: "security_events", query: insertSecurityEventSQL, schema: securityIngestSchema},
	} {
		parameters := url.Values{"param_table": {target.table}}
		if err := client.execute(ctx, client.queryTimeout, []byte(ingestSchemaSQL), parameters, true, func(encoded []byte) error {
			var columns []ingestColumn
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.DisallowUnknownFields()
			for {
				var column ingestColumn
				if err := decoder.Decode(&column); err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return err
				}
				columns = append(columns, column)
			}
			if !slices.Equal(columns, target.schema) {
				return ErrInvalidResponse
			}
			return nil
		}); err != nil {
			return err
		}
		if err := client.execute(ctx, client.writeTimeout, []byte(target.query+"\n"), nil, false, nil); err != nil {
			return err
		}
	}
	return nil
}

func (client *Client) WriteAccessEvents(ctx context.Context, batchID string, events []AccessEvent) error {
	return writeBatch(client, ctx, batchID, events, insertAccessEventsSQL, validateAccessEvent, accessIdentity, accessInsertFrom)
}

func (client *Client) WriteSecurityEvents(ctx context.Context, batchID string, events []SecurityEvent) error {
	return writeBatch(client, ctx, batchID, events, insertSecurityEventSQL, validateSecurityEvent, securityIdentity, securityInsertFrom)
}

func writeBatch[T any](
	client *Client,
	ctx context.Context,
	batchID string,
	events []T,
	query string,
	validate func(T) error,
	identity func(T) string,
	storageRow func(T) (any, error),
) error {
	if !validBatchID(batchID) || len(events) == 0 || len(events) > client.maxBatchEvents {
		return ErrInvalidInput
	}
	var body bytes.Buffer
	body.Grow(min(int(client.maxBatchBytes), 64*1024))
	body.WriteString(query)
	body.WriteByte('\n')
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	identities := make(map[string]struct{}, len(events))
	for _, event := range events {
		if err := validate(event); err != nil {
			return err
		}
		key := identity(event)
		if _, exists := identities[key]; exists {
			return ErrInvalidInput
		}
		identities[key] = struct{}{}
		row, err := storageRow(event)
		if err != nil || encoder.Encode(row) != nil {
			return ErrInvalidInput
		}
		if int64(body.Len()-len(query)-1) > client.maxBatchBytes {
			return ErrInvalidInput
		}
	}
	parameters := url.Values{
		"insert_deduplicate":               {"1"},
		"insert_deduplication_token":       {batchID},
		"date_time_input_format":           {"best_effort"},
		"input_format_skip_unknown_fields": {"0"},
	}
	err := client.execute(ctx, client.writeTimeout, body.Bytes(), parameters, false, nil)
	if errors.Is(err, ErrTransport) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrIngestWriteOutcomeUnknown, err)
	}
	return err
}

func accessInsertFrom(event AccessEvent) (any, error) {
	requestBody, err := encodedCaptureBody(event.RequestBody)
	if err != nil {
		return nil, err
	}
	responseBody, err := encodedCaptureBody(event.ResponseBody)
	if err != nil || !validBatchID(event.InstallationID) {
		return nil, ErrInvalidInput
	}
	return accessInsertRow{
		MetricVersion: event.MetricVersion, EventID: event.EventID, OccurredAt: event.OccurredAt,
		TenantID: event.TenantID, PackageSubscriptionID: storageSubscriptionID(event.PackageSubscriptionID),
		SiteID: event.SiteID, NodeID: event.NodeID,
		RequestID: event.RequestID, TraceID: event.TraceID, ConfigVersion: event.ConfigVersion,
		TaskID: event.TaskID, InstallationID: event.InstallationID,
		RequestHeaders: nonnilHeaders(event.RequestHeaders), ResponseHeaders: nonnilHeaders(event.ResponseHeaders),
		RequestBody: requestBody, ResponseBody: responseBody, JA4: event.JA4,
		OriginConnectUS: event.OriginConnectUS, OriginFirstByteUS: event.OriginFirstByteUS, OriginTotalUS: event.OriginTotalUS,
		Host: event.Host, ListenPort: event.ListenPort, Path: event.Path, ClientIP: event.ClientIP, CountryCode: event.CountryCode, Carrier: event.Carrier,
		Method: event.Method, Protocol: event.Protocol, CacheStatus: event.CacheStatus, UpstreamResult: event.UpstreamResult,
		UpstreamAddr: event.UpstreamAddr, StatusCode: event.StatusCode, RequestBytes: event.RequestBytes, ResponseBytes: event.ResponseBytes, DurationUS: event.DurationUS,
		Blocked: event.Blocked, Province: event.Province, ClientBrowser: event.ClientBrowser, ClientOS: event.ClientOS,
	}, nil
}

func securityInsertFrom(event SecurityEvent) (any, error) {
	requestBody, err := encodedCaptureBody(event.RequestBody)
	if err != nil {
		return nil, err
	}
	responseBody, err := encodedCaptureBody(event.ResponseBody)
	if err != nil || !validBatchID(event.InstallationID) {
		return nil, ErrInvalidInput
	}
	return securityInsertRow{
		MetricVersion: event.MetricVersion, EventID: event.EventID, OccurredAt: event.OccurredAt,
		TenantID: event.TenantID, PackageSubscriptionID: storageSubscriptionID(event.PackageSubscriptionID),
		SiteID: event.SiteID, NodeID: event.NodeID,
		RequestID: event.RequestID, TraceID: event.TraceID, ConfigVersion: event.ConfigVersion,
		TaskID: event.TaskID, InstallationID: event.InstallationID,
		RequestHeaders: nonnilHeaders(event.RequestHeaders), ResponseHeaders: nonnilHeaders(event.ResponseHeaders),
		RequestBody: requestBody, ResponseBody: responseBody, JA4: event.JA4,
		OriginConnectUS: event.OriginConnectUS, OriginFirstByteUS: event.OriginFirstByteUS, OriginTotalUS: event.OriginTotalUS,
		Host: event.Host, Path: event.Path, ClientIP: event.ClientIP, CountryCode: event.CountryCode, Carrier: event.Carrier,
		EventType: event.EventType, Action: event.Action, Severity: event.Severity, RuleID: event.RuleID,
		Method: event.Method, ListenPort: event.ListenPort, DestinationPort: event.DestinationPort,
		Protocol: event.Protocol, RequestClass: event.RequestClass,
		StatusCode: event.StatusCode, RequestBytes: event.RequestBytes, ResponseBytes: event.ResponseBytes,
		PolicyID: event.PolicyID, Detector: event.Detector, Matched: event.Matched, UserAgent: event.UserAgent,
		RequestBodyExcerpt: event.RequestBodyExcerpt, EventCount: eventCount(event.Count),
		Province: event.Province,
	}, nil
}

func encodedCaptureBody(body map[string]any) (*string, error) {
	if body == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > maxCapturedBodyBytes {
		return nil, ErrInvalidInput
	}
	value := string(encoded)
	return &value, nil
}

func nonnilHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return map[string]string{}
	}
	return headers
}

func storageSubscriptionID(value string) string {
	if value == "" {
		return nilUUIDValue
	}
	return value
}

func (client *Client) execute(
	ctx context.Context,
	timeout time.Duration,
	body []byte,
	parameters url.Values,
	expectRows bool,
	decode func([]byte) error,
) error {
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := requestContext.Err(); err != nil {
		return err
	}
	deadline, _ := requestContext.Deadline()
	budgetMilliseconds := time.Until(deadline) / time.Millisecond
	if budgetMilliseconds <= 0 {
		return context.DeadlineExceeded
	}
	requestURL := *client.endpoint
	values := requestURL.Query()
	values.Set("database", client.database)
	values.Set("max_execution_time", strconv.FormatFloat(float64(budgetMilliseconds)/1000, 'f', 3, 64))
	values.Set("timeout_overflow_mode", "throw")
	values.Set("output_format_json_quote_64bit_integers", "0")
	for key, entries := range parameters {
		for _, value := range entries {
			values.Add(key, value)
		}
	}
	requestURL.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return ErrInvalidInput
	}
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	request.Header.Set("Accept-Encoding", "identity")
	if client.username != "" {
		request.SetBasicAuth(client.username, client.password)
	}
	response, err := client.http.Do(request)
	if err != nil {
		if requestContext.Err() != nil {
			return requestContext.Err()
		}
		return ErrTransport
	}
	defer response.Body.Close()
	drainLimit := min(client.maxResponseBytes, int64(64<<10)) + 1
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, drainErr := io.Copy(io.Discard, io.LimitReader(response.Body, drainLimit))
		if contextErr := responseContextError(drainErr); contextErr != nil {
			return contextErr
		}
		if requestErr := requestContext.Err(); drainErr != nil && requestErr != nil {
			return requestErr
		}
		return &HTTPError{StatusCode: response.StatusCode}
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, client.maxResponseBytes+1))
	if err != nil {
		if contextErr := responseContextError(err); contextErr != nil {
			return contextErr
		}
		if requestContext.Err() != nil {
			return requestContext.Err()
		}
		return ErrInvalidResponse
	}
	if int64(len(encoded)) > client.maxResponseBytes {
		_, drainErr := io.Copy(io.Discard, io.LimitReader(response.Body, drainLimit))
		if contextErr := responseContextError(drainErr); contextErr != nil {
			return contextErr
		}
		if requestErr := requestContext.Err(); drainErr != nil && requestErr != nil {
			return requestErr
		}
		return ErrResponseTooLarge
	}
	if expectRows {
		if decode == nil || decode(encoded) != nil {
			return ErrInvalidResponse
		}
		return nil
	}
	if len(bytes.TrimSpace(encoded)) != 0 {
		return ErrInvalidResponse
	}
	return nil
}

func responseContextError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func accessIdentity(event AccessEvent) string {
	return strings.ToLower(event.TenantID) + "/" + event.EventID
}

func securityIdentity(event SecurityEvent) string {
	return strings.ToLower(event.TenantID) + "/" + event.EventID
}

func validBatchID(value string) bool {
	if !required(value, 128) {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character)) {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > MaxDatabaseIdentifierBytes || !((value[0] >= 'a' && value[0] <= 'z') ||
		(value[0] >= 'A' && value[0] <= 'Z') || value[0] == '_') {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_') {
			return false
		}
	}
	return true
}

func ValidDatabaseIdentifier(value string) bool {
	return validIdentifier(value)
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func durationDefault(value, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return value
}

func int64Default(value, fallback int64) int64 {
	if value == 0 {
		return fallback
	}
	return value
}

func intDefault(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}
