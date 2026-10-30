package analyticsconnections

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	insertReceiptSQL = "INSERT INTO connections_ingest_receipts_v1 FORMAT JSONEachRow"
	lookupReceiptSQL = `SELECT receipt_id,batch_id,event_id,tenant_id,installation_id,site_id,node_id,domain,listen_port,package_subscription_id,config_version_id,occurred_at,connections,payload_sha256,canonical_event_sha256,evidence_sha256,source_watermark,finalized_through,nats_stream,nats_durable,nats_stream_sequence,nats_consumer_sequence,puback_stream,puback_sequence,toBool(puback_duplicate) AS puback_duplicate,clickhouse_insert_token,state,state_rank,
toUInt8(receipt_id={receipt:String} AND batch_id={batch:String} AND installation_id={installation:String} AND site_id={site:UUID} AND node_id={node:UUID} AND domain={domain:String} AND listen_port={listen_port:UInt16} AND package_subscription_id={subscription:UUID} AND nats_stream={stream:String} AND nats_durable={durable:String} AND nats_stream_sequence={stream_sequence:UInt64} AND nats_consumer_sequence={consumer_sequence:UInt64} AND puback_stream={puback_stream:String} AND puback_sequence={puback_sequence:UInt64} AND puback_duplicate={puback_duplicate:UInt8} AND payload_sha256={payload_sha256:String} AND canonical_event_sha256={canonical_event_sha256:String} AND evidence_sha256={evidence_sha256:String} AND clickhouse_insert_token={clickhouse_token:String}) AS request_identity_match
FROM connections_ingest_receipts_v1 FINAL
WHERE tenant_id={tenant:UUID} AND event_id={event:String}
LIMIT 2 FORMAT JSONEachRow`
)

type ClickHouseConfig struct {
	Endpoint         string
	Database         string
	Username         string
	Password         string
	ConnectTimeout   time.Duration
	OperationTimeout time.Duration
	MaxResponseBytes int64
}

type ClickHouseWriter struct {
	endpoint         *url.URL
	database         string
	username         string
	password         string
	http             HTTPClient
	connectTimeout   time.Duration
	operationTimeout time.Duration
	maxResponseBytes int64
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

func NewClickHouseWriter(config ClickHouseConfig, client HTTPClient) (*ClickHouseWriter, error) {
	endpoint, err := url.Parse(strings.TrimSpace(config.Endpoint))
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && loopback(endpoint.Hostname()))) || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || !validID(config.Database) {
		return nil, ErrInvalidConfiguration
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = DefaultConnectTimeout
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = DefaultOperationTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if config.ConnectTimeout <= 0 || config.OperationTimeout <= 0 || config.MaxResponseBytes <= 0 || config.MaxResponseBytes > 16<<20 {
		return nil, ErrInvalidConfiguration
	}
	if client == nil {
		client = &http.Client{Timeout: config.OperationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	endpoint.Path = "/"
	return &ClickHouseWriter{endpoint: endpoint, database: config.Database, username: config.Username, password: config.Password, http: client, connectTimeout: config.ConnectTimeout, operationTimeout: config.OperationTimeout, maxResponseBytes: config.MaxResponseBytes}, nil
}

func (writer *ClickHouseWriter) Prepare(ctx context.Context, receipt Receipt) error {
	if writer == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	if err := validateReceipt(receipt); err != nil {
		return err
	}
	rows, err := writer.lookup(ctx, receipt)
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		for _, row := range rows {
			if err := validateReceiptLookup(receipt, row); err != nil {
				return err
			}
		}
		return nil
	}
	received := receipt
	received.State = StateReceived
	prepared := receipt
	prepared.State = StateClickHousePrepared
	return writer.insertRows(ctx, received, prepared)
}

func (writer *ClickHouseWriter) MarkBrokerAckObserved(ctx context.Context, receipt Receipt, ack PubAck) error {
	if writer == nil || ctx == nil || ack.Sequence == 0 || ack.Stream != receipt.Stream {
		return ErrInvalidDelivery
	}
	if err := validateReceipt(receipt); err != nil {
		return err
	}
	receipt.PubAck = ack
	receipt.State = StateBrokerAckObserved
	return writer.insert(ctx, receipt)
}

type receiptRow struct {
	ConfigVersionID       string       `json:"config_version_id"`
	ReceiptID             string       `json:"receipt_id"`
	BatchID               string       `json:"batch_id"`
	EventID               string       `json:"event_id"`
	TenantID              string       `json:"tenant_id"`
	InstallationID        string       `json:"installation_id"`
	SiteID                string       `json:"site_id"`
	NodeID                string       `json:"node_id"`
	Domain                string       `json:"domain"`
	ListenPort            uint16       `json:"listen_port"`
	PackageSubscriptionID string       `json:"package_subscription_id"`
	OccurredAt            time.Time    `json:"occurred_at"`
	Connections           uint64       `json:"connections"`
	PayloadSHA256         string       `json:"payload_sha256"`
	CanonicalEventSHA256  string       `json:"canonical_event_sha256"`
	EvidenceSHA256        string       `json:"evidence_sha256"`
	SourceWatermark       uint64       `json:"source_watermark"`
	FinalizedThrough      time.Time    `json:"finalized_through"`
	NATSStream            string       `json:"nats_stream"`
	NATSDurable           string       `json:"nats_durable"`
	NATSStreamSequence    uint64       `json:"nats_stream_sequence"`
	NATSConsumerSequence  uint64       `json:"nats_consumer_sequence"`
	PubAckStream          string       `json:"puback_stream"`
	PubAckSequence        uint64       `json:"puback_sequence"`
	PubAckDuplicate       bool         `json:"puback_duplicate"`
	ClickHouseToken       string       `json:"clickhouse_insert_token"`
	State                 ReceiptState `json:"state"`
	StateRank             uint8        `json:"state_rank"`
	RequestIdentityMatch  uint8        `json:"request_identity_match"`
}

var receiptLookupFields = map[string]struct{}{
	"config_version_id": {},
	"receipt_id":        {}, "batch_id": {}, "event_id": {}, "tenant_id": {}, "installation_id": {},
	"site_id": {}, "node_id": {}, "domain": {}, "listen_port": {}, "package_subscription_id": {}, "occurred_at": {}, "connections": {},
	"payload_sha256": {}, "canonical_event_sha256": {}, "evidence_sha256": {}, "source_watermark": {},
	"finalized_through": {}, "nats_stream": {}, "nats_durable": {}, "nats_stream_sequence": {},
	"nats_consumer_sequence": {}, "puback_stream": {}, "puback_sequence": {}, "puback_duplicate": {},
	"clickhouse_insert_token": {}, "state": {}, "state_rank": {}, "request_identity_match": {},
}

func (writer *ClickHouseWriter) lookup(ctx context.Context, receipt Receipt) ([]receiptRow, error) {
	values := url.Values{}
	values.Set("database", writer.database)
	values.Set("param_tenant", receipt.TenantID)
	values.Set("param_receipt", receipt.ReceiptID)
	values.Set("param_batch", receipt.BatchID)
	values.Set("param_event", receipt.EventID)
	values.Set("param_installation", receipt.InstallationID)
	values.Set("param_site", receipt.SiteID)
	values.Set("param_node", receipt.NodeID)
	values.Set("param_domain", receipt.Domain)
	values.Set("param_listen_port", strconv.FormatUint(uint64(receipt.ListenPort), 10))
	values.Set("param_subscription", storageUUID(receipt.PackageSubscriptionID))
	values.Set("param_stream", receipt.Stream)
	values.Set("param_durable", receipt.Durable)
	values.Set("param_stream_sequence", strconv.FormatUint(receipt.StreamSequence, 10))
	values.Set("param_consumer_sequence", strconv.FormatUint(receipt.ConsumerSequence, 10))
	values.Set("param_puback_stream", receipt.PubAck.Stream)
	values.Set("param_puback_sequence", strconv.FormatUint(receipt.PubAck.Sequence, 10))
	if receipt.PubAck.Duplicate {
		values.Set("param_puback_duplicate", "1")
	} else {
		values.Set("param_puback_duplicate", "0")
	}
	values.Set("param_payload_sha256", digestHex(receipt.PayloadSHA256))
	values.Set("param_canonical_event_sha256", digestHex(receipt.CanonicalEventSHA256))
	values.Set("param_evidence_sha256", digestHex(receipt.EvidenceSHA256))
	values.Set("param_clickhouse_token", receipt.ClickHouseToken)
	values.Set("output_format_json_quote_64bit_integers", "0")
	values.Set("date_time_output_format", "iso")
	body, err := writer.execute(ctx, lookupReceiptSQL, values, nil, true)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	rows := make([]receiptRow, 0, 2)
	for {
		first, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrReceiptConflict
		}
		row, err := decodeReceiptLookupObject(decoder, first)
		if err != nil {
			return nil, ErrReceiptConflict
		}
		rows = append(rows, row)
	}
	if len(rows) > 1 {
		return nil, ErrReceiptConflict
	}
	return rows, nil
}

func decodeReceiptLookupObject(decoder *json.Decoder, first json.Token) (receiptRow, error) {
	if delimiter, ok := first.(json.Delim); !ok || delimiter != '{' {
		return receiptRow{}, ErrReceiptConflict
	}
	fields := make(map[string]json.RawMessage, len(receiptLookupFields))
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return receiptRow{}, ErrReceiptConflict
		}
		if _, exists := fields[key]; exists {
			return receiptRow{}, ErrReceiptConflict
		}
		if _, ok := receiptLookupFields[key]; !ok {
			return receiptRow{}, ErrReceiptConflict
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return receiptRow{}, ErrReceiptConflict
		}
		fields[key] = raw
	}
	closing, err := decoder.Token()
	if err != nil {
		return receiptRow{}, ErrReceiptConflict
	}
	_, hasConfigVersion := fields["config_version_id"]
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' ||
		len(fields) != len(receiptLookupFields) && !(len(fields) == len(receiptLookupFields)-1 && !hasConfigVersion) {
		return receiptRow{}, ErrReceiptConflict
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return receiptRow{}, ErrReceiptConflict
	}
	var row receiptRow
	if err := json.Unmarshal(encoded, &row); err != nil {
		return receiptRow{}, ErrReceiptConflict
	}
	return row, nil
}

func validateReceiptLookup(receipt Receipt, row receiptRow) error {
	if receipt.SchemaVersion == 2 && row.ConfigVersionID != receipt.ConfigVersionID {
		return ErrReceiptConflict
	}
	requestedRank, ok := receiptStateRank(receipt.State)
	if !ok {
		return ErrReceiptConflict
	}
	storedRank, ok := receiptStateRank(row.State)
	if !ok || row.StateRank != storedRank || storedRank < requestedRank {
		return ErrReceiptConflict
	}
	if row.RequestIdentityMatch != 1 || row.ReceiptID != receipt.ReceiptID || row.BatchID != receipt.BatchID || row.EventID != receipt.EventID ||
		row.TenantID != receipt.TenantID || row.InstallationID != receipt.InstallationID || row.SiteID != receipt.SiteID ||
		row.NodeID != receipt.NodeID || row.Domain != receipt.Domain || row.ListenPort != receipt.ListenPort ||
		storageUUID(row.PackageSubscriptionID) != storageUUID(receipt.PackageSubscriptionID) || !row.OccurredAt.Equal(receipt.OccurredAt) ||
		row.Connections != receipt.Connections || row.SourceWatermark != receipt.SourceWatermark ||
		!row.FinalizedThrough.Equal(receipt.FinalizedThrough) || row.NATSStream != receipt.Stream ||
		row.NATSDurable != receipt.Durable || row.NATSStreamSequence != receipt.StreamSequence ||
		row.NATSConsumerSequence != receipt.ConsumerSequence || row.PubAckStream != receipt.PubAck.Stream ||
		row.PubAckSequence != receipt.PubAck.Sequence || row.PubAckDuplicate != receipt.PubAck.Duplicate ||
		row.ClickHouseToken != receipt.ClickHouseToken {
		return ErrReceiptConflict
	}
	for _, pair := range []struct {
		value string
		want  [sha256.Size]byte
	}{
		{row.PayloadSHA256, receipt.PayloadSHA256},
		{row.CanonicalEventSHA256, receipt.CanonicalEventSHA256},
		{row.EvidenceSHA256, receipt.EvidenceSHA256},
	} {
		digest, err := parseDigestHex(pair.value)
		if err != nil || digest != pair.want {
			return ErrReceiptConflict
		}
	}
	return nil
}

type receiptInsertRow struct {
	ConfigVersionID       string       `json:"config_version_id"`
	SchemaVersion         uint32       `json:"schema_version"`
	ReceiptID             string       `json:"receipt_id"`
	BatchID               string       `json:"batch_id"`
	EventID               string       `json:"event_id"`
	TenantID              string       `json:"tenant_id"`
	InstallationID        string       `json:"installation_id"`
	SiteID                string       `json:"site_id"`
	NodeID                string       `json:"node_id"`
	Domain                string       `json:"domain"`
	ListenPort            uint16       `json:"listen_port"`
	PackageSubscriptionID string       `json:"package_subscription_id"`
	OccurredAt            time.Time    `json:"occurred_at"`
	Connections           uint64       `json:"connections"`
	PayloadSHA256         string       `json:"payload_sha256"`
	CanonicalEventSHA256  string       `json:"canonical_event_sha256"`
	EvidenceSHA256        string       `json:"evidence_sha256"`
	SourceWatermark       uint64       `json:"source_watermark"`
	FinalizedThrough      time.Time    `json:"finalized_through"`
	NATSStream            string       `json:"nats_stream"`
	NATSDurable           string       `json:"nats_durable"`
	NATSStreamSequence    uint64       `json:"nats_stream_sequence"`
	NATSConsumerSequence  uint64       `json:"nats_consumer_sequence"`
	PubAckStream          string       `json:"puback_stream"`
	PubAckSequence        uint64       `json:"puback_sequence"`
	PubAckDuplicate       bool         `json:"puback_duplicate"`
	ClickHouseInsertToken string       `json:"clickhouse_insert_token"`
	State                 ReceiptState `json:"state"`
	StateRank             uint8        `json:"state_rank"`
}

func newReceiptInsertRow(receipt Receipt) (receiptInsertRow, bool) {
	rank, ok := receiptStateRank(receipt.State)
	if !ok {
		return receiptInsertRow{}, false
	}
	return receiptInsertRow{SchemaVersion: receipt.SchemaVersion, ConfigVersionID: storageUUID(receipt.ConfigVersionID), ReceiptID: receipt.ReceiptID, BatchID: receipt.BatchID, EventID: receipt.EventID, TenantID: receipt.TenantID, InstallationID: receipt.InstallationID, SiteID: receipt.SiteID, NodeID: receipt.NodeID, Domain: receipt.Domain, ListenPort: receipt.ListenPort, PackageSubscriptionID: storageUUID(receipt.PackageSubscriptionID), OccurredAt: receipt.OccurredAt.UTC(), Connections: receipt.Connections, PayloadSHA256: digestHex(receipt.PayloadSHA256), CanonicalEventSHA256: digestHex(receipt.CanonicalEventSHA256), EvidenceSHA256: digestHex(receipt.EvidenceSHA256), SourceWatermark: receipt.SourceWatermark, FinalizedThrough: receipt.FinalizedThrough.UTC(), NATSStream: receipt.Stream, NATSDurable: receipt.Durable, NATSStreamSequence: receipt.StreamSequence, NATSConsumerSequence: receipt.ConsumerSequence, PubAckStream: receipt.PubAck.Stream, PubAckSequence: receipt.PubAck.Sequence, PubAckDuplicate: receipt.PubAck.Duplicate, ClickHouseInsertToken: receipt.ClickHouseToken, State: receipt.State, StateRank: rank}, true
}

func (writer *ClickHouseWriter) insert(ctx context.Context, receipt Receipt) error {
	return writer.insertRows(ctx, receipt)
}

func (writer *ClickHouseWriter) insertRows(ctx context.Context, receipts ...Receipt) error {
	if len(receipts) == 0 {
		return ErrInvalidDelivery
	}
	encoded := make([]byte, 0, len(receipts)*512)
	for _, receipt := range receipts {
		insertRow, ok := newReceiptInsertRow(receipt)
		if !ok || receipt.ClickHouseToken != receipts[0].ClickHouseToken {
			return ErrInvalidDelivery
		}
		row, err := json.Marshal(insertRow)
		if err != nil {
			return ErrInvalidDelivery
		}
		encoded = append(encoded, row...)
		encoded = append(encoded, '\n')
	}
	requestToken := sha256.Sum256([]byte("cdnca.connections.insert.transition.v1\x00" + receipts[0].ClickHouseToken + "\x00" + string(receipts[len(receipts)-1].State)))
	values := url.Values{}
	values.Set("database", writer.database)
	values.Set("insert_deduplication_token", digestHex(requestToken))
	values.Set("date_time_input_format", "best_effort")
	if _, err := writer.execute(ctx, insertReceiptSQL, values, encoded, false); err != nil {
		return err
	}
	return nil
}

func receiptStateRank(state ReceiptState) (uint8, bool) {
	switch state {
	case StateReceived:
		return 1, true
	case StateClickHousePrepared:
		return 2, true
	case StateBrokerAckObserved:
		return 3, true
	default:
		return 0, false
	}
}

func (writer *ClickHouseWriter) execute(ctx context.Context, query string, values url.Values, body []byte, expectRows bool) ([]byte, error) {
	operationTimeout, err := clickHouseDispatchTimeout(ctx, writer.operationTimeout)
	if err != nil {
		return nil, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if values == nil {
		values = url.Values{}
	}
	values.Set("max_execution_time", strconv.FormatFloat(operationTimeout.Seconds(), 'f', 3, 64))
	requestURL := *writer.endpoint
	requestValues := requestURL.Query()
	for key, entries := range values {
		for _, value := range entries {
			requestValues.Add(key, value)
		}
	}
	requestURL.RawQuery = requestValues.Encode()
	payload := body
	if payload == nil {
		payload = []byte(query)
	} else {
		payload = append([]byte(query+"\n"), payload...)
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, requestURL.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if writer.username != "" {
		request.SetBasicAuth(writer.username, writer.password)
	}
	response, err := writer.http.Do(request)
	if err != nil {
		if requestCtx.Err() != nil {
			return nil, requestCtx.Err()
		}
		return nil, ErrClickHouseUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, min64(writer.maxResponseBytes, 64<<10)+1))
		return nil, ErrClickHouseUnavailable
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, writer.maxResponseBytes+1))
	if err != nil {
		if requestCtx.Err() != nil {
			return nil, requestCtx.Err()
		}
		return nil, ErrClickHouseUnavailable
	}
	if int64(len(encoded)) > writer.maxResponseBytes {
		return nil, ErrClickHouseUnavailable
	}
	if !expectRows && len(bytes.TrimSpace(encoded)) != 0 {
		return nil, ErrClickHouseUnavailable
	}
	return encoded, nil
}

func clickHouseDispatchTimeout(ctx context.Context, configured time.Duration) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	timeout := configured.Truncate(time.Millisecond)
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining.Truncate(time.Millisecond)
		}
	}
	if timeout < time.Millisecond {
		return 0, context.DeadlineExceeded
	}
	return timeout, nil
}

func validateReceipt(receipt Receipt) error {
	if (receipt.SchemaVersion != SchemaVersion && receipt.SchemaVersion != 2) || !validID(receipt.ReceiptID) || !validID(receipt.BatchID) || !validID(receipt.EventID) || !validID(receipt.Stream) || !validID(receipt.Durable) || receipt.StreamSequence == 0 || receipt.ConsumerSequence == 0 || receipt.SourceWatermark == 0 || receipt.FinalizedThrough.Before(receipt.OccurredAt) || !validConnectionDimensions(receipt.NodeID, receipt.Domain, receipt.ListenPort) || receipt.ClickHouseToken != ClickHouseInsertToken(receipt) {
		return ErrInvalidDelivery
	}
	configID, configErr := uuid.Parse(receipt.ConfigVersionID)
	if receipt.SchemaVersion == 2 && (configErr != nil || configID == uuid.Nil || configID.String() != receipt.ConfigVersionID) || receipt.SchemaVersion == 1 && receipt.ConfigVersionID != "" {
		return ErrInvalidDelivery
	}
	return nil
}

func storageUUID(value string) string {
	if value == "" {
		return uuid.Nil.String()
	}
	return value
}

func loopback(host string) bool { return host == "127.0.0.1" || host == "localhost" || host == "::1" }
func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

var _ Store = (*ClickHouseWriter)(nil)
