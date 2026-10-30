package analyticsconnections

import (
	"bytes"
	"context"
	"net/url"
	"strconv"
	"time"
)

const retentionClickHouseSQL = `SELECT
metric,
toString(tenant_id) AS tenant_id,
toString(package_subscription_id) AS subscription_id,
formatDateTime(period_start,'%Y-%m-%dT%H:%i:%SZ','UTC') AS period_start,
formatDateTime(period_end,'%Y-%m-%dT%H:%i:%SZ','UTC') AS period_end,
value,
formatDateTime(finalized_through,'%Y-%m-%dT%H:%i:%SZ','UTC') AS finalized_through,
toUInt64(toUnixTimestamp64Milli(observed_at)) AS source_watermark,
lower(source_evidence_digest) AS evidence_digest,
formatDateTime(period_end+INTERVAL 400 DAY,'%Y-%m-%dT%H:%i:%SZ','UTC') AS retention_until
FROM package_metric_finalized_v1
WHERE tenant_id={tenant:UUID}
AND package_subscription_id={subscription:UUID}
AND metric='connections'
AND period_start>={from:DateTime64(3)}
AND period_end<={to:DateTime64(3)}
ORDER BY period_start ASC,period_end ASC,metric ASC
LIMIT {limit:UInt64}
FORMAT JSONEachRow`

type ClickHouseRetentionReader struct {
	writer *ClickHouseWriter
	model  *RetentionReadModel
}

func NewClickHouseRetentionReader(config ClickHouseConfig, retention RetentionConfig, client HTTPClient) (*ClickHouseRetentionReader, error) {
	writer, err := NewClickHouseWriter(config, client)
	if err != nil {
		return nil, err
	}
	model, err := NewRetentionReadModel(retention)
	if err != nil {
		return nil, err
	}
	return &ClickHouseRetentionReader{writer: writer, model: model}, nil
}

func (reader *ClickHouseRetentionReader) Read(ctx context.Context, query RetentionQuery) ([]RetentionRow, error) {
	if reader == nil || reader.writer == nil || reader.model == nil {
		return nil, ErrInvalidConfiguration
	}
	if ctx == nil {
		return nil, ErrRetentionInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateRetentionQuery(query); err != nil {
		return nil, err
	}
	operationTimeout, err := retentionCallerTimeout(ctx, reader.writer.operationTimeout)
	if err != nil {
		return nil, err
	}
	limit := reader.model.maxRows + 1
	values := url.Values{}
	values.Set("database", reader.writer.database)
	values.Set("param_tenant", query.TenantID)
	values.Set("param_subscription", query.SubscriptionID)
	values.Set("param_from", query.From.Format(time.RFC3339Nano))
	values.Set("param_to", query.To.Format(time.RFC3339Nano))
	values.Set("param_limit", strconv.Itoa(limit))
	values.Set("max_execution_time", strconv.FormatFloat(operationTimeout.Seconds(), 'f', 3, 64))
	values.Set("max_result_rows", strconv.Itoa(limit))
	values.Set("result_overflow_mode", "throw")
	values.Set("output_format_json_quote_64bit_integers", "0")
	encoded, err := reader.writer.execute(ctx, retentionClickHouseSQL, values, nil, true)
	if err != nil {
		return nil, err
	}
	return reader.model.Read(ctx, query, bytes.NewReader(encoded))
}

func retentionCallerTimeout(ctx context.Context, configured time.Duration) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	timeout := configured.Truncate(time.Millisecond)
	if timeout <= 0 {
		return 0, context.DeadlineExceeded
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining.Truncate(time.Millisecond)
			if timeout <= 0 {
				return 0, context.DeadlineExceeded
			}
		}
	}
	return timeout, nil
}
