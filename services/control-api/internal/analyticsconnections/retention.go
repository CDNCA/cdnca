package analyticsconnections

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultRetentionTTL   = 400 * 24 * time.Hour
	DefaultRetentionRows  = 1024
	DefaultRetentionBytes = 1 << 20
	MaximumRetentionRows  = 4096
	MaximumRetentionBytes = 16 << 20
)

var (
	ErrRetentionUnavailable      = errors.New("connections retention unavailable")
	ErrRetentionInvalidResponse  = errors.New("invalid connections retention response")
	ErrRetentionResponseTooLarge = errors.New("connections retention response too large")
	ErrRetentionScopeMismatch    = errors.New("connections retention scope mismatch")
	ErrRetentionOrder            = errors.New("connections retention rows are not strictly ordered")
	ErrRetentionDuplicate        = errors.New("duplicate connections retention row")
	ErrRetentionExpired          = errors.New("connections retention row expired")
	ErrRetentionInvalidRequest   = errors.New("invalid connections retention request")
)

type RetentionConfig struct {
	MaxRows          int
	MaxResponseBytes int64
	TTL              time.Duration
	Now              func() time.Time
}

type RetentionQuery struct {
	TenantID       string
	SubscriptionID string
	From           time.Time
	To             time.Time
}

type RetentionRow struct {
	Metric           string
	TenantID         string
	SubscriptionID   string
	PeriodStart      time.Time
	PeriodEnd        time.Time
	Value            uint64
	FinalizedThrough time.Time
	SourceWatermark  uint64
	EvidenceDigest   [sha256.Size]byte
	RetentionUntil   time.Time
}

type RetentionReadModel struct {
	maxRows          int
	maxResponseBytes int64
	ttl              time.Duration
	now              func() time.Time
}

func NewRetentionReadModel(config RetentionConfig) (*RetentionReadModel, error) {
	if config.MaxRows == 0 {
		config.MaxRows = DefaultRetentionRows
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = DefaultRetentionBytes
	}
	if config.TTL == 0 {
		config.TTL = DefaultRetentionTTL
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxRows <= 0 || config.MaxRows > MaximumRetentionRows || config.MaxResponseBytes <= 0 ||
		config.MaxResponseBytes > MaximumRetentionBytes || config.TTL <= 0 || config.TTL > DefaultRetentionTTL {
		return nil, ErrRetentionInvalidRequest
	}
	return &RetentionReadModel{maxRows: config.MaxRows, maxResponseBytes: config.MaxResponseBytes, ttl: config.TTL, now: config.Now}, nil
}

func (model *RetentionReadModel) Read(ctx context.Context, query RetentionQuery, response io.Reader) ([]RetentionRow, error) {
	if model == nil || response == nil {
		return nil, ErrRetentionUnavailable
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
	encoded, err := io.ReadAll(io.LimitReader(response, model.maxResponseBytes+1))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrRetentionUnavailable
	}
	if int64(len(encoded)) > model.maxResponseBytes {
		return nil, ErrRetentionResponseTooLarge
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	encoded = bytes.TrimSpace(encoded)
	if len(encoded) == 0 {
		return nil, ErrRetentionInvalidResponse
	}
	lines := bytes.Split(encoded, []byte{'\n'})
	if len(lines) > model.maxRows {
		return nil, ErrRetentionResponseTooLarge
	}
	rows := make([]RetentionRow, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	var previous *RetentionRow
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			return nil, ErrRetentionInvalidResponse
		}
		row, err := decodeRetentionRow(line, query, model.ttl, model.now().UTC())
		if err != nil {
			return nil, err
		}
		identity := row.Metric + "\x00" + row.PeriodStart.Format(time.RFC3339Nano) + "\x00" + row.PeriodEnd.Format(time.RFC3339Nano)
		if _, exists := seen[identity]; exists {
			return nil, ErrRetentionDuplicate
		}
		seen[identity] = struct{}{}
		if previous != nil && !retentionRowAfter(*previous, row) {
			return nil, ErrRetentionOrder
		}
		copyRow := row
		previous = &copyRow
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, ErrRetentionInvalidResponse
	}
	return rows, nil
}

var retentionFields = map[string]struct{}{
	"metric": {}, "tenant_id": {}, "subscription_id": {}, "period_start": {}, "period_end": {},
	"value": {}, "finalized_through": {}, "source_watermark": {}, "evidence_digest": {}, "retention_until": {},
}

func decodeRetentionRow(line []byte, query RetentionQuery, ttl time.Duration, now time.Time) (RetentionRow, error) {
	fields, err := decodeRetentionObject(line)
	if err != nil {
		return RetentionRow{}, ErrRetentionInvalidResponse
	}
	for key := range fields {
		if _, ok := retentionFields[key]; !ok {
			return RetentionRow{}, ErrRetentionInvalidResponse
		}
	}
	for key := range retentionFields {
		if _, ok := fields[key]; !ok {
			return RetentionRow{}, ErrRetentionInvalidResponse
		}
	}
	metric, err := strictString(fields["metric"])
	if err != nil || metric != "connections" {
		return RetentionRow{}, ErrRetentionInvalidResponse
	}
	tenant, err := strictString(fields["tenant_id"])
	if err != nil || tenant != query.TenantID {
		return RetentionRow{}, ErrRetentionScopeMismatch
	}
	subscription, err := strictString(fields["subscription_id"])
	if err != nil || subscription != query.SubscriptionID {
		return RetentionRow{}, ErrRetentionScopeMismatch
	}
	periodStart, err := strictUTC(fields["period_start"])
	if err != nil {
		return RetentionRow{}, ErrRetentionInvalidResponse
	}
	periodEnd, err := strictUTC(fields["period_end"])
	if err != nil || !periodStart.Before(periodEnd) || periodStart.Before(query.From) || periodEnd.After(query.To) {
		return RetentionRow{}, ErrRetentionInvalidResponse
	}
	value, err := strictUint(fields["value"])
	if err != nil || value == 0 {
		return RetentionRow{}, ErrRetentionInvalidResponse
	}
	finalizedThrough, err := strictUTC(fields["finalized_through"])
	if err != nil || !finalizedThrough.Equal(periodEnd) {
		return RetentionRow{}, ErrRetentionInvalidResponse
	}
	sourceWatermark, err := strictUint(fields["source_watermark"])
	if err != nil || sourceWatermark == 0 {
		return RetentionRow{}, ErrRetentionInvalidResponse
	}
	evidenceText, err := strictString(fields["evidence_digest"])
	if err != nil || len(evidenceText) != sha256.Size*2 || strings.ToLower(evidenceText) != evidenceText {
		return RetentionRow{}, ErrRetentionInvalidResponse
	}
	evidence, err := hex.DecodeString(evidenceText)
	if err != nil || len(evidence) != sha256.Size || allZero(evidence) {
		return RetentionRow{}, ErrRetentionInvalidResponse
	}
	retentionUntil, err := strictUTC(fields["retention_until"])
	if err != nil {
		return RetentionRow{}, ErrRetentionInvalidResponse
	}
	if retentionUntil.Before(now) {
		return RetentionRow{}, ErrRetentionExpired
	}
	if !retentionUntil.Equal(periodEnd.Add(ttl)) {
		return RetentionRow{}, ErrRetentionInvalidResponse
	}
	row := RetentionRow{Metric: metric, TenantID: tenant, SubscriptionID: subscription, PeriodStart: periodStart, PeriodEnd: periodEnd, Value: value, FinalizedThrough: finalizedThrough, SourceWatermark: sourceWatermark, RetentionUntil: retentionUntil}
	copy(row.EvidenceDigest[:], evidence)
	return row, nil
}

func decodeRetentionObject(line []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrRetentionInvalidResponse
	}
	fields := make(map[string]json.RawMessage, len(retentionFields))
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return nil, ErrRetentionInvalidResponse
		}
		if _, exists := fields[key]; exists {
			return nil, ErrRetentionInvalidResponse
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, ErrRetentionInvalidResponse
		}
		fields[key] = raw
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrRetentionInvalidResponse
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrRetentionInvalidResponse
	}
	return fields, nil
}

func strictString(raw json.RawMessage) (string, error) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || value == "" {
		return "", ErrRetentionInvalidResponse
	}
	return value, nil
}

func strictUTC(raw json.RawMessage) (time.Time, error) {
	value, err := strictString(raw)
	if err != nil || !strings.HasSuffix(value, "Z") {
		return time.Time{}, ErrRetentionInvalidResponse
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, ErrRetentionInvalidResponse
	}
	return parsed, nil
}

func strictUint(raw json.RawMessage) (uint64, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" || strings.HasPrefix(text, "-") || strings.ContainsAny(text, ".eE") {
		return 0, ErrRetentionInvalidResponse
	}
	value, err := strconv.ParseUint(text, 10, 64)
	return value, err
}

func validateRetentionQuery(query RetentionQuery) error {
	if !canonicalRetentionUUID(query.TenantID) || !canonicalRetentionUUID(query.SubscriptionID) || query.From.IsZero() || query.To.IsZero() ||
		query.From.Location() != time.UTC || query.To.Location() != time.UTC ||
		!query.From.Equal(query.From.Truncate(time.Millisecond)) || !query.To.Equal(query.To.Truncate(time.Millisecond)) ||
		!query.From.Before(query.To) || query.To.Sub(query.From) > DefaultRetentionTTL {
		return ErrRetentionInvalidRequest
	}
	return nil
}

func canonicalRetentionUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func retentionRowAfter(previous, current RetentionRow) bool {
	if current.PeriodStart.After(previous.PeriodStart) {
		return true
	}
	if !current.PeriodStart.Equal(previous.PeriodStart) {
		return false
	}
	if current.PeriodEnd.After(previous.PeriodEnd) {
		return true
	}
	return current.PeriodEnd.Equal(previous.PeriodEnd) && current.Metric > previous.Metric
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
