package analyticslog

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
)

const (
	finalizedAccessCursorDomain = "cdnca.analyticslog.finalized-access.cursor.v1"
	finalizedAccessExpiry       = 5 * time.Minute
	defaultFinalizedCapacity    = 32
	maximumFinalizedCapacity    = 256
)

const finalizedAccessSQL = `WITH
if({has_snapshot:UInt8}=1,
    fromUnixTimestamp64Milli({snapshot_ms:Int64}, 'UTC'),
    fromUnixTimestamp64Milli({now_ms:Int64}, 'UTC') - INTERVAL 1 MILLISECOND
) AS snapshot_at,
latest_rows AS
(
    SELECT tenant_id, event_id,
        argMaxMerge(latest_payload_state) AS latest,
        maxMerge(latest_ingested_at_state) AS latest_ingested_at
    FROM access_event_latest_state_v1
    PREWHERE metric_version=1 AND tenant_id={tenant_id:UUID}
    WHERE ingested_at<=snapshot_at
    GROUP BY tenant_id,event_id
),
conflicts AS
(
    SELECT event_id,
        if(uniqExactMerge(version_pair_state)>uniqExactMerge(ingested_at_state),toUInt64(2),toUInt64(1)) AS version_count
    FROM access_event_conflict_state_v1
    PREWHERE metric_version=1 AND tenant_id={tenant_id:UUID}
    WHERE ingested_at<=snapshot_at
    GROUP BY event_id
),
scoped_latest AS
(
    SELECT latest_rows.*,
        toUInt64(ifNull(conflicts.version_count,1)) AS version_count
    FROM latest_rows
    LEFT JOIN conflicts USING (event_id)
    WHERE tupleElement(latest,2)>={from:DateTime64(3,'UTC')}
      AND tupleElement(latest,2)<{to:DateTime64(3,'UTC')}
      AND ({has_site:UInt8}=0 OR tupleElement(latest,3)={site_id:UUID})
      AND ({has_node:UInt8}=0 OR tupleElement(latest,4)={node_id:UUID})
),
fact_rows AS
(
    SELECT tenant_id,event_id,
        argMax(tuple(site_id,ingested_at,source_watermark,finalized_through),ingested_at) AS fact
    FROM site_realtime_access_facts_v1
    PREWHERE metric_version=1 AND tenant_id={tenant_id:UUID}
    WHERE ingested_at<=snapshot_at
    GROUP BY tenant_id,event_id
),
authoritative AS
(
    SELECT scoped_latest.*,
        tupleElement(fact_rows.fact,3) AS source_watermark,
        tupleElement(fact_rows.fact,4) AS finalized_through
    FROM scoped_latest
    INNER JOIN fact_rows USING (tenant_id,event_id)
    WHERE tupleElement(fact_rows.fact,1)=tupleElement(scoped_latest.latest,3)
      AND tupleElement(fact_rows.fact,2)=scoped_latest.latest_ingested_at
      AND tupleElement(fact_rows.fact,3)>0
      AND tupleElement(fact_rows.fact,4)<=snapshot_at
),
latest_stats AS
(
    SELECT toUInt64(count()) AS latest_count,
        toUInt64(countIf(version_count!=1)) AS conflict_count
    FROM scoped_latest
),
authority AS
(
    SELECT toUInt64(count()) AS authority_count,
        toUInt64(max(source_watermark)) AS source_watermark,
        toInt64(toUnixTimestamp64Milli(max(finalized_through))) AS finalized_through_ms,
        lower(hex(SHA256(toJSONString(tuple(
            count(),min(event_id),max(event_id),
            groupBitXor(cityHash64(tuple(event_id,latest_ingested_at,source_watermark,finalized_through)))
        ))))) AS evidence_digest
    FROM authoritative
),
diagnostics AS
(
    SELECT authoritative.*,
        multiIf(
            tupleElement(latest,23)='config_mismatch','config_mismatch',
            tupleElement(latest,15)='','no_host',
            tupleElement(latest,23)='no_host','no_host',
            tupleElement(latest,24)=530,'edge_530',
            tupleElement(latest,24)>=500 AND tupleElement(latest,24)<=599,'upstream_5xx',''
        ) AS category
    FROM authoritative
),
page AS
(
    SELECT * FROM diagnostics
    WHERE category!='' AND ({category:String}='' OR category={category:String})
      AND ({has_cursor:UInt8}=0
        OR tupleElement(latest,2)<{cursor_occurred_at:DateTime64(3,'UTC')}
        OR (tupleElement(latest,2)={cursor_occurred_at:DateTime64(3,'UTC')} AND event_id<{cursor_event_id:String}))
    ORDER BY tupleElement(latest,2) DESC,event_id DESC
    LIMIT {row_limit:UInt16}
)
SELECT * FROM
(
    SELECT 'meta' AS row_kind,toString({tenant_id:UUID}) AS tenant_id,
        '' AS event_id,toInt64(0) AS occurred_at_ms,'' AS site_id,'' AS node_id,
        '' AS request_id,'' AS trace_id,'' AS config_version_id,'' AS host,
        '' AS upstream_result,toUInt16(0) AS status_code,NULL AS task_id,'' AS installation_id,
        toUInt64(0) AS latest_version_count,
        toInt64(toUnixTimestamp64Milli(snapshot_at)) AS snapshot_ms,
        authority.source_watermark AS source_watermark,
        authority.finalized_through_ms AS finalized_through_ms,
        if({has_snapshot:UInt8}=1,{expires_at_ms:Int64},{now_ms:Int64}+300000) AS expires_at_ms,
        latest_stats.latest_count AS latest_count,authority.authority_count AS authority_count,
        latest_stats.conflict_count AS conflict_count,authority.evidence_digest AS evidence_digest
    FROM latest_stats CROSS JOIN authority
    UNION ALL
    SELECT 'event',toString(tenant_id),event_id,
        toInt64(toUnixTimestamp64Milli(tupleElement(latest,2))),
        toString(tupleElement(latest,3)),toString(tupleElement(latest,4)),
        tupleElement(latest,5),tupleElement(latest,6),tupleElement(latest,7),
        tupleElement(latest,15),tupleElement(latest,23),toUInt16(tupleElement(latest,24)),
        tupleElement(latest,8),tupleElement(latest,9),version_count,
        toInt64(toUnixTimestamp64Milli(snapshot_at)),authority.source_watermark,
        authority.finalized_through_ms,
        if({has_snapshot:UInt8}=1,{expires_at_ms:Int64},{now_ms:Int64}+300000),
        latest_stats.latest_count,authority.authority_count,latest_stats.conflict_count,authority.evidence_digest
    FROM page CROSS JOIN latest_stats CROSS JOIN authority
)
ORDER BY row_kind='meta' DESC,occurred_at_ms DESC,event_id DESC
FORMAT JSONEachRow`

type FinalizedAccessConfig struct {
	QueryTimeout  time.Duration
	MaxConcurrent int
	Now           func() time.Time
}

type FinalizedAccessRequest struct {
	TenantID string
	From     time.Time
	To       time.Time
	SiteID   string
	NodeID   string
	Category string
	Limit    uint16
	Cursor   string
	Snapshot *analyticsrealtime.Snapshot
}

type FinalizedAccessFact struct {
	TenantID string
	Log      AccessLog
}

type FinalizedAccessPage struct {
	Facts      []FinalizedAccessFact
	NextCursor string
	Snapshot   analyticsrealtime.Snapshot
}

type FinalizedAccessReader interface {
	ReadFinalizedAccess(context.Context, FinalizedAccessRequest) (FinalizedAccessPage, error)
}

type FinalizedAccessSource struct {
	client       *Client
	queryTimeout time.Duration
	capacity     chan struct{}
	now          func() time.Time
}

func NewFinalizedAccessSource(client *Client, config FinalizedAccessConfig) (*FinalizedAccessSource, error) {
	if client == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = client.queryTimeout
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = defaultFinalizedCapacity
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.QueryTimeout < time.Millisecond || config.QueryTimeout > 30*time.Second ||
		config.MaxConcurrent < 1 || config.MaxConcurrent > maximumFinalizedCapacity {
		return nil, ErrInvalidConfiguration
	}
	return &FinalizedAccessSource{
		client: client, queryTimeout: config.QueryTimeout,
		capacity: make(chan struct{}, config.MaxConcurrent), now: config.Now,
	}, nil
}

func (source *FinalizedAccessSource) ReadFinalizedAccess(
	ctx context.Context,
	request FinalizedAccessRequest,
) (FinalizedAccessPage, error) {
	if source == nil || source.client == nil || source.capacity == nil || source.now == nil || ctx == nil {
		return FinalizedAccessPage{}, ErrStorageUnavailable
	}
	if err := ctx.Err(); err != nil {
		return FinalizedAccessPage{}, err
	}
	select {
	case source.capacity <- struct{}{}:
		defer func() { <-source.capacity }()
	case <-ctx.Done():
		return FinalizedAccessPage{}, ctx.Err()
	default:
		return FinalizedAccessPage{}, ErrStorageUnavailable
	}

	now := source.now().UTC().Truncate(time.Millisecond)
	if now.IsZero() || validateFinalizedAccessRequest(request, now) != nil {
		return FinalizedAccessPage{}, ErrInvalidInput
	}
	fingerprint := finalizedAccessFingerprint(request)
	var cursor finalizedAccessCursor
	var err error
	if request.Cursor != "" {
		cursor, err = decodeFinalizedAccessCursor(source.client.cursorKeys, request.Cursor, fingerprint)
		if err != nil || request.Snapshot == nil || !cursor.matchesSnapshot(*request.Snapshot) {
			return FinalizedAccessPage{}, ErrInvalidInput
		}
	}

	queryCtx, cancel := context.WithTimeout(ctx, source.queryTimeout)
	defer cancel()
	parameters := finalizedAccessParameters(request, cursor, now)
	rows, err := queryRows[finalizedAccessWireRow](
		source.client, queryCtx, finalizedAccessSQL, parameters, int(request.Limit)+2,
	)
	if err != nil {
		if queryCtx.Err() != nil {
			return FinalizedAccessPage{}, queryCtx.Err()
		}
		return FinalizedAccessPage{}, err
	}
	if err := queryCtx.Err(); err != nil {
		return FinalizedAccessPage{}, err
	}
	return finalizedAccessPage(rows, request, cursor, fingerprint, source.client.cursorKeys, now)
}

type finalizedAccessWireRow struct {
	RowKind            string  `json:"row_kind"`
	TenantID           string  `json:"tenant_id"`
	EventID            string  `json:"event_id"`
	OccurredAtMS       int64   `json:"occurred_at_ms"`
	SiteID             string  `json:"site_id"`
	NodeID             string  `json:"node_id"`
	RequestID          string  `json:"request_id"`
	TraceID            string  `json:"trace_id"`
	ConfigVersion      string  `json:"config_version_id"`
	Host               string  `json:"host"`
	UpstreamResult     string  `json:"upstream_result"`
	StatusCode         uint16  `json:"status_code"`
	TaskID             *string `json:"task_id"`
	InstallationID     string  `json:"installation_id"`
	VersionCount       uint64  `json:"latest_version_count"`
	SnapshotMS         int64   `json:"snapshot_ms"`
	SourceWatermark    uint64  `json:"source_watermark"`
	FinalizedThroughMS int64   `json:"finalized_through_ms"`
	ExpiresAtMS        int64   `json:"expires_at_ms"`
	LatestCount        uint64  `json:"latest_count"`
	AuthorityCount     uint64  `json:"authority_count"`
	ConflictCount      uint64  `json:"conflict_count"`
	EvidenceDigest     string  `json:"evidence_digest"`
}

type finalizedAccessCursor struct {
	Version            uint8  `json:"v"`
	Query              string `json:"q"`
	SnapshotMS         int64  `json:"s"`
	SourceWatermark    uint64 `json:"w"`
	FinalizedThroughMS int64  `json:"f"`
	ExpiresAtMS        int64  `json:"x"`
	EvidenceDigest     string `json:"d"`
	OccurredAtMS       int64  `json:"o"`
	EventID            string `json:"e"`
}

func validateFinalizedAccessRequest(request FinalizedAccessRequest, now time.Time) error {
	if !validCanonicalUUID(request.TenantID) || !validFinalizedAccessTime(request.From) ||
		!validFinalizedAccessTime(request.To) || !request.From.Before(request.To) ||
		request.To.After(now) || request.To.Sub(request.From) > 31*24*time.Hour ||
		request.SiteID != "" && !validCanonicalUUID(request.SiteID) ||
		request.NodeID != "" && !validCanonicalUUID(request.NodeID) ||
		!validFinalizedAccessCategory(request.Category) || request.Limit == 0 || request.Limit > MaxLimit ||
		len(request.Cursor) > maxLogCursorBytes || (request.Cursor == "") != (request.Snapshot == nil) {
		return ErrInvalidInput
	}
	if request.Snapshot != nil && !validFinalizedAccessSnapshot(*request.Snapshot, request.To, now) {
		return ErrInvalidInput
	}
	return nil
}

func validFinalizedAccessCategory(value string) bool {
	switch value {
	case "", "upstream_5xx", "edge_530", "no_host", "config_mismatch":
		return true
	default:
		return false
	}
}

func validFinalizedAccessTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(value.Truncate(time.Millisecond))
}

func validFinalizedAccessSnapshot(snapshot analyticsrealtime.Snapshot, through, now time.Time) bool {
	return snapshot.SourceWatermark > 0 && validFinalizedAccessTime(snapshot.At) &&
		validFinalizedAccessTime(snapshot.FinalizedThrough) && validFinalizedAccessTime(snapshot.ExpiresAt) &&
		!snapshot.FinalizedThrough.Before(through) && !snapshot.FinalizedThrough.After(snapshot.At) &&
		snapshot.ExpiresAt.After(now) && snapshot.ExpiresAt.After(snapshot.At)
}

func finalizedAccessFingerprint(request FinalizedAccessRequest) string {
	parameters := url.Values{
		"tenant_id": {request.TenantID}, "from_ms": {strconv.FormatInt(request.From.UnixMilli(), 10)},
		"to_ms": {strconv.FormatInt(request.To.UnixMilli(), 10)}, "site_id": {request.SiteID},
		"node_id": {request.NodeID}, "category": {request.Category},
		"limit": {strconv.FormatUint(uint64(request.Limit), 10)}, "dimension": {"access.desc"},
	}
	digest := sha256.Sum256([]byte("finalized-access-v1\x00" + parameters.Encode()))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func finalizedAccessParameters(request FinalizedAccessRequest, cursor finalizedAccessCursor, now time.Time) url.Values {
	snapshotMS := now.Add(-time.Millisecond).UnixMilli()
	expiresMS := now.Add(finalizedAccessExpiry).UnixMilli()
	if request.Snapshot != nil {
		snapshotMS = request.Snapshot.At.UnixMilli()
		expiresMS = request.Snapshot.ExpiresAt.UnixMilli()
	}
	siteID, hasSite := finalizedOptionalUUID(request.SiteID)
	nodeID, hasNode := finalizedOptionalUUID(request.NodeID)
	return url.Values{
		"param_tenant_id": {request.TenantID}, "param_from": {request.From.Format(time.RFC3339Nano)},
		"param_to": {request.To.Format(time.RFC3339Nano)}, "param_has_site": {finalizedBool(hasSite)},
		"param_site_id": {siteID}, "param_has_node": {finalizedBool(hasNode)}, "param_node_id": {nodeID},
		"param_category": {request.Category}, "param_has_cursor": {finalizedBool(request.Cursor != "")},
		"param_cursor_occurred_at": {time.UnixMilli(cursor.OccurredAtMS).UTC().Format(time.RFC3339Nano)},
		"param_cursor_event_id":    {cursor.EventID}, "param_row_limit": {strconv.FormatUint(uint64(request.Limit+1), 10)},
		"param_has_snapshot": {finalizedBool(request.Snapshot != nil)}, "param_snapshot_ms": {strconv.FormatInt(snapshotMS, 10)},
		"param_expires_at_ms": {strconv.FormatInt(expiresMS, 10)}, "param_now_ms": {strconv.FormatInt(now.UnixMilli(), 10)},
	}
}

func finalizedOptionalUUID(value string) (string, bool) {
	if value == "" {
		return nilUUID, false
	}
	return value, true
}

func finalizedBool(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func finalizedAccessPage(
	rows []finalizedAccessWireRow,
	request FinalizedAccessRequest,
	cursor finalizedAccessCursor,
	fingerprint string,
	keyring CursorKeyring,
	now time.Time,
) (FinalizedAccessPage, error) {
	var metadata *finalizedAccessWireRow
	events := make([]finalizedAccessWireRow, 0, len(rows))
	for index := range rows {
		row := rows[index]
		switch row.RowKind {
		case "meta":
			if metadata != nil {
				return FinalizedAccessPage{}, ErrInvalidResponse
			}
			metadata = &row
		case "event":
			events = append(events, row)
		default:
			return FinalizedAccessPage{}, ErrInvalidResponse
		}
	}
	if metadata == nil || metadata.TenantID != request.TenantID || metadata.LatestCount == 0 ||
		metadata.LatestCount != metadata.AuthorityCount || metadata.ConflictCount != 0 ||
		!validEvidenceDigest(metadata.EvidenceDigest) || len(events) > int(request.Limit)+1 {
		return FinalizedAccessPage{}, ErrInvalidResponse
	}
	snapshot := analyticsrealtime.Snapshot{
		At: time.UnixMilli(metadata.SnapshotMS).UTC(), SourceWatermark: metadata.SourceWatermark,
		FinalizedThrough: time.UnixMilli(metadata.FinalizedThroughMS).UTC(),
		ExpiresAt:        time.UnixMilli(metadata.ExpiresAtMS).UTC(),
	}
	if !validFinalizedAccessSnapshot(snapshot, request.To, now) {
		return FinalizedAccessPage{}, ErrInvalidResponse
	}
	if request.Snapshot == nil {
		if !snapshot.At.Equal(now.Add(-time.Millisecond)) || !snapshot.ExpiresAt.Equal(now.Add(finalizedAccessExpiry)) {
			return FinalizedAccessPage{}, ErrInvalidResponse
		}
	} else if snapshot != *request.Snapshot || cursor.EvidenceDigest != metadata.EvidenceDigest {
		return FinalizedAccessPage{}, ErrInvalidResponse
	}

	seen := make(map[string]struct{}, len(events))
	facts := make([]FinalizedAccessFact, 0, min(len(events), int(request.Limit)))
	for index, row := range events {
		if !sameFinalizedMetadata(*metadata, row) || !validFinalizedAccessEvent(row, request) {
			return FinalizedAccessPage{}, ErrInvalidResponse
		}
		if _, duplicate := seen[row.EventID]; duplicate {
			return FinalizedAccessPage{}, ErrInvalidResponse
		}
		seen[row.EventID] = struct{}{}
		if index > 0 && !rowsOrdered(events[index-1].OccurredAtMS, events[index-1].EventID, row.OccurredAtMS, row.EventID) ||
			cursor.EventID != "" && !rowsOrdered(cursor.OccurredAtMS, cursor.EventID, row.OccurredAtMS, row.EventID) {
			return FinalizedAccessPage{}, ErrInvalidResponse
		}
		if index < int(request.Limit) {
			facts = append(facts, FinalizedAccessFact{TenantID: row.TenantID, Log: finalizedAccessLog(row)})
		}
	}
	page := FinalizedAccessPage{Facts: facts, Snapshot: snapshot}
	if len(events) > int(request.Limit) {
		last := events[request.Limit-1]
		page.NextCursor, _ = encodeFinalizedAccessCursor(keyring, finalizedAccessCursor{
			Version: 1, Query: fingerprint, SnapshotMS: snapshot.At.UnixMilli(),
			SourceWatermark: snapshot.SourceWatermark, FinalizedThroughMS: snapshot.FinalizedThrough.UnixMilli(),
			ExpiresAtMS: snapshot.ExpiresAt.UnixMilli(), EvidenceDigest: metadata.EvidenceDigest,
			OccurredAtMS: last.OccurredAtMS, EventID: last.EventID,
		})
		if page.NextCursor == "" {
			return FinalizedAccessPage{}, ErrInvalidResponse
		}
	}
	return page, nil
}

func validFinalizedAccessEvent(row finalizedAccessWireRow, request FinalizedAccessRequest) bool {
	occurredAt := time.UnixMilli(row.OccurredAtMS).UTC()
	log := finalizedAccessLog(row)
	return row.TenantID == request.TenantID && row.VersionCount == 1 && validEventID(row.EventID) &&
		validCanonicalUUID(row.SiteID) && validCanonicalUUID(row.NodeID) &&
		validOutputText(row.RequestID, 128, true) && validOutputText(row.TraceID, 128, true) &&
		validCanonicalUUID(row.ConfigVersion) && validCanonicalUUID(row.InstallationID) &&
		validOutputText(row.Host, 253, false) && validOutputText(row.UpstreamResult, 64, false) &&
		(row.TaskID == nil || validCanonicalUUID(*row.TaskID)) && row.StatusCode >= 100 && row.StatusCode <= 599 &&
		!occurredAt.Before(request.From) && occurredAt.Before(request.To) &&
		(request.SiteID == "" || row.SiteID == request.SiteID) && (request.NodeID == "" || row.NodeID == request.NodeID) &&
		finalizedAccessCategory(log) != "" && (request.Category == "" || finalizedAccessCategory(log) == request.Category)
}

func finalizedAccessCategory(log AccessLog) string {
	switch {
	case log.UpstreamResult == "config_mismatch":
		return "config_mismatch"
	case log.Host == "" || log.UpstreamResult == "no_host":
		return "no_host"
	case log.StatusCode == 530:
		return "edge_530"
	case log.StatusCode >= 500 && log.StatusCode <= 599:
		return "upstream_5xx"
	default:
		return ""
	}
}

func finalizedAccessLog(row finalizedAccessWireRow) AccessLog {
	return AccessLog{
		EventID: row.EventID, OccurredAt: time.UnixMilli(row.OccurredAtMS).UTC(), SiteID: row.SiteID,
		NodeID: row.NodeID, RequestID: row.RequestID, TraceID: row.TraceID, ConfigVersion: row.ConfigVersion,
		Host: row.Host, UpstreamResult: row.UpstreamResult, StatusCode: row.StatusCode,
		TaskID: row.TaskID, InstallationID: row.InstallationID,
	}
}

func sameFinalizedMetadata(metadata, row finalizedAccessWireRow) bool {
	return row.SnapshotMS == metadata.SnapshotMS && row.SourceWatermark == metadata.SourceWatermark &&
		row.FinalizedThroughMS == metadata.FinalizedThroughMS && row.ExpiresAtMS == metadata.ExpiresAtMS &&
		row.LatestCount == metadata.LatestCount && row.AuthorityCount == metadata.AuthorityCount &&
		row.ConflictCount == metadata.ConflictCount && row.EvidenceDigest == metadata.EvidenceDigest
}

func validEvidenceDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && !bytes.Equal(decoded, make([]byte, sha256.Size))
}

func (cursor finalizedAccessCursor) matchesSnapshot(snapshot analyticsrealtime.Snapshot) bool {
	return cursor.SnapshotMS == snapshot.At.UnixMilli() && cursor.SourceWatermark == snapshot.SourceWatermark &&
		cursor.FinalizedThroughMS == snapshot.FinalizedThrough.UnixMilli() && cursor.ExpiresAtMS == snapshot.ExpiresAt.UnixMilli()
}

func encodeFinalizedAccessCursor(keyring CursorKeyring, cursor finalizedAccessCursor) (string, error) {
	payload, err := json.Marshal(cursor)
	key, ok := keyring.Keys[keyring.ActiveKID]
	if err != nil || !ok {
		return "", ErrInvalidResponse
	}
	packet, err := json.Marshal(logCursorEnvelope{
		Payload: base64.RawURLEncoding.EncodeToString(payload), KID: keyring.ActiveKID,
		Tag: base64.RawURLEncoding.EncodeToString(logCursorMAC(finalizedAccessCursorDomain, keyring.ActiveKID, payload, key)),
	})
	if err != nil {
		return "", ErrInvalidResponse
	}
	encoded := base64.RawURLEncoding.EncodeToString(packet)
	if len(encoded) > maxLogCursorBytes {
		return "", ErrInvalidResponse
	}
	return encoded, nil
}

func decodeFinalizedAccessCursor(keyring CursorKeyring, encoded, fingerprint string) (finalizedAccessCursor, error) {
	packet, ok := decodeCanonicalRawURL(encoded, 1, maxLogCursorBytes)
	if !ok {
		return finalizedAccessCursor{}, ErrInvalidInput
	}
	payload, kid, tag, ok := decodeLogCursorEnvelope(packet)
	key, keyOK := keyring.Keys[kid]
	if !ok || !keyOK || !hmac.Equal(tag, logCursorMAC(finalizedAccessCursorDomain, kid, payload, key)) {
		return finalizedAccessCursor{}, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var cursor finalizedAccessCursor
	if decoder.Decode(&cursor) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return finalizedAccessCursor{}, ErrInvalidInput
	}
	canonical, err := json.Marshal(cursor)
	if err != nil || !bytes.Equal(canonical, payload) || cursor.Version != 1 || cursor.Query != fingerprint ||
		cursor.SnapshotMS <= 0 || cursor.SourceWatermark == 0 || cursor.FinalizedThroughMS <= 0 ||
		cursor.ExpiresAtMS <= cursor.SnapshotMS || !validEvidenceDigest(cursor.EvidenceDigest) ||
		cursor.OccurredAtMS <= 0 || !validEventID(cursor.EventID) {
		return finalizedAccessCursor{}, ErrInvalidInput
	}
	return cursor, nil
}

var _ FinalizedAccessReader = (*FinalizedAccessSource)(nil)
