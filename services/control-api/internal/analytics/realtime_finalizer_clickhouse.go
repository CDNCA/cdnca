package analytics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maximumRealtimeConnectionEvidenceNodes = 10_000

const realtimeConnectionCoverageSQL = `SELECT
	toString(node_id) AS result_node_id,
	if(countIf(schema_version=2)>0,anyIf(toString(config_version_id),schema_version=2),'') AS result_config_version_id,
	toUInt64(uniqExactIf(config_version_id,schema_version=2)) AS config_version_count,
	toUInt64(max(source_watermark)) AS max_source_watermark,
	toInt64(toUnixTimestamp64Milli(min(finalized_through))) AS finalized_through_ms,
	lower(hex(SHA256(arrayStringConcat(arraySort(groupUniqArray(
		concat(toString(source_watermark),':',evidence_sha256)
	)), '\n')))) AS aggregate_evidence_sha256,
	toUInt64(uniqExact(source_watermark)) AS watermark_count,
	toUInt64(uniqExact(tuple(source_watermark,evidence_sha256))) AS watermark_evidence_count,
	toUInt64(uniqExact(installation_id)) AS installation_count,
	toUInt64(uniqExact(package_subscription_id)) AS subscription_count
FROM connections_ingest_receipts_v1 FINAL
WHERE schema_version IN (1,2) AND state_rank>=2
	AND tenant_id={tenant_id:UUID} AND site_id={site_id:UUID}
	AND domain={domain:String} AND listen_port={listen_port:UInt16}
	AND occurred_at>=fromUnixTimestamp64Milli({window_start_ms:UInt64},'UTC')
	AND occurred_at<=fromUnixTimestamp64Milli({window_end_ms:UInt64},'UTC')
	AND finalized_through=fromUnixTimestamp64Milli({window_end_ms:UInt64},'UTC')
	AND node_id!=toUUID('00000000-0000-0000-0000-000000000000')
	AND source_watermark>0 AND length(evidence_sha256)=64
GROUP BY node_id
ORDER BY node_id
LIMIT 10001
FORMAT JSONEachRow`

type ClickHouseRealtimeConnectionEvidenceReader struct {
	client *Client
}

func NewClickHouseRealtimeConnectionEvidenceReader(
	client *Client,
) (*ClickHouseRealtimeConnectionEvidenceReader, error) {
	if client == nil {
		return nil, ErrInvalidServiceConfig
	}
	return &ClickHouseRealtimeConnectionEvidenceReader{client: client}, nil
}

type realtimeConnectionCoverageWireRow struct {
	ConfigVersionID        string `json:"result_config_version_id"`
	ConfigVersionCount     uint64 `json:"config_version_count"`
	NodeID                 string `json:"result_node_id"`
	SourceWatermark        uint64 `json:"max_source_watermark"`
	FinalizedThroughMS     int64  `json:"finalized_through_ms"`
	EvidenceSHA256         string `json:"aggregate_evidence_sha256"`
	WatermarkCount         uint64 `json:"watermark_count"`
	WatermarkEvidenceCount uint64 `json:"watermark_evidence_count"`
	InstallationCount      uint64 `json:"installation_count"`
	SubscriptionCount      uint64 `json:"subscription_count"`
}

func (reader *ClickHouseRealtimeConnectionEvidenceReader) RealtimeConnectionEvidence(
	ctx context.Context,
	candidate RealtimeCoverageCandidateV1,
) ([]RealtimeConnectionEvidenceV1, error) {
	if reader == nil || reader.client == nil || ctx == nil || !validRealtimeCoverageCandidate(candidate) {
		return nil, ErrRealtimeCoverageConflict
	}
	parameters := url.Values{
		"param_tenant_id":       {candidate.TenantID},
		"param_site_id":         {candidate.SiteID},
		"param_domain":          {candidate.Host},
		"param_listen_port":     {strconv.FormatUint(uint64(candidate.ListenPort), 10)},
		"param_window_start_ms": {strconv.FormatInt(candidate.WindowStart.UnixMilli(), 10)},
		"param_window_end_ms":   {strconv.FormatInt(candidate.WindowEnd.UnixMilli(), 10)},
	}
	rows, err := queryRows[realtimeConnectionCoverageWireRow](
		reader.client, ctx, realtimeConnectionCoverageSQL, parameters, maximumRealtimeConnectionEvidenceNodes+1,
	)
	if err != nil {
		return nil, err
	}
	if len(rows) > maximumRealtimeConnectionEvidenceNodes {
		return nil, ErrRealtimeCoverageConflict
	}
	evidence := make([]RealtimeConnectionEvidenceV1, len(rows))
	for index, row := range rows {
		if row.ConfigVersionCount > 1 || row.ConfigVersionID != "" && (!validUUID(row.ConfigVersionID) || nilUUID(row.ConfigVersionID)) {
			return nil, ErrRealtimeCoverageConflict
		}
		finalizedThrough := time.UnixMilli(row.FinalizedThroughMS).UTC()
		if !validUUID(row.NodeID) || strings.ToLower(row.NodeID) != row.NodeID ||
			index > 0 && rows[index-1].NodeID >= row.NodeID || row.SourceWatermark == 0 ||
			!finalizedThrough.Equal(candidate.WindowEnd) || row.WatermarkCount == 0 ||
			row.WatermarkEvidenceCount != row.WatermarkCount || row.InstallationCount != 1 ||
			row.SubscriptionCount != 1 || len(row.EvidenceSHA256) != sha256.Size*2 ||
			strings.ToLower(row.EvidenceSHA256) != row.EvidenceSHA256 {
			return nil, ErrRealtimeCoverageConflict
		}
		digest, err := hex.DecodeString(row.EvidenceSHA256)
		if err != nil || len(digest) != sha256.Size || allZeroBytes(digest) {
			return nil, ErrRealtimeCoverageConflict
		}
		evidence[index] = RealtimeConnectionEvidenceV1{
			ConfigVersionID: row.ConfigVersionID,
			NodeID:          row.NodeID, SourceWatermark: row.SourceWatermark,
			FinalizedThrough: finalizedThrough, RecordedAt: finalizedThrough,
		}
		copy(evidence[index].EvidenceSHA256[:], digest)
		if !validRealtimeConnectionCoverage(evidence[index], candidate) {
			return nil, ErrRealtimeCoverageConflict
		}
	}
	return evidence, nil
}
