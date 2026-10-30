package analyticslog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

const exportSchemaAuthority = "MIGRATION_132"

type ExportLimits struct {
	MaxRows  int
	MaxBytes int
	PageSize uint16
}

type AccessExportArtifact struct {
	Bytes      []byte
	RowCount   int
	SHA256     string
	SnapshotAt time.Time
}

func buildAccessExportCSV(
	ctx context.Context,
	store Store,
	queryScope scope,
	filter Filter,
	limits ExportLimits,
	now func() time.Time,
) (AccessExportArtifact, error) {
	if now == nil {
		now = time.Now
	}
	if store == nil || limits.MaxRows <= 0 || limits.MaxRows > 100000 || limits.MaxBytes < 1024 ||
		limits.MaxBytes > 16<<20 || limits.PageSize == 0 || limits.PageSize > MaxLimit {
		return AccessExportArtifact{}, ErrInvalidConfiguration
	}
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	writer.UseCRLF = true
	header := []string{
		"event_id", "occurred_at", "site_id", "node_id", "host", "uri_path", "client_ip", "country_code",
		"carrier", "method", "protocol", "status_code", "upstream_result", "upstream_addr", "content_type", "user_agent", "cache_status",
		"request_bytes", "response_bytes", "duration_us", "origin_connect_us", "origin_first_byte_us", "origin_total_us",
	}
	if err := writer.Write(header); err != nil {
		return AccessExportArtifact{}, ErrStorageUnavailable
	}
	var snapshot time.Time
	cursor := ""
	rows := 0
	seen := make(map[string]struct{})
	var previous *AccessLog
	for {
		if err := ctx.Err(); err != nil {
			return AccessExportArtifact{}, err
		}
		page, err := store.ListAccess(ctx, queryScope, filter, limits.PageSize, cursor)
		if err != nil {
			return AccessExportArtifact{}, err
		}
		if err := validateAccessPage(page, limits.PageSize); err != nil {
			return AccessExportArtifact{}, err
		}
		if page.SnapshotAt.IsZero() && cursor == "" && len(page.Items) == 0 && page.NextCursor == "" {
			// TF-C04：条件合法但没有日志。首页 0 行时查询无法带回快照
			// （快照取自行），这不是无效响应：生成仅表头的 CSV，快照记为
			// 查询窗口的结束（不晚于当前时间）。
			snapshot = emptyExportSnapshot(filter, now)
			break
		}
		if page.SnapshotAt.IsZero() || !snapshot.IsZero() && !page.SnapshotAt.Equal(snapshot) {
			return AccessExportArtifact{}, ErrInvalidResponse
		}
		if snapshot.IsZero() {
			snapshot = page.SnapshotAt
		}
		for _, item := range page.Items {
			if rows >= limits.MaxRows {
				return AccessExportArtifact{}, ErrResponseTooLarge
			}
			if _, duplicate := seen[item.EventID]; duplicate || previous != nil &&
				!rowsOrdered(previous.OccurredAt.UnixMilli(), previous.EventID, item.OccurredAt.UnixMilli(), item.EventID) {
				return AccessExportArtifact{}, ErrInvalidResponse
			}
			seen[item.EventID] = struct{}{}
			record := []string{
				item.EventID, item.OccurredAt.UTC().Format(time.RFC3339Nano), item.SiteID, item.NodeID, item.Host,
				safeURIPath(item.URIPath), item.ClientIP, item.CountryCode, item.Carrier, item.Method, item.Protocol,
				strconv.FormatUint(uint64(item.StatusCode), 10), item.UpstreamResult, item.UpstreamAddr, accessContentType(item),
				accessHeader(item.RequestHeaders, "User-Agent", 512), item.CacheStatus,
				strconv.FormatUint(item.RequestBytes, 10), strconv.FormatUint(item.ResponseBytes, 10), strconv.FormatUint(item.DurationUS, 10),
				optionalUint64(item.OriginConnectUS), optionalUint64(item.OriginFirstByteUS), optionalUint64(item.OriginTotalUS),
			}
			for index := range record {
				record[index] = safeCSVCell(record[index])
			}
			if err := writer.Write(record); err != nil {
				return AccessExportArtifact{}, ErrStorageUnavailable
			}
			writer.Flush()
			if writer.Error() != nil {
				return AccessExportArtifact{}, ErrStorageUnavailable
			}
			rows++
			if output.Len() > limits.MaxBytes {
				return AccessExportArtifact{}, ErrResponseTooLarge
			}
			current := item
			previous = &current
		}
		if page.NextCursor == "" {
			break
		}
		if len(page.Items) == 0 || page.NextCursor == cursor {
			return AccessExportArtifact{}, ErrInvalidResponse
		}
		cursor = page.NextCursor
	}
	writer.Flush()
	if writer.Error() != nil || output.Len() > limits.MaxBytes {
		return AccessExportArtifact{}, ErrResponseTooLarge
	}
	digest := sha256.Sum256(output.Bytes())
	return AccessExportArtifact{
		Bytes: append([]byte(nil), output.Bytes()...), RowCount: rows,
		SHA256: hex.EncodeToString(digest[:]), SnapshotAt: snapshot,
	}, nil
}

// safeCSVCell 中和表格软件会当作公式的开头（与 observabilitylog 系统日志
// CSV 同一语义，另加制表符与回车）：前置单引号，原文仍可读。数值列由无符号
// 整数格式化，不会以这些字符开头。
func safeCSVCell(value string) string {
	if value == "" {
		return ""
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	default:
		return value
	}
}

func emptyExportSnapshot(filter Filter, now func() time.Time) time.Time {
	snapshot := now().UTC().Truncate(time.Millisecond)
	if !filter.To.IsZero() && filter.To.Before(snapshot) {
		snapshot = filter.To.UTC().Truncate(time.Millisecond)
	}
	return snapshot
}

func optionalUint64(value *uint64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatUint(*value, 10)
}

func accessContentType(item AccessLog) string {
	value := accessHeader(item.ResponseHeaders, "Content-Type", 256)
	mediaType, _, _ := strings.Cut(value, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	if validContentTypeFilter(mediaType) {
		return mediaType
	}
	return ""
}

func accessHeader(headers map[string]string, wanted string, maximum int) string {
	for name, value := range headers {
		if strings.EqualFold(name, wanted) && validOutputText(value, maximum, true) {
			return value
		}
	}
	return ""
}
