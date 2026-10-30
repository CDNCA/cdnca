package nodetrafficpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/google/uuid"
)

type AnalyticsSummaryReader interface {
	Summary(context.Context, analytics.Scope, analytics.Filter) (analytics.Summary, error)
}

type AnalyticsUsageReader struct {
	reader AnalyticsSummaryReader
}

func NewAnalyticsUsageReader(reader AnalyticsSummaryReader) (*AnalyticsUsageReader, error) {
	if reader == nil {
		return nil, ErrInvalidConfig
	}
	return &AnalyticsUsageReader{reader: reader}, nil
}

func (reader *AnalyticsUsageReader) Read(ctx context.Context, query UsageQuery) (UsageEvidence, error) {
	if query.ScopeID == uuid.Nil || query.NodeID == uuid.Nil || query.Period.Key == "" ||
		query.Period.Start.IsZero() || !query.Period.End.After(query.Period.Start) || query.SnapshotAt.IsZero() {
		return UsageEvidence{}, ErrInvalidInput
	}
	summary, err := reader.reader.Summary(ctx, analytics.AdminScope(), analytics.Filter{
		From: query.Period.Start, To: query.Period.End, NodeID: query.NodeID.String(),
		Timezone: "UTC", SnapshotAt: query.SnapshotAt,
	})
	if err != nil {
		return UsageEvidence{}, err
	}
	digestInput := fmt.Sprintf("cdnca.node-traffic-usage/v1\n%s\n%s\n%s\n%s\n%s\n%d\n",
		query.ScopeID, query.NodeID, query.Period.Start.UTC().Format(time.RFC3339Nano),
		query.Period.End.UTC().Format(time.RFC3339Nano), query.SnapshotAt.UTC().Format(time.RFC3339Nano), summary.TotalBytes)
	digest := sha256.Sum256([]byte(digestInput))
	return UsageEvidence{
		Bytes: summary.TotalBytes, SnapshotAt: query.SnapshotAt.UTC(),
		FinalizedThrough: query.SnapshotAt.UTC(), SourceDigest: hex.EncodeToString(digest[:]),
	}, nil
}
