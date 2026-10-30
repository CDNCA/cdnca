package analytics

import "time"

type realtimeMinuteMetadata struct {
	queryMetadata
	QueryVersion uint16 `json:"query_version"`
}

type realtimeMinuteResponse struct {
	Data RealtimeResult         `json:"data"`
	Meta realtimeMinuteMetadata `json:"meta"`
}

// Cached clients validate exact keys. The opt-in minute query must not extend
// their response shape or change the meaning of their hour-aligned evidence.
type realtimeLegacyPoint struct {
	Bucket       time.Time `json:"bucket"`
	Requests     uint64    `json:"requests"`
	TrafficBytes uint64    `json:"traffic_bytes"`
	BandwidthBPS float64   `json:"bandwidth_bps"`
	Connections  uint64    `json:"connections"`
}

type realtimeLegacyEvidence struct {
	AccessSourceCount     uint64    `json:"access_source_count"`
	ConnectionSourceCount uint64    `json:"connection_source_count"`
	ExpectedEvents        uint64    `json:"expected_events"`
	ObservedEvents        uint64    `json:"observed_events"`
	ErrorPPM              uint64    `json:"error_ppm"`
	FinalizedThrough      time.Time `json:"finalized_through"`
	SourceWatermark       time.Time `json:"source_watermark"`
}

type realtimeLegacyResult struct {
	MetricVersion uint16                 `json:"metric_version"`
	Summary       RealtimeMetrics        `json:"summary"`
	Series        []realtimeLegacyPoint  `json:"series"`
	Top           []RealtimeTopItem      `json:"top"`
	Evidence      realtimeLegacyEvidence `json:"evidence"`
}

type realtimeLegacyResponse struct {
	Data realtimeLegacyResult `json:"data"`
	Meta queryMetadata        `json:"meta"`
}

func legacyRealtimeResponse(result RealtimeResult, meta queryMetadata) realtimeLegacyResponse {
	series := make([]realtimeLegacyPoint, len(result.Series))
	for index, point := range result.Series {
		series[index] = realtimeLegacyPoint{Bucket: point.Bucket, Requests: point.Requests,
			TrafficBytes: point.TrafficBytes, BandwidthBPS: point.BandwidthBPS, Connections: point.Connections}
	}
	evidence := result.Evidence
	return realtimeLegacyResponse{
		Data: realtimeLegacyResult{MetricVersion: result.MetricVersion, Summary: result.Summary, Series: series, Top: result.Top,
			Evidence: realtimeLegacyEvidence{AccessSourceCount: evidence.AccessSourceCount, ConnectionSourceCount: evidence.ConnectionSourceCount,
				ExpectedEvents: evidence.ExpectedEvents, ObservedEvents: evidence.ObservedEvents, ErrorPPM: evidence.ErrorPPM,
				FinalizedThrough: evidence.FinalizedThrough, SourceWatermark: evidence.SourceWatermark}},
		Meta: meta,
	}
}

// query_version=3 adds coverage fields to the minute evidence. A partial range
// reports coverage_complete=false and the unsettled hour starts; facts and
// reconciliation then cover the settled hours only.
type realtimeCoverageEvidence struct {
	RealtimeEvidence
	CoverageComplete bool        `json:"coverage_complete"`
	RequestedWindows uint16      `json:"requested_windows"`
	CoveredWindows   uint16      `json:"covered_windows"`
	MissingWindows   []time.Time `json:"missing_windows"`
}

type realtimeCoverageResult struct {
	RealtimeResult
	Evidence realtimeCoverageEvidence `json:"evidence"`
}

type realtimeCoverageResponse struct {
	Data realtimeCoverageResult `json:"data"`
	Meta realtimeMinuteMetadata `json:"meta"`
}

// query_version=4 (live) reuses this shape: coverage spans every hour and the
// evidence carries no expected count, accuracy or finalization claim.
func realtimeCoverageResponseFor(result RealtimeResult, meta queryMetadata, version uint16) realtimeCoverageResponse {
	evidence := result.Evidence
	missing := evidence.MissingWindows
	if missing == nil {
		missing = []time.Time{}
	}
	return realtimeCoverageResponse{
		Data: realtimeCoverageResult{RealtimeResult: result, Evidence: realtimeCoverageEvidence{RealtimeEvidence: evidence,
			CoverageComplete: evidence.CoverageComplete, RequestedWindows: evidence.RequestedWindows,
			CoveredWindows: evidence.CoveredWindows, MissingWindows: missing}},
		Meta: realtimeMinuteMetadata{queryMetadata: meta, QueryVersion: version},
	}
}
