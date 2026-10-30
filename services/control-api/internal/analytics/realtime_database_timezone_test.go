package analytics

import (
	"testing"
	"time"
)

func TestRealtimeDatabaseTimestampsNormalizeEquivalentUTCOffsets(t *testing.T) {
	from := time.Date(2026, 9, 25, 1, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	databaseTime := to.In(time.FixedZone("database-UTC", 0))
	reader := &PostgresRealtimeExpectedCountReader{queryer: &realtimeEvidenceQueryFixture{row: realtimeEvidenceRowFixture{scan: func(destinations ...any) error {
		for i, v := range []string{"0", "1", "1"} {
			*destinations[i].(*string) = v
		}
		*destinations[3].(*bool) = true
		for i := 4; i < 8; i++ {
			*destinations[i].(*string) = "1"
		}
		*destinations[8].(**time.Time) = &databaseTime
		*destinations[9].(**time.Time) = &databaseTime
		return nil
	}}}}
	evidence, err := reader.ExpectedRealtimeEvidence(t.Context(), AdminScope(), RealtimeFilter{From: from, To: to})
	if err != nil || evidence.FinalizedThrough.Location() != time.UTC || !evidence.FinalizedThrough.Equal(to) {
		t.Fatalf("valid database timestamp rejected: %v", err)
	}
}
