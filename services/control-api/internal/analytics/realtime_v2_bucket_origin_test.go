package analytics

import (
	"strings"
	"testing"
	"unicode"
)

func TestRealtimeV2BucketsUseQueryOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sql  string
	}{
		{name: "basic", sql: realtimeV2BasicSQL},
		{name: "quality", sql: realtimeV2QualitySQL},
		{name: "origin", sql: realtimeV2OriginSQL},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compact := strings.Map(func(character rune) rune {
				if unicode.IsSpace(character) {
					return -1
				}
				return character
			}, test.sql)
			total := strings.Count(compact, "toStartOfInterval(")
			anchored := 0
			for _, timestamp := range []string{"occurred_at", "receipt.occurred_at", "access.occurred_at"} {
				anchored += strings.Count(compact, "toStartOfInterval("+timestamp+
					",toIntervalMillisecond({bucket_ms:UInt64}),fromUnixTimestamp64Milli({from_ms:UInt64},'UTC'),{timezone:String})")
			}
			if total == 0 || anchored != total {
				t.Fatalf("bucket expressions anchored to query origin = %d, want all %d", anchored, total)
			}
		})
	}
}
