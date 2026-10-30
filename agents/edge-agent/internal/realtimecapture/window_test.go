package realtimecapture

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestWindowRequiresContinuousIndependentObservationsAndGrace(t *testing.T) {
	start := time.Date(2026, 9, 25, 1, 0, 0, 0, time.UTC)
	evidence := sha256.Sum256([]byte("real-read"))
	tracker := Tracker{}
	for n := 0; n < 744; n++ {
		if done := tracker.Observe(start.Add(time.Duration(n)*5*time.Second), 0, evidence, evidence, true); len(done) != 0 {
			t.Fatal("finalized before grace")
		}
	}
	done := tracker.Observe(start.Add(time.Hour+FinalizationGrace), 0, evidence, evidence, true)
	if len(done) != 1 || done[0].Start != start || done[0].End != start.Add(time.Hour) || done[0].Connections != 0 || done[0].ConnectionEvidence == ([32]byte{}) {
		t.Fatalf("completed=%+v", done)
	}
}

func TestRestartMissingSamplesAndUnavailableSourceDoNotCertifyEmptyWindows(t *testing.T) {
	start := time.Date(2026, 9, 25, 1, 0, 0, 0, time.UTC)
	e := sha256.Sum256([]byte("read"))
	for _, mode := range []string{"cold-start", "source-failure", "gap", "restart"} {
		t.Run(mode, func(t *testing.T) {
			tracker := Tracker{}
			for n := 0; n <= 744; n++ {
				if mode == "cold-start" && n == 0 || mode == "gap" && n >= 100 && n <= 104 {
					continue
				}
				if mode == "restart" && n == 100 {
					tracker = Tracker{}
				}
				done := tracker.Observe(start.Add(time.Duration(n)*5*time.Second), 0, e, e, !(mode == "source-failure" && n == 100))
				if len(done) != 0 {
					t.Fatal("uncovered hour was certified")
				}
			}
		})
	}
}
