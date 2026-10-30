package ipintelupdate

import (
	"time"
)

// scheduleEpoch anchors every schedule: pulls happen at
// epoch-day + anchor minute (local time) + k*interval.
var scheduleEpoch = [3]int{2026, 1, 1}

// NextPull returns the first scheduled pull strictly after now: the grid
// starts on 2026-01-01 at anchorMinute in zone and repeats every interval.
// Daylight-saving changes shift wall-clock times; the grid is in absolute
// time from the anchor.
func NextPull(now time.Time, intervalMinutes, anchorMinute int, zone *time.Location) time.Time {
	if zone == nil {
		zone = time.UTC
	}
	interval := time.Duration(intervalMinutes) * time.Minute
	start := time.Date(scheduleEpoch[0], time.Month(scheduleEpoch[1]), scheduleEpoch[2], anchorMinute/60, anchorMinute%60, 0, 0, zone)
	if now.Before(start) {
		return start.UTC()
	}
	steps := now.Sub(start)/interval + 1
	return start.Add(steps * interval).UTC()
}

// validSchedule checks the form values and loads the zone.
func validSchedule(intervalMinutes, anchorMinute int, zoneName string) (*time.Location, bool) {
	if intervalMinutes < MinIntervalMinutes || intervalMinutes > MaxIntervalMinutes || anchorMinute < 0 || anchorMinute > 1439 ||
		zoneName == "" || len(zoneName) > 64 {
		return nil, false
	}
	zone, err := time.LoadLocation(zoneName)
	if err != nil {
		return nil, false
	}
	return zone, true
}
