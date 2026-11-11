package edgeconfig

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

var timeWindowNow = time.Date(2026, 11, 10, 6, 0, 0, 0, time.UTC)

func timeReason(err error) string {
	var value *TimeConditionError
	if errors.As(err, &value) && errors.Is(err, ErrInvalidConfig) {
		return value.Reason
	}
	return ""
}

func TestCompileWAFTimeMatchWeeklyShanghai(t *testing.T) {
	match, err := CompileWAFTimeMatch("", []string{"mon,tue,wed,thu,fri 09:00-18:00"}, false, timeWindowNow)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(match.Weekly, []WAFWeekSlot{{Days: 0b0011111, From: 540, To: 1080}}) ||
		!reflect.DeepEqual(match.Offsets, [][2]int64{{time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), 8 * 3600}}) ||
		match.Until != time.Date(2047, 1, 1, 0, 0, 0, 0, time.UTC).Unix() || match.Ranges != nil {
		t.Fatalf("%+v", match)
	}
	if err := ValidateWAFTimeMatch(match); err != nil {
		t.Fatal(err)
	}
	shanghai, _ := time.LoadLocation("Asia/Shanghai")
	for local, want := range map[time.Time]bool{
		time.Date(2026, 11, 9, 9, 0, 0, 0, shanghai):    true,  // Monday 09:00, start included
		time.Date(2026, 11, 9, 17, 59, 59, 0, shanghai): true,  // last second
		time.Date(2026, 11, 9, 18, 0, 0, 0, shanghai):   false, // end excluded
		time.Date(2026, 11, 9, 8, 59, 59, 0, shanghai):  false,
		time.Date(2026, 11, 14, 10, 0, 0, 0, shanghai):  false, // Saturday
	} {
		if got := match.Matches(local.Unix()); got != want {
			t.Errorf("%s: %v", local, got)
		}
	}
	// The anchor is the year, not the instant: republishing the same day or
	// month does not change the condition (no site object churn).
	later, _ := CompileWAFTimeMatch("Asia/Shanghai", []string{"mon,tue,wed,thu,fri 09:00-18:00"}, false, timeWindowNow.Add(30*24*time.Hour))
	if !reflect.DeepEqual(later, match) {
		t.Fatalf("anchor moved: %+v", later)
	}
}

func TestCompileWAFTimeMatchWeeklyNewYorkDST(t *testing.T) {
	match, err := CompileWAFTimeMatch("America/New_York", []string{"mon 09:00-10:00"}, false, timeWindowNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(match.Offsets) < 40 || len(match.Offsets) > MaxWAFTimeOffsets {
		t.Fatalf("offsets %d", len(match.Offsets))
	}
	for index := 1; index < len(match.Offsets); index++ {
		if match.Offsets[index][0] <= match.Offsets[index-1][0] || match.Offsets[index][1] == match.Offsets[index-1][1] {
			t.Fatalf("offsets not ascending transitions at %d: %v", index, match.Offsets[index-1:index+1])
		}
	}
	newYork, _ := time.LoadLocation("America/New_York")
	// Every year of the table has its two changes (Go's ZoneBounds stops
	// past 2037; the table must not), the last on 2046-11-04 06:00 UTC.
	perYear := map[int]int{}
	for _, entry := range match.Offsets[1:] {
		perYear[time.Unix(entry[0], 0).UTC().Year()]++
	}
	for year := 2025; year <= 2046; year++ {
		if perYear[year] != 2 {
			t.Errorf("%d: %d offset changes", year, perYear[year])
		}
	}
	if last := match.Offsets[len(match.Offsets)-1]; last != [2]int64{time.Date(2046, 11, 4, 6, 0, 0, 0, time.UTC).Unix(), -18000} {
		t.Fatalf("last change %v", last)
	}
	for _, entry := range match.Offsets {
		if _, offset := time.Unix(entry[0], 0).In(newYork).Zone(); int64(offset) != entry[1] {
			t.Fatalf("entry %v: offset %d", entry, offset)
		}
		if _, offset := time.Unix(entry[0]-1, 0).In(newYork).Zone(); entry[0] != match.Offsets[0][0] && int64(offset) == entry[1] {
			t.Fatalf("entry %v is not the first second of its offset", entry)
		}
	}
	for local, want := range map[time.Time]bool{
		time.Date(2027, 1, 4, 9, 30, 0, 0, newYork): true, // EST Monday
		time.Date(2027, 7, 5, 9, 30, 0, 0, newYork): true, // EDT Monday
		time.Date(2027, 7, 5, 8, 30, 0, 0, newYork): false,
		time.Date(2027, 7, 5, 10, 0, 0, 0, newYork): false,
	} {
		if got := match.Matches(local.Unix()); got != want {
			t.Errorf("%s: %v", local, got)
		}
	}
	// Outside the table neither in nor not_in holds (§6).
	negated := match
	negated.Negate = true
	for _, outside := range []int64{match.Offsets[0][0] - 1, match.Until, match.Until + 86400} {
		if match.Matches(outside) || negated.Matches(outside) {
			t.Fatalf("outside the table %d matched", outside)
		}
	}
	if negated.Matches(time.Date(2027, 7, 5, 9, 30, 0, 0, newYork).Unix()) || !negated.Matches(time.Date(2027, 7, 5, 11, 0, 0, 0, newYork).Unix()) {
		t.Fatal("not_in_time_range")
	}
}

// fri 22:00-02:00 is Friday 22:00 to Saturday 02:00.
func TestCompileWAFTimeMatchAcrossMidnight(t *testing.T) {
	match, err := CompileWAFTimeMatch("UTC", []string{"fri 22:00-02:00"}, false, timeWindowNow)
	if err != nil {
		t.Fatal(err)
	}
	for at, want := range map[time.Time]bool{
		time.Date(2026, 11, 13, 22, 0, 0, 0, time.UTC):  true,  // Friday
		time.Date(2026, 11, 14, 1, 59, 59, 0, time.UTC): true,  // Saturday early
		time.Date(2026, 11, 14, 2, 0, 0, 0, time.UTC):   false, // end excluded
		time.Date(2026, 11, 13, 1, 0, 0, 0, time.UTC):   false, // Friday early belongs to Thursday's slot
		time.Date(2026, 11, 14, 22, 30, 0, 0, time.UTC): false, // Saturday night
	} {
		if got := match.Matches(at.Unix()); got != want {
			t.Errorf("%s: %v", at, got)
		}
	}
	// sun 23:00-01:00 wraps to Monday.
	sunday, _ := CompileWAFTimeMatch("UTC", []string{"sun 23:00-01:00"}, false, timeWindowNow)
	if !sunday.Matches(time.Date(2026, 11, 16, 0, 30, 0, 0, time.UTC).Unix()) {
		t.Fatal("Sunday slot does not reach Monday")
	}
}

func TestCompileWAFTimeMatchRanges(t *testing.T) {
	match, err := CompileWAFTimeMatch("Asia/Shanghai", []string{
		"2026-12-01T00:00:00 / 2026-12-02T00:00:00",
		"2026-11-11T00:00:00 / 2026-11-12T00:00:00",
		"2026-11-11T12:00:00 / 2026-11-13T00:00:00", // overlaps: merged
	}, true, timeWindowNow)
	if err != nil {
		t.Fatal(err)
	}
	shanghai, _ := time.LoadLocation("Asia/Shanghai")
	want := [][2]int64{
		{time.Date(2026, 11, 11, 0, 0, 0, 0, shanghai).Unix(), time.Date(2026, 11, 13, 0, 0, 0, 0, shanghai).Unix()},
		{time.Date(2026, 12, 1, 0, 0, 0, 0, shanghai).Unix(), time.Date(2026, 12, 2, 0, 0, 0, 0, shanghai).Unix()},
	}
	if !match.Negate || !reflect.DeepEqual(match.Ranges, want) || match.Weekly != nil || match.Offsets != nil || match.Until != 0 {
		t.Fatalf("%+v", match)
	}
	if err := ValidateWAFTimeMatch(match); err != nil {
		t.Fatal(err)
	}
	if match.Matches(want[0][0]) || !match.Matches(want[0][1]) || !match.Matches(want[0][0]-1) {
		t.Fatal("not_in ranges, end excluded")
	}
}

func TestCompileWAFTimeMatchRejects(t *testing.T) {
	for _, test := range []struct {
		zone   string
		values []string
		reason string
	}{
		{"", nil, TimeReasonEmpty},
		{"", []string{}, TimeReasonEmpty},
		{"Mars/Base", []string{"mon 09:00-10:00"}, TimeReasonUnknownZone},
		{"Local", []string{"mon 09:00-10:00"}, TimeReasonUnknownZone},
		{"", []string{" 09:00-10:00"}, TimeReasonEmpty}, // no day
		{"", []string{"mon 09:00-09:00"}, TimeReasonEmpty},
		{"", []string{"mon,mon 09:00-10:00"}, TimeReasonInvalidFormat},
		{"", []string{"monday 09:00-10:00"}, TimeReasonInvalidFormat},
		{"", []string{"mon 24:00-10:00"}, TimeReasonInvalidFormat},
		{"", []string{"mon 9:00-10:00"}, TimeReasonInvalidFormat},
		{"", []string{"mon 09:60-10:00"}, TimeReasonInvalidFormat},
		{"", []string{"mon 09:00-10:00", "2026-11-11T00:00:00 / 2026-11-12T00:00:00"}, TimeReasonInvalidFormat},
		{"", []string{"2026-11-12T00:00:00 / 2026-11-11T00:00:00"}, TimeReasonEmpty},
		{"", []string{"2026-11-11T00:00:00 / 2026-11-11T00:00:00"}, TimeReasonEmpty},
		{"", []string{"2026-11-11 / 2026-11-12"}, TimeReasonInvalidFormat},
		{"", []string{"2026-11-11T00:00:00/2026-11-12T00:00:00"}, TimeReasonInvalidFormat},
		{"", []string{"mon 09:00-10:00", "tue 09:00-10:00", "wed 09:00-10:00", "thu 09:00-10:00", "fri 09:00-10:00", "sat 09:00-10:00", "sun 09:00-10:00", "mon 11:00-12:00"}, TimeReasonInvalidFormat},
		{"", []string{"2026-01-01T00:00:00 / 2026-01-02T00:00:00", "2026-02-01T00:00:00 / 2026-02-02T00:00:00", "2026-03-01T00:00:00 / 2026-03-02T00:00:00", "2026-04-01T00:00:00 / 2026-04-02T00:00:00", "2026-05-01T00:00:00 / 2026-05-02T00:00:00"}, TimeReasonInvalidFormat},
	} {
		_, err := CompileWAFTimeMatch(test.zone, test.values, false, timeWindowNow)
		if got := timeReason(err); got != test.reason {
			t.Errorf("%q %q: reason %q (%v), want %q", test.zone, test.values, got, err, test.reason)
		}
	}
	if location, err := LoadWAFTimeZone(""); err != nil || location.String() != DefaultWAFTimeZone {
		t.Fatalf("default zone %v %v", location, err)
	}
}

func TestValidateWAFTimeMatch(t *testing.T) {
	good, _ := CompileWAFTimeMatch("UTC", []string{"mon 09:00-10:00"}, false, timeWindowNow)
	if err := ValidateWAFTimeMatch(good); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]WAFTimeMatch{
		"neither":         {},
		"both":            {Ranges: [][2]int64{{1, 2}}, Weekly: good.Weekly, Offsets: good.Offsets, Until: good.Until},
		"range reversed":  {Ranges: [][2]int64{{2, 1}}},
		"range overlap":   {Ranges: [][2]int64{{1, 5}, {4, 8}}},
		"range unsorted":  {Ranges: [][2]int64{{10, 11}, {1, 2}}},
		"range offsets":   {Ranges: [][2]int64{{1, 2}}, Offsets: good.Offsets},
		"range until":     {Ranges: [][2]int64{{1, 2}}, Until: 5},
		"too many ranges": {Ranges: [][2]int64{{1, 2}, {3, 4}, {5, 6}, {7, 8}, {9, 10}}},
		"weekly no table": {Weekly: good.Weekly},
		"days zero":       {Weekly: []WAFWeekSlot{{Days: 0, From: 1, To: 2}}, Offsets: good.Offsets, Until: good.Until},
		"days high bit":   {Weekly: []WAFWeekSlot{{Days: 0x80, From: 1, To: 2}}, Offsets: good.Offsets, Until: good.Until},
		"same minute":     {Weekly: []WAFWeekSlot{{Days: 1, From: 5, To: 5}}, Offsets: good.Offsets, Until: good.Until},
		"minute range":    {Weekly: []WAFWeekSlot{{Days: 1, From: 0, To: 1440}}, Offsets: good.Offsets, Until: good.Until},
		"offset too big":  {Weekly: good.Weekly, Offsets: [][2]int64{{0, 19 * 3600}}, Until: 10},
		"offset order":    {Weekly: good.Weekly, Offsets: [][2]int64{{10, 0}, {5, 3600}}, Until: 20},
		"until early":     {Weekly: good.Weekly, Offsets: good.Offsets, Until: good.Offsets[0][0]},
	} {
		if err := ValidateWAFTimeMatch(bad); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s accepted", name)
		}
		if _, err := normalizeWAFMatch(WAFMatch{Time: &bad}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s accepted by normalizeWAFMatch", name)
		}
	}
	if match, err := normalizeWAFMatch(WAFMatch{Time: &good}); err != nil || !reflect.DeepEqual(*match.Time, good) {
		t.Fatalf("%+v %v", match, err)
	}
}

// Compiling is cheap for every zone (it runs at each publication): a zone
// without daylight saving time stops at its last change, one with it walks
// its transitions, a 30-minute change (Lord Howe) is found to the second.
func TestWAFTimeOffsetTableZones(t *testing.T) {
	for _, zone := range []string{"Asia/Shanghai", "UTC", "Asia/Kolkata", "America/New_York", "Europe/London", "Australia/Lord_Howe", "Pacific/Chatham"} {
		started := time.Now()
		match, err := CompileWAFTimeMatch(zone, []string{"mon 09:00-10:00"}, false, timeWindowNow)
		if err != nil || time.Since(started) > 200*time.Millisecond {
			t.Fatalf("%s: %v in %s", zone, err, time.Since(started))
		}
		location, _ := time.LoadLocation(zone)
		for _, entry := range match.Offsets {
			if _, offset := time.Unix(entry[0], 0).In(location).Zone(); int64(offset) != entry[1] {
				t.Fatalf("%s entry %v: offset %d", zone, entry, offset)
			}
		}
		for at := match.Offsets[0][0]; at < match.Until; at += 7 * 86400 {
			entry := match.Offsets[0]
			for _, candidate := range match.Offsets {
				if candidate[0] <= at {
					entry = candidate
				}
			}
			if _, offset := time.Unix(at, 0).In(location).Zone(); int64(offset) != entry[1] {
				t.Fatalf("%s at %d: table %d, zone %d", zone, at, entry[1], offset)
			}
		}
	}
}
