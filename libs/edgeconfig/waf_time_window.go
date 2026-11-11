package edgeconfig

import (
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Request time conditions.
// The node has no time zone database: the control plane compiles a
// condition to UTC seconds (date ranges) or to local weekly minutes plus the
// zone's UTC offset table (weekly windows), and the node compares integers
// against ngx.time().

// DefaultWAFTimeZone is the zone of a request_time condition without key.
const DefaultWAFTimeZone = "Asia/Shanghai"

const (
	// MaxWAFTimeWeekly / MaxWAFTimeRanges bound a condition's values.
	MaxWAFTimeWeekly = 7
	MaxWAFTimeRanges = 4
	// MaxWAFTimeOffsets bounds the offset table (a zone with daylight saving
	// time has about 45 entries over the table's 22 years).
	MaxWAFTimeOffsets = 64
	// MaxWAFTimeOffsetSeconds bounds a UTC offset (±18 h).
	MaxWAFTimeOffsetSeconds = 18 * 3600
	// wafTimeTableYears: the offset table runs from January 1 of the year
	// before compilation for this many years, so republishing within a year
	// does not change the condition, and it is valid at least 20 years ahead.
	wafTimeTableYears = 22
	maxWAFTimeUnix    = 1<<53 - 1
)

// Request time error reasons (the control plane's validation_error reason).
const (
	TimeReasonInvalidFormat = "invalid_format"
	TimeReasonEmpty         = "time_range_empty" // no value, no day, start = end or start after end
	TimeReasonUnknownZone   = "unknown_time_zone"
)

// TimeConditionError is a refused request_time condition: Index is the value
// (values[Index]), -1 for the key or the whole list. It wraps ErrInvalidConfig.
type TimeConditionError struct {
	Index  int
	Reason string
}

func (err *TimeConditionError) Error() string {
	if err.Index < 0 {
		return "request time: " + err.Reason
	}
	return "request time value " + strconv.Itoa(err.Index) + ": " + err.Reason
}

func (err *TimeConditionError) Unwrap() error { return ErrInvalidConfig }

// WAFTimeMatch is a compiled request_time condition, exactly one form:
//
//   - Ranges: [start, end) in UTC seconds, ascending, not overlapping or
//     touching (CompileWAFTimeMatch merges them).
//   - Weekly: local slots; Offsets [[from UTC second, offset seconds], ...]
//     ascending, each in force until the next; Until ends the table. Outside
//     [Offsets[0][0], Until) the condition holds neither in nor not_in.
//
// Negate turns in_time_range into not_in_time_range.
type WAFTimeMatch struct {
	Negate  bool          `json:"negate,omitempty"`
	Ranges  [][2]int64    `json:"ranges,omitempty"`
	Weekly  []WAFWeekSlot `json:"weekly,omitempty"`
	Offsets [][2]int64    `json:"offsets,omitempty"`
	Until   int64         `json:"until,omitempty"`
}

// WAFWeekSlot: Days bit 0 = Monday ... bit 6 = Sunday; From and To are local
// minutes 0..1439, To excluded. From > To runs past midnight and belongs to
// the day it starts on (fri 22:00-02:00 is Friday 22:00 to Saturday 02:00).
type WAFWeekSlot struct {
	Days uint8 `json:"days"`
	From int   `json:"from"`
	To   int   `json:"to"`
}

// Spec is the rule plan value (RuleOpTimeWindow).
func (match WAFTimeMatch) Spec() string { return conditionSpec(match) }

// LoadWAFTimeZone loads a condition key: an IANA zone name ("" is
// DefaultWAFTimeZone; "Local" and unknown names are refused).
func LoadWAFTimeZone(name string) (*time.Location, error) {
	if name == "" {
		name = DefaultWAFTimeZone
	}
	if name == "Local" || len(name) > 64 {
		return nil, &TimeConditionError{Index: -1, Reason: TimeReasonUnknownZone}
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return nil, &TimeConditionError{Index: -1, Reason: TimeReasonUnknownZone}
	}
	return location, nil
}

var (
	weeklyValuePattern = regexp.MustCompile(`^([a-z,]*) ([01][0-9]|2[0-3]):([0-5][0-9])-([01][0-9]|2[0-3]):([0-5][0-9])$`)
	weekdayBits        = map[string]uint8{"mon": 1, "tue": 2, "wed": 4, "thu": 8, "fri": 16, "sat": 32, "sun": 64}
)

const rangeValueLayout = "2006-01-02T15:04:05"

// CompileWAFTimeMatch compiles a request_time condition: zone is the key,
// values either all weekly ("mon,tue 09:00-18:00", at most 7) or all date
// ranges ("2026-11-11T00:00:00 / 2026-11-12T00:00:00" local time, at most
// 4); negate for not_in_time_range. now anchors the weekly offset table.
func CompileWAFTimeMatch(zone string, values []string, negate bool, now time.Time) (WAFTimeMatch, error) {
	if len(values) == 0 {
		return WAFTimeMatch{}, &TimeConditionError{Index: -1, Reason: TimeReasonEmpty}
	}
	location, err := LoadWAFTimeZone(zone)
	if err != nil {
		return WAFTimeMatch{}, err
	}
	ranges := strings.Contains(values[0], "/")
	if ranges && len(values) > MaxWAFTimeRanges || !ranges && len(values) > MaxWAFTimeWeekly {
		return WAFTimeMatch{}, &TimeConditionError{Index: -1, Reason: TimeReasonInvalidFormat}
	}
	match := WAFTimeMatch{Negate: negate}
	for index, value := range values {
		if strings.Contains(value, "/") != ranges {
			return WAFTimeMatch{}, &TimeConditionError{Index: index, Reason: TimeReasonInvalidFormat}
		}
		if ranges {
			span, reason := parseTimeRangeValue(value, location)
			if reason != "" {
				return WAFTimeMatch{}, &TimeConditionError{Index: index, Reason: reason}
			}
			match.Ranges = append(match.Ranges, span)
			continue
		}
		slot, reason := parseWeeklyValue(value)
		if reason != "" {
			return WAFTimeMatch{}, &TimeConditionError{Index: index, Reason: reason}
		}
		match.Weekly = append(match.Weekly, slot)
	}
	if ranges {
		match.Ranges = mergeTimeRanges(match.Ranges)
	} else {
		slices.SortFunc(match.Weekly, compareWeekSlot)
		match.Weekly = slices.Compact(match.Weekly)
		match.Offsets, match.Until, err = wafTimeOffsetTable(location, now)
		if err != nil {
			return WAFTimeMatch{}, err
		}
	}
	return match, ValidateWAFTimeMatch(match)
}

func parseWeeklyValue(value string) (WAFWeekSlot, string) {
	parts := weeklyValuePattern.FindStringSubmatch(value)
	if parts == nil {
		return WAFWeekSlot{}, TimeReasonInvalidFormat
	}
	slot := WAFWeekSlot{}
	if parts[1] != "" {
		for _, day := range strings.Split(parts[1], ",") {
			bit, ok := weekdayBits[day]
			if !ok || slot.Days&bit != 0 {
				return WAFWeekSlot{}, TimeReasonInvalidFormat
			}
			slot.Days |= bit
		}
	}
	slot.From = minuteOf(parts[2], parts[3])
	slot.To = minuteOf(parts[4], parts[5])
	if slot.Days == 0 || slot.From == slot.To {
		return WAFWeekSlot{}, TimeReasonEmpty
	}
	return slot, ""
}

func minuteOf(hour, minute string) int {
	h, _ := strconv.Atoi(hour)
	m, _ := strconv.Atoi(minute)
	return h*60 + m
}

func parseTimeRangeValue(value string, location *time.Location) ([2]int64, string) {
	start, end, ok := strings.Cut(value, " / ")
	if !ok || len(start) != len(rangeValueLayout) || len(end) != len(rangeValueLayout) {
		return [2]int64{}, TimeReasonInvalidFormat
	}
	from, err := time.ParseInLocation(rangeValueLayout, start, location)
	if err != nil {
		return [2]int64{}, TimeReasonInvalidFormat
	}
	to, err := time.ParseInLocation(rangeValueLayout, end, location)
	if err != nil || from.Unix() < 0 || to.Unix() > maxWAFTimeUnix {
		return [2]int64{}, TimeReasonInvalidFormat
	}
	if from.Unix() >= to.Unix() {
		return [2]int64{}, TimeReasonEmpty
	}
	return [2]int64{from.Unix(), to.Unix()}, ""
}

func mergeTimeRanges(ranges [][2]int64) [][2]int64 {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
	merged := [][2]int64{ranges[0]}
	for _, span := range ranges[1:] {
		last := &merged[len(merged)-1]
		if span[0] <= last[1] {
			last[1] = max(last[1], span[1])
			continue
		}
		merged = append(merged, span)
	}
	return merged
}

func compareWeekSlot(left, right WAFWeekSlot) int {
	if left.From != right.From {
		return left.From - right.From
	}
	if left.To != right.To {
		return left.To - right.To
	}
	return int(left.Days) - int(right.Days)
}

// wafTimeOffsetTable is location's UTC offsets from January 1 (UTC) of the
// year before now for wafTimeTableYears years, one entry per offset change
// at its exact second. ZoneBounds only proposes the next point: past the
// zone's explicit transitions (the TZ rule extension, from 2037 on) it also
// returns artificial year boundaries and, at some, an end that is not later,
// so the walk then steps an hour and bisects each change to the second. A
// zero end means the offset never changes again.
func wafTimeOffsetTable(location *time.Location, now time.Time) ([][2]int64, int64, error) {
	start := time.Date(now.UTC().Year()-1, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	until := time.Unix(start, 0).UTC().AddDate(wafTimeTableYears, 0, 0).Unix()
	offsetAt := func(at int64) int64 {
		_, offset := time.Unix(at, 0).In(location).Zone()
		return int64(offset)
	}
	table := [][2]int64{{start, offsetAt(start)}}
	for at := start; at < until; {
		_, end := time.Unix(at, 0).In(location).ZoneBounds()
		if end.IsZero() {
			break // the offset never changes again (a zone without daylight saving time)
		}
		next := at + 3600
		if end.Unix() > at {
			next = end.Unix()
		}
		next = min(next, until)
		if offset := offsetAt(next); next < until && offset != table[len(table)-1][1] {
			low, high := at, next // low has the old offset, high the new one
			for high-low > 1 {
				if middle := low + (high-low)/2; offsetAt(middle) == offset {
					high = middle
				} else {
					low = middle
				}
			}
			table = append(table, [2]int64{high, offset})
			if len(table) > MaxWAFTimeOffsets {
				return nil, 0, &TimeConditionError{Index: -1, Reason: TimeReasonUnknownZone}
			}
		}
		at = next
	}
	return table, until, nil
}

// ValidateWAFTimeMatch checks a compiled condition (the node rejects the
// rule plan on the same rules).
func ValidateWAFTimeMatch(match WAFTimeMatch) error {
	if (len(match.Ranges) == 0) == (len(match.Weekly) == 0) {
		return ErrInvalidConfig
	}
	if len(match.Ranges) != 0 {
		if match.Offsets != nil || match.Until != 0 || len(match.Ranges) > MaxWAFTimeRanges {
			return ErrInvalidConfig
		}
		for index, span := range match.Ranges {
			if span[0] < 0 || span[0] >= span[1] || span[1] > maxWAFTimeUnix || index > 0 && match.Ranges[index-1][1] >= span[0] {
				return ErrInvalidConfig
			}
		}
		return nil
	}
	if len(match.Weekly) > MaxWAFTimeWeekly || len(match.Offsets) == 0 || len(match.Offsets) > MaxWAFTimeOffsets {
		return ErrInvalidConfig
	}
	for index, slot := range match.Weekly {
		if slot.Days == 0 || slot.Days > 0x7f || slot.From < 0 || slot.From > 1439 || slot.To < 0 || slot.To > 1439 ||
			slot.From == slot.To || index > 0 && compareWeekSlot(match.Weekly[index-1], slot) >= 0 {
			return ErrInvalidConfig
		}
	}
	for index, entry := range match.Offsets {
		if entry[0] < 0 || entry[0] > maxWAFTimeUnix || entry[1] < -MaxWAFTimeOffsetSeconds || entry[1] > MaxWAFTimeOffsetSeconds ||
			index > 0 && match.Offsets[index-1][0] >= entry[0] {
			return ErrInvalidConfig
		}
	}
	if match.Until <= match.Offsets[len(match.Offsets)-1][0] || match.Until > maxWAFTimeUnix {
		return ErrInvalidConfig
	}
	return nil
}

// Matches is the condition's reference semantics at UTC second now.
func (match WAFTimeMatch) Matches(now int64) bool {
	if len(match.Ranges) != 0 {
		inside := slices.ContainsFunc(match.Ranges, func(span [2]int64) bool { return now >= span[0] && now < span[1] })
		return inside != match.Negate
	}
	if len(match.Offsets) == 0 || now < match.Offsets[0][0] || now >= match.Until {
		return false
	}
	entry := sort.Search(len(match.Offsets), func(i int) bool { return match.Offsets[i][0] > now }) - 1
	local := now + match.Offsets[entry][1]
	day := local / 86400
	if local < 0 && local%86400 != 0 {
		day--
	}
	minute := int((local - day*86400) / 60)
	weekday := uint8((day%7 + 7 + 3) % 7) // 1970-01-01 was a Thursday; Monday = 0
	today, yesterday := uint8(1)<<weekday, uint8(1)<<((weekday+6)%7)
	inside := slices.ContainsFunc(match.Weekly, func(slot WAFWeekSlot) bool {
		if slot.From < slot.To {
			return slot.Days&today != 0 && minute >= slot.From && minute < slot.To
		}
		return slot.Days&today != 0 && minute >= slot.From || slot.Days&yesterday != 0 && minute < slot.To
	})
	return inside != match.Negate
}

func normalizeWAFTimeMatch(value *WAFTimeMatch) (*WAFTimeMatch, error) {
	if value == nil {
		return nil, nil
	}
	if err := ValidateWAFTimeMatch(*value); err != nil {
		return nil, err
	}
	copied := WAFTimeMatch{Negate: value.Negate, Until: value.Until}
	if value.Ranges != nil {
		copied.Ranges = slices.Clone(value.Ranges)
	}
	if value.Weekly != nil {
		copied.Weekly = slices.Clone(value.Weekly)
	}
	if value.Offsets != nil {
		copied.Offsets = slices.Clone(value.Offsets)
	}
	return &copied, nil
}
