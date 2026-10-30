package packageperiod

import "time"

// Terms deliberately mirrors the duration/end_at oneOf at the domain boundary.
type Terms struct {
	Duration *Duration
	EndAt    *time.Time
}

// Validity is an immutable, half-open package activation window.
type Validity struct {
	startsAt time.Time
	endsAt   time.Time
	location *time.Location
}

func NewValidity(now time.Time, location *time.Location, terms Terms) (Validity, error) {
	if location == nil || !validTime(now) || (terms.Duration == nil) == (terms.EndAt == nil) {
		return Validity{}, ErrInvalidTerms
	}
	start := canonicalTime(now)
	var end time.Time
	if terms.Duration != nil {
		months := durationMonths(*terms.Duration)
		if months == 0 {
			return Validity{}, ErrInvalidTerms
		}
		var ok bool
		end, ok = addMonthsClamped(start.In(location), int64(months))
		if !ok {
			return Validity{}, ErrInvalidTerms
		}
		end = canonicalTime(end)
	} else {
		if !validTime(*terms.EndAt) {
			return Validity{}, ErrInvalidTerms
		}
		end = canonicalTime(*terms.EndAt)
	}
	if !end.After(start) {
		return Validity{}, ErrInvalidTerms
	}
	return Validity{startsAt: start, endsAt: end, location: location}, nil
}

func (v Validity) StartsAt() time.Time {
	return v.startsAt
}

func (v Validity) EndsAt() time.Time {
	return v.endsAt
}

func (v Validity) TimeZone() string {
	if v.location == nil {
		return ""
	}
	return v.location.String()
}

func (v Validity) contains(at time.Time) bool {
	return !at.Before(v.startsAt) && at.Before(v.endsAt)
}

func (v Validity) valid() bool {
	return v.location != nil && validTime(v.startsAt) && validTime(v.endsAt) && v.endsAt.After(v.startsAt)
}

func durationMonths(duration Duration) int {
	switch duration {
	case DurationMonth:
		return 1
	case DurationQuarter:
		return 3
	case DurationYear:
		return 12
	default:
		return 0
	}
}

func addMonthsClamped(value time.Time, months int64) (time.Time, bool) {
	year, month, day := value.Date()
	totalMonths := int64(year)*12 + int64(month-1) + months
	targetYear := totalMonths / 12
	targetMonth := time.Month(totalMonths%12 + 1)
	if targetYear < 1 || targetYear > 9999 {
		return time.Time{}, false
	}
	if last := daysInMonth(int(targetYear), targetMonth); day > last {
		day = last
	}
	hour, minute, second := value.Clock()
	return time.Date(int(targetYear), targetMonth, day, hour, minute, second, value.Nanosecond(), value.Location()), true
}

func daysInMonth(year int, month time.Month) int {
	switch month {
	case time.April, time.June, time.September, time.November:
		return 30
	case time.February:
		if year%400 == 0 || (year%4 == 0 && year%100 != 0) {
			return 29
		}
		return 28
	default:
		return 31
	}
}

func canonicalTime(value time.Time) time.Time {
	return value.Round(0).UTC()
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}
