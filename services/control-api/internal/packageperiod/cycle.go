package packageperiod

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Cycle is a half-open quota window derived only from package validity and policy.
type Cycle struct {
	startsAt time.Time
	endsAt   time.Time
	timeZone string
	resetKey string
}

func CurrentCycle(subscriptionID string, validity Validity, policy CyclePolicy, at time.Time) (Cycle, error) {
	if subscriptionID == "" || strings.TrimSpace(subscriptionID) != subscriptionID || len(subscriptionID) > 256 ||
		!validity.valid() || !validTime(at) || !policy.valid() {
		return Cycle{}, ErrInvalidCycle
	}
	at = canonicalTime(at)
	if !validity.contains(at) {
		return Cycle{}, ErrNoActiveCycle
	}
	anchor := validity.startsAt.In(validity.location)
	localAt := at.In(validity.location)
	index := policy.estimateIndex(anchor, localAt)
	start, ok := policy.boundary(anchor, index)
	if !ok {
		return Cycle{}, ErrInvalidCycle
	}
	for index > 0 && localAt.Before(start) {
		index--
		start, ok = policy.boundary(anchor, index)
		if !ok {
			return Cycle{}, ErrInvalidCycle
		}
	}
	end, ok := policy.boundary(anchor, index+1)
	if !ok {
		return Cycle{}, ErrInvalidCycle
	}
	for !localAt.Before(end) {
		index++
		start = end
		end, ok = policy.boundary(anchor, index+1)
		if !ok {
			return Cycle{}, ErrInvalidCycle
		}
	}
	startUTC := canonicalTime(start)
	endUTC := canonicalTime(end)
	if endUTC.After(validity.endsAt) {
		endUTC = validity.endsAt
	}
	cycle := Cycle{
		startsAt: startUTC,
		endsAt:   endUTC,
		timeZone: validity.location.String(),
	}
	cycle.resetKey = makeResetKey(subscriptionID, cycle)
	return cycle, nil
}

func (c Cycle) StartsAt() time.Time {
	return c.startsAt
}

func (c Cycle) EndsAt() time.Time {
	return c.endsAt
}

func (c Cycle) TimeZone() string {
	return c.timeZone
}

func (c Cycle) ResetKey() string {
	return c.resetKey
}

func (c Cycle) contains(at time.Time) bool {
	return !at.Before(c.startsAt) && at.Before(c.endsAt)
}

func (c Cycle) valid() bool {
	return validTime(c.startsAt) && validTime(c.endsAt) && c.endsAt.After(c.startsAt) &&
		c.timeZone != "" && c.resetKey != ""
}

func (p CyclePolicy) valid() bool {
	switch p.Kind {
	case CycleDaily, CycleMonthly:
		return p.CustomDays == 0
	case CycleCustomDays:
		return p.CustomDays > 0 && p.CustomDays <= MaxCustomCycleDays
	default:
		return false
	}
}

func (p CyclePolicy) Validate() error {
	if !p.valid() {
		return ErrInvalidCycle
	}
	return nil
}

func (p CyclePolicy) estimateIndex(anchor, at time.Time) int64 {
	if p.Kind == CycleMonthly {
		anchorYear, anchorMonth, _ := anchor.Date()
		atYear, atMonth, _ := at.Date()
		return (int64(atYear-anchorYear)*12 + int64(atMonth-anchorMonth))
	}
	days := civilDay(at) - civilDay(anchor)
	interval := int64(1)
	if p.Kind == CycleCustomDays {
		interval = int64(p.CustomDays)
	}
	return days / interval
}

func (p CyclePolicy) boundary(anchor time.Time, index int64) (time.Time, bool) {
	if index < 0 {
		return time.Time{}, false
	}
	switch p.Kind {
	case CycleDaily:
		return addDays(anchor, index)
	case CycleMonthly:
		return addMonthsClamped(anchor, index)
	case CycleCustomDays:
		if index > int64(^uint(0)>>1)/int64(p.CustomDays) {
			return time.Time{}, false
		}
		return addDays(anchor, index*int64(p.CustomDays))
	default:
		return time.Time{}, false
	}
}

func addDays(value time.Time, days int64) (time.Time, bool) {
	if days > int64(^uint(0)>>1) {
		return time.Time{}, false
	}
	result := value.AddDate(0, 0, int(days))
	return result, validTime(result)
}

func civilDay(value time.Time) int64 {
	year, month, day := value.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC).Unix() / int64((24*time.Hour)/time.Second)
}

func makeResetKey(subscriptionID string, cycle Cycle) string {
	digest := sha256.New()
	for _, value := range []string{
		"package-period-reset/v1",
		subscriptionID,
		strconv.FormatInt(cycle.startsAt.Unix(), 10),
		strconv.Itoa(cycle.startsAt.Nanosecond()),
		strconv.FormatInt(cycle.endsAt.Unix(), 10),
		strconv.Itoa(cycle.endsAt.Nanosecond()),
		cycle.timeZone,
	} {
		_, _ = digest.Write([]byte(strconv.Itoa(len(value))))
		_, _ = digest.Write([]byte{':'})
		_, _ = digest.Write([]byte(value))
	}
	return "ppr1_" + hex.EncodeToString(digest.Sum(nil))
}
