package dashboard

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

func NewQuery(audience Audience, rangeValue, timezone string, now time.Time) (Query, error) {
	return NewFilteredQuery(audience, rangeValue, timezone, "", "", now)
}

func NewFilteredQuery(audience Audience, rangeValue, timezone, siteID, nodeID string, now time.Time) (Query, error) {
	if now.IsZero() || len(timezone) == 0 || len(timezone) > 128 || strings.TrimSpace(timezone) != timezone || timezone == "Local" {
		return Query{}, ErrInvalidQuery
	}
	if !validOptionalCanonicalUUID(siteID) || !validOptionalCanonicalUUID(nodeID) {
		return Query{}, ErrInvalidQuery
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return Query{}, ErrInvalidQuery
	}

	localNow := now.In(location)
	dayEnd := time.Date(localNow.Year(), localNow.Month(), localNow.Day()+1, 0, 0, 0, 0, location)
	var from, to time.Time
	switch audience {
	case AudienceAdmin:
		switch rangeValue {
		case "seven_days":
			from, to = dayEnd.AddDate(0, 0, -7), dayEnd
		case "thirty_days":
			from, to = dayEnd.AddDate(0, 0, -30), dayEnd
		case "previous_month":
			to = time.Date(localNow.Year(), localNow.Month(), 1, 0, 0, 0, 0, location)
			from = to.AddDate(0, -1, 0)
		default:
			return Query{}, ErrInvalidQuery
		}
	case AudienceTenant:
		switch rangeValue {
		case "today":
			from, to = dayEnd.AddDate(0, 0, -1), dayEnd
		case "yesterday":
			from, to = dayEnd.AddDate(0, 0, -2), dayEnd.AddDate(0, 0, -1)
		case "seven_days":
			from, to = dayEnd.AddDate(0, 0, -7), dayEnd
		case "thirty_days":
			from, to = dayEnd.AddDate(0, 0, -30), dayEnd
		default:
			return Query{}, ErrInvalidQuery
		}
	default:
		return Query{}, ErrInvalidQuery
	}

	from, to = from.UTC(), to.UTC()
	if !from.Before(to) || to.Sub(from) > 31*24*time.Hour+time.Hour ||
		!from.Equal(from.Truncate(time.Hour)) || !to.Equal(to.Truncate(time.Hour)) {
		return Query{}, ErrInvalidQuery
	}
	return Query{
		Range: rangeValue, Timezone: timezone, From: from, To: to, AsOf: now.UTC(),
		SiteID: siteID, NodeID: nodeID,
	}, nil
}

func validOptionalCanonicalUUID(value string) bool {
	if value == "" {
		return true
	}
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
