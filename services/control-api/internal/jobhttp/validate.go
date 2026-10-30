package jobhttp

import (
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	defaultPageLimit          = 20
	maximumPageLimit          = 100
	maximumPageNumber         = 1_000_000
	maximumJobAttempts uint32 = 1001
	maximumTimeSpan           = 31 * 24 * time.Hour
	maximumCursorLen          = 8192
)

var (
	stableIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	requestIDPattern        = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	jobRevisionPattern      = regexp.MustCompile(`^(?:[1-9][0-9]{0,19}|[0-9a-f]{64})$`)
)

func normalizeListRequest(request ListRequest) (ListRequest, error) {
	if request.Limit == 0 {
		request.Limit = defaultPageLimit
	}
	request.From = request.From.UTC()
	request.To = request.To.UTC()
	if request.Audience != AudiencePlatform && request.Audience != AudienceTenant ||
		request.Limit < 1 || request.Limit > maximumPageLimit || len(request.Cursor) > maximumCursorLen ||
		request.Page < 0 || request.Page > maximumPageNumber || request.Page > 0 && request.Cursor != "" ||
		request.From.IsZero() || request.To.IsZero() || !request.From.Before(request.To) ||
		request.To.Sub(request.From) > maximumTimeSpan ||
		(request.TenantID != nil && *request.TenantID == uuid.Nil) ||
		(request.TaskID != nil && *request.TaskID == uuid.Nil) ||
		(request.Kind != "" && !stableIdentifierPattern.MatchString(request.Kind)) ||
		(request.Resource != "" && !validSafeText(request.Resource, 512)) {
		return ListRequest{}, ErrInvalidRequest
	}
	seen := make(map[State]struct{}, len(request.States))
	for _, state := range request.States {
		if !validState(state) {
			return ListRequest{}, ErrInvalidRequest
		}
		if _, exists := seen[state]; exists {
			return ListRequest{}, ErrInvalidRequest
		}
		seen[state] = struct{}{}
	}
	sort.Slice(request.States, func(left, right int) bool { return request.States[left] < request.States[right] })
	return request, nil
}

func normalizeChildRequest(request ChildPageRequest) (ChildPageRequest, error) {
	if request.Limit == 0 {
		request.Limit = defaultPageLimit
	}
	if request.Audience != AudiencePlatform && request.Audience != AudienceTenant ||
		request.TaskID == uuid.Nil || request.Limit < 1 || request.Limit > maximumPageLimit ||
		len(request.Cursor) > maximumCursorLen {
		return ChildPageRequest{}, ErrInvalidRequest
	}
	return request, nil
}

func validState(state State) bool {
	switch state {
	case StateQueued, StateRunning, StateSucceeded, StatePartialFailed, StateFailed, StateCancelled:
		return true
	default:
		return false
	}
}

func validAttemptState(state AttemptState) bool {
	switch state {
	case AttemptRunning, AttemptSucceeded, AttemptPartialFailed, AttemptFailed, AttemptCancelled, AttemptLeaseExpired:
		return true
	default:
		return false
	}
}

func validResultState(state ResultState) bool {
	switch state {
	case ResultPending, ResultSucceeded, ResultFailed, ResultCancelled:
		return true
	default:
		return false
	}
}

func validSafeText(value string, limit int) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func validOptionalSafeText(value string, limit int) bool {
	return value == "" || validSafeText(value, limit)
}

func validUTCOutputTime(value time.Time) bool {
	if value.IsZero() || value.Location() != time.UTC {
		return false
	}
	_, err := value.MarshalJSON()
	return err == nil
}
