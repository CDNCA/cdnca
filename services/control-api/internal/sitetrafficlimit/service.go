// Package sitetrafficlimit is a website's own traffic caps (ge-analytics,
// "网站流量限制"): daily, monthly and total byte caps independent of the
// site's package, and the notice page nodes serve once a cap is reached.
//
// The setting is a site write (sites.manage): it advances sites.revision (GET
// ETag / PUT If-Match), so a manual scope shows it pending and an automatic
// scope publishes it. The enforcement (Evaluator, run by the traffic
// enforcement runtime) reads the site's usage from ClickHouse, records the
// reached cap and republishes the scope through the system channel
// (traffic_enforcement trigger): the site's release then carries
// traffic_limit.exceeded and nodes answer 509 with the page. A new day/month,
// a raised cap or a disabled limit clears it the same way.
package sitetrafficlimit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid site traffic limit input")
	ErrNotFound            = errors.New("site not found")
	ErrRevisionConflict    = errors.New("site revision conflict")
	ErrIdempotencyConflict = errors.New("site traffic limit idempotency conflict")
	ErrLocked              = errors.New("site is locked")
)

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// MaxLimitBytes bounds one cap (1 EiB).
const MaxLimitBytes = int64(1) << 60

// Actor is the authenticated principal (sites.read / sites.manage checked by
// the caller); a tenant actor only reaches its own scope's sites.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

// Setting is what a user sets. A nil cap is no cap of that period.
type Setting struct {
	Enabled      bool   `json:"enabled"`
	DailyBytes   *int64 `json:"daily_bytes"`
	MonthlyBytes *int64 `json:"monthly_bytes"`
	TotalBytes   *int64 `json:"total_bytes"`
	// TimeZone is the IANA zone daily and monthly periods start in.
	TimeZone string `json:"time_zone"`
	// NoticeHTML is the page nodes serve while exceeded ("" the default).
	NoticeHTML string `json:"notice_html"`
}

// Usage is the site's traffic in each capped period, as last evaluated.
type Usage struct {
	DailyBytes   uint64     `json:"daily_bytes"`
	MonthlyBytes uint64     `json:"monthly_bytes"`
	TotalBytes   uint64     `json:"total_bytes"`
	EvaluatedAt  *time.Time `json:"evaluated_at"`
}

// State is a site's traffic limit and its enforcement.
type State struct {
	SiteID uuid.UUID `json:"site_id"`
	// Version is sites.revision (ETag / If-Match).
	Version int64   `json:"version"`
	Setting Setting `json:"setting"`
	// TotalSince is when the total cap started counting.
	TotalSince *time.Time `json:"total_since"`
	// ExceededPeriod is the reached cap ("" none): nodes serve the page.
	ExceededPeriod string     `json:"exceeded_period"`
	ExceededAt     *time.Time `json:"exceeded_at"`
	EvaluatedAt    *time.Time `json:"evaluated_at"`
	UpdatedAt      *time.Time `json:"updated_at"`
}

type UpdateRequest struct {
	SiteID           uuid.UUID
	ExpectedRevision int64
	Setting          Setting
	IdempotencyKey   string
	RequestID        string
	SourceIP         string
}

type Service struct{ store *Store }

func NewService(store *Store) *Service { return &Service{store: store} }

func (s *Service) Get(ctx context.Context, actor Actor, siteID uuid.UUID) (State, error) {
	if !validActor(actor) || siteID == uuid.Nil {
		return State{}, ErrInvalidInput
	}
	return s.store.Get(ctx, actor, siteID)
}

func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (State, error) {
	if !validActor(actor) || request.SiteID == uuid.Nil || request.ExpectedRevision < 1 ||
		!idempotencyPattern.MatchString(request.IdempotencyKey) || strings.TrimSpace(request.RequestID) == "" {
		return State{}, ErrInvalidInput
	}
	if err := NormalizeSetting(&request.Setting); err != nil {
		return State{}, err
	}
	encoded, err := json.Marshal(struct {
		SiteID  uuid.UUID `json:"site_id"`
		Version int64     `json:"expected_version"`
		Setting Setting   `json:"setting"`
	}{request.SiteID, request.ExpectedRevision, request.Setting})
	if err != nil {
		return State{}, err
	}
	return s.store.Update(ctx, actor, request, sha256.Sum256(encoded))
}

// NormalizeSetting validates a setting. An enabled limit needs at least one
// cap; the zone must load; the page is bounded UTF-8 HTML.
func NormalizeSetting(setting *Setting) error {
	setting.TimeZone = strings.TrimSpace(setting.TimeZone)
	if setting.TimeZone == "" {
		setting.TimeZone = "Asia/Shanghai"
	}
	location, err := time.LoadLocation(setting.TimeZone)
	if err != nil || location == time.Local || setting.TimeZone == "Local" || len(setting.TimeZone) > 64 {
		return ErrInvalidInput
	}
	for _, value := range []*int64{setting.DailyBytes, setting.MonthlyBytes, setting.TotalBytes} {
		if value != nil && (*value < 1 || *value > MaxLimitBytes) {
			return ErrInvalidInput
		}
	}
	if setting.Enabled && setting.DailyBytes == nil && setting.MonthlyBytes == nil && setting.TotalBytes == nil {
		return ErrInvalidInput
	}
	if len(setting.NoticeHTML) > edgeconfig.MaxSiteTrafficNoticeBytes || !utf8.ValidString(setting.NoticeHTML) ||
		strings.ContainsRune(setting.NoticeHTML, 0) {
		return ErrInvalidInput
	}
	return nil
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && (actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

// PeriodStarts are the starts of the day and month containing at, in zone.
func PeriodStarts(at time.Time, location *time.Location) (day, month time.Time) {
	local := at.In(location)
	day = time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, location).UTC()
	month = time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, location).UTC()
	return day, month
}
