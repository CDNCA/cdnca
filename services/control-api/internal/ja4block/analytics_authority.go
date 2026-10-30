package ja4block

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

const (
	maximumAnalyticsWindow = 30 * 24 * time.Hour
	maximumSnapshotTTL     = 15 * time.Minute
	maximumAuthorityPages  = 100
)

type AnalyticsRanker interface {
	Rank(context.Context, analytics.Actor, analytics.QueryRequest, analytics.RankDimension, uint16, string) (analytics.RankPage, error)
}

type PublicationTargetResolver interface {
	LoadPublicationTarget(context.Context, uuid.UUID, uuid.UUID) (PublicationTarget, error)
}

type PublicationTarget struct {
	TenantScopeID           uuid.UUID
	SiteID                  uuid.UUID
	CurrentPolicy           *securitypolicy.Policy
	ExpectedBindingRevision int64
	ExpectedActiveVersion   int64
	TargetSnapshotID        uuid.UUID
	TargetSnapshotRevision  int64
	TargetSnapshotSHA256    [32]byte
	TargetNodeIDs           []uuid.UUID
}

type AnalyticsAuthorityConfig struct {
	Actor       analytics.Actor
	Window      time.Duration
	SnapshotTTL time.Duration
	PageSize    uint16
	MaxPages    int
	Clock       func() time.Time
}

type AnalyticsAuthority struct {
	ranker  AnalyticsRanker
	targets PublicationTargetResolver
	config  AnalyticsAuthorityConfig
}

func NewAnalyticsAuthority(ranker AnalyticsRanker, targets PublicationTargetResolver, config AnalyticsAuthorityConfig) (*AnalyticsAuthority, error) {
	if nilInterface(ranker) || nilInterface(targets) || config.Clock == nil ||
		config.Actor.ScopeKind != "platform" || !slices.Contains(config.Actor.Permissions, "platform.admin") ||
		!slices.Contains(config.Actor.Permissions, analytics.ReadPermission) || config.Window < time.Hour ||
		config.Window > maximumAnalyticsWindow || config.Window%time.Hour != 0 || config.SnapshotTTL <= 0 ||
		config.SnapshotTTL > maximumSnapshotTTL || config.PageSize == 0 || config.PageSize > 100 ||
		config.MaxPages < 1 || config.MaxPages > maximumAuthorityPages {
		return nil, ErrInvalidConfiguration
	}
	return &AnalyticsAuthority{ranker: ranker, targets: targets, config: config}, nil
}

func (authority *AnalyticsAuthority) Resolve(ctx context.Context, request AuthorityRequest) (AuthoritySnapshot, error) {
	if authority == nil || ctx == nil || request.TenantScopeID == uuid.Nil || request.SiteID == uuid.Nil ||
		!edgeconfig.ValidJA4(request.JA4) || request.SnapshotAt.IsZero() {
		return AuthoritySnapshot{}, ErrInvalidInput
	}
	now := authority.config.Clock().UTC()
	snapshotAt := request.SnapshotAt.UTC().Truncate(time.Millisecond)
	if snapshotAt.After(now.Add(time.Minute)) || !snapshotAt.Add(authority.config.SnapshotTTL).After(now) {
		return AuthoritySnapshot{}, ErrSnapshotExpired
	}
	to := now.Truncate(time.Hour)
	query := analytics.QueryRequest{
		Audience: analytics.AudiencePlatform, TenantID: request.TenantScopeID.String(),
		SiteID: request.SiteID.String(), From: to.Add(-authority.config.Window), To: to,
		Timezone: "UTC", SnapshotAt: snapshotAt,
	}
	var found *analytics.RankItem
	cursor := ""
	for pageNumber := 0; pageNumber < authority.config.MaxPages; pageNumber++ {
		page, err := authority.ranker.Rank(ctx, authority.config.Actor, query, analytics.RankByJA4, authority.config.PageSize, cursor)
		if err != nil {
			return AuthoritySnapshot{}, authorityDependencyError(err)
		}
		if !page.SnapshotAt.UTC().Truncate(time.Millisecond).Equal(snapshotAt) {
			return AuthoritySnapshot{}, ErrSnapshotStale
		}
		for index := range page.Items {
			if page.Items[index].Key == request.JA4 {
				item := page.Items[index]
				found = &item
				break
			}
		}
		if found != nil || page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if found == nil || found.RequestCount == 0 {
		return AuthoritySnapshot{}, ErrSnapshotStale
	}
	target, err := authority.targets.LoadPublicationTarget(ctx, request.TenantScopeID, request.SiteID)
	if err != nil {
		return AuthoritySnapshot{}, authorityDependencyError(err)
	}
	if target.TenantScopeID != request.TenantScopeID || target.SiteID != request.SiteID {
		return AuthoritySnapshot{}, ErrScopeConflict
	}
	snapshot := AuthoritySnapshot{
		TenantScopeID: request.TenantScopeID, SiteID: request.SiteID, JA4: request.JA4,
		FilterFrom: query.From, FilterTo: query.To, FilterTimezone: query.Timezone,
		SnapshotAt: snapshotAt, SnapshotExpiresAt: snapshotAt.Add(authority.config.SnapshotTTL),
		Consistency: "latest_event_id_at_snapshot", RequestCount: found.RequestCount, ResponseBytes: found.ResponseBytes,
		CurrentPolicy: clonePolicy(target.CurrentPolicy), ExpectedBindingRevision: target.ExpectedBindingRevision,
		ExpectedActiveVersion: target.ExpectedActiveVersion, TargetSnapshotID: target.TargetSnapshotID,
		TargetSnapshotRevision: target.TargetSnapshotRevision, TargetSnapshotSHA256: target.TargetSnapshotSHA256,
		TargetNodeIDs: canonicalNodes(target.TargetNodeIDs),
		RolloutID:     uuid.NewSHA1(uuid.NameSpaceOID, []byte(request.TenantScopeID.String()+"/"+request.SiteID.String()+"/"+request.JA4+"/"+snapshotAt.Format(time.RFC3339Nano))),
	}
	if !validPublicationTarget(snapshot) {
		return AuthoritySnapshot{}, ErrDependencyUnavailable
	}
	return snapshot, nil
}

func authorityDependencyError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrDependencyUnavailable
}
