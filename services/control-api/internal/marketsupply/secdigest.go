package marketsupply

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/secdigest"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Attack digests for market sites (ADR 0012 §19.1, ML-20): every 5-minute
// window, each market tenant site with enforced WAF / CC decisions gets one
// signed secdigest.Digest the runtime seals to the grant's root subscriber.

// AttackSummaries is analyticslog.Client (every tenant's sites of a window).
type AttackSummaries interface {
	ListAttackSummaries(ctx context.Context, from, to time.Time, minimum uint64, limit uint16) ([]analyticslog.AttackSiteSummary, error)
}

// SiteSecurity is autodefense.ClickHouse.SiteSecurityWindow.
type SiteSecurity interface {
	SiteSecurityWindow(ctx context.Context, tenant, site uuid.UUID, from, to time.Time, limit int,
	) ([]secdigest.Log, int64, []secdigest.Action, error)
}

// DigestTarget is one market site's digest of a window and where it goes.
type DigestTarget struct {
	Grant      grant.Grant
	Subscriber uuid.UUID // root subscriber member (secdigest recipient)
	Domains    []string  // the site's host, for the relay header
	Digest     secdigest.Digest
}

// WithSecurityReaders lets SecurityDigests read the leaf's ClickHouse.
func (s *Service) WithSecurityReaders(summaries AttackSummaries, security SiteSecurity) *Service {
	s.summaries, s.security = summaries, security
	return s
}

// Subscriber returns the root subscriber member of a grant's external key,
// learned from the requests it sent through the relay (the relay only
// accepts subscriber requests from the root buyer of the grant), so the
// grant itself never has to name the root.
func (s *Service) Subscriber(key string) (uuid.UUID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.subscribers[key]
	return id, ok
}

// RememberSubscriber records the root subscriber of key (see Subscriber).
func (s *Service) RememberSubscriber(key string, member uuid.UUID) {
	if member == uuid.Nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscribers == nil {
		s.subscribers = map[string]uuid.UUID{}
	}
	s.subscribers[key] = member
}

// Subscribers returns a copy of every remembered root subscriber by key.
func (s *Service) Subscribers() map[string]uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uuid.UUID, len(s.subscribers))
	for k, v := range s.subscribers {
		out[k] = v
	}
	return out
}

// SecurityDigests builds the digests of [start, start+5m) for every market
// tenant site with enforced decisions. Sites whose tenant has no current
// grant or whose root subscriber is not known yet (no request seen since
// this controller started) are skipped; leaf is this member.
func (s *Service) SecurityDigests(ctx context.Context, leaf uuid.UUID, start time.Time) ([]DigestTarget, error) {
	if s.summaries == nil || s.security == nil {
		return nil, nil
	}
	end := start.Add(secdigest.WindowSeconds * time.Second)
	sites, err := s.summaries.ListAttackSummaries(ctx, start, end, 1, analyticslog.MaxAttackSummarySites)
	if err != nil {
		return nil, err
	}
	if len(sites) == 0 {
		return nil, nil
	}
	s.mu.Lock()
	latest := map[string]grant.Grant{}
	for _, g := range s.grants {
		key := Key(g)
		if current, ok := latest[key]; !ok || g.NotAfter > current.NotAfter {
			latest[key] = g
		}
	}
	s.mu.Unlock()
	var out []DigestTarget
	for _, summary := range sites {
		siteID, err := uuid.Parse(summary.SiteID)
		if err != nil {
			continue
		}
		tenantID, err := uuid.Parse(summary.TenantID)
		if err != nil {
			continue
		}
		var username, domain string
		err = s.pool.QueryRow(ctx, `SELECT account.username, site.domain FROM sites site
			JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant' AND scope.tenant_id=$2
			JOIN memberships membership ON membership.scope_id=scope.id
			JOIN users account ON account.id=membership.user_id AND account.username LIKE 'mkt-%'
			WHERE site.id=$1 AND site.deleted_at IS NULL LIMIT 1`, siteID, tenantID).Scan(&username, &domain)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // not a market tenant site
		}
		if err != nil {
			return nil, err
		}
		key := strings.TrimPrefix(username, tenantPrefix)
		g, ok := latest[key]
		if !ok {
			continue
		}
		switch g.StatusAt(s.now()) {
		case grant.StatusActive, grant.StatusGrace:
		default:
			continue
		}
		subscriber, ok := s.Subscriber(key)
		if !ok {
			continue
		}
		logs, total, actions, err := s.security.SiteSecurityWindow(ctx, tenantID, siteID, start, end, secdigest.MaxLogs)
		if err != nil {
			return nil, err
		}
		d := secdigest.Digest{Schema: secdigest.SchemaV1, LeafMemberID: leaf, GrantID: g.GrantID, LeafSiteID: siteID,
			WindowStart: start.Unix(), WindowSeconds: secdigest.WindowSeconds,
			Summary: secdigest.Summary{Events: int64(summary.Events), Blocked: int64(summary.Blocked),
				Challenged: int64(summary.Challenged), Banned: int64(summary.Banned), Clients: int64(summary.Clients),
				TopDetector: digestSlug(summary.TopDetector), TopClientIP: summary.TopClientIP,
				FirstMS: summary.FirstEventAt.UnixMilli(), LastMS: summary.LastEventAt.UnixMilli()},
			Actions: keepValidActions(actions, start.Unix()), Logs: keepValidLogs(logs)}
		if n := total - int64(len(logs)); n > 0 {
			d.Dropped.Logs = n
		}
		d.Truncate()
		if d.Empty() {
			continue
		}
		if err := d.Validate(); err != nil {
			continue // a row the contract cannot carry; the next window still goes
		}
		out = append(out, DigestTarget{Grant: g, Subscriber: subscriber, Domains: []string{domain}, Digest: d})
	}
	return out, nil
}

// keepValidLogs drops log lines the digest contract refuses (a path that is
// not origin-form, a detector or rule outside the slug alphabet), so one
// odd request does not cost the whole window.
func keepValidLogs(logs []secdigest.Log) []secdigest.Log {
	out := logs[:0]
	for _, l := range logs {
		l.Detector, l.RuleID = digestSlug(l.Detector), digestSlug(l.RuleID)
		probe := secdigest.Digest{Schema: secdigest.SchemaV1, LeafMemberID: uuid.Max, GrantID: uuid.Max, LeafSiteID: uuid.Max,
			WindowStart: l.AtMS / 1000 / secdigest.WindowSeconds * secdigest.WindowSeconds, WindowSeconds: secdigest.WindowSeconds,
			Logs: []secdigest.Log{l}}
		if probe.Validate() == nil {
			out = append(out, l)
		}
	}
	return out
}

// keepValidActions drops verdicts the contract refuses (for example an
// unmasked CIDR), with reasons cut to the contract's 512 bytes.
func keepValidActions(actions []secdigest.Action, window int64) []secdigest.Action {
	out := actions[:0]
	for _, a := range actions {
		if len(a.Reason) > 512 {
			a.Reason = strings.ToValidUTF8(a.Reason[:512], "")
		}
		probe := secdigest.Digest{Schema: secdigest.SchemaV1, LeafMemberID: uuid.Max, GrantID: uuid.Max, LeafSiteID: uuid.Max,
			WindowStart: window, WindowSeconds: secdigest.WindowSeconds, Actions: []secdigest.Action{a}}
		if probe.Validate() == nil {
			out = append(out, a)
		}
	}
	return out
}

// digestSlug lower-cases a detector or rule ID into the contract's slug
// alphabet; anything else becomes empty (both fields are optional).
func digestSlug(s string) string {
	s = strings.ToLower(s)
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == ':' || r == '-') {
			return ""
		}
	}
	if s != "" && (s[0] < 'a' || s[0] > 'z') && (s[0] < '0' || s[0] > '9') {
		return ""
	}
	if len(s) > 64 {
		return ""
	}
	return s
}
