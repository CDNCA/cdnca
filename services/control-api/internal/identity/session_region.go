package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Session region binding. A sign-in
// session family remembers the region it was verified in (country, or
// country-province when the IP intelligence library knows the province). A
// session request from another region is refused with
// ErrSessionRegionChanged until the user re-enters the password
// (VerifySessionRegion). Addresses the library cannot place (private
// networks, unknown ranges) never trigger the check, so a missing library
// degrades to "no check" rather than locking people out. Refresh is not
// checked: the minted access token is refused on its first request anyway.
//
// Re-verification requires the password (not just a session-local id); it is required, it goes through the
// sign-in throttle, and both the challenge and the re-verification are
// audited.

var ErrSessionRegionChanged = errors.New("session region changed")

const sessionRegionPolicyTTL = 5 * time.Second

// RegionResolver places an address; ok=false means unknown.
type RegionResolver interface {
	Region(ctx context.Context, address netip.Addr) (region string, ok bool)
}

type sessionRegionPolicy struct {
	mu       sync.Mutex
	enabled  bool
	loadedAt time.Time
	loaded   bool
}

// SetRegionResolver enables the session region check (still subject to the
// platform setting session_region_check).
func (s *Service) SetRegionResolver(resolver RegionResolver) {
	if s != nil {
		s.regionResolver = resolver
	}
}

func (s *Service) sessionRegionEnabled(ctx context.Context) bool {
	if s.regionResolver == nil || s.store == nil || s.store.pool == nil {
		return false
	}
	if s.publicSettings == nil {
		return true
	}
	cache := &s.regionPolicy
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.loaded && s.now().Sub(cache.loadedAt) < sessionRegionPolicyTTL {
		return cache.enabled
	}
	settings, err := s.publicSettings.GetPublic(ctx, uuid.Nil)
	if err != nil {
		// Keep the previous answer; an unreadable policy must not unlock it.
		return cache.loaded && cache.enabled
	}
	cache.enabled, cache.loadedAt, cache.loaded = settings.SessionRegionCheck, s.now(), true
	return cache.enabled
}

func (s *Service) regionOf(ctx context.Context, source string) (string, string, bool) {
	address, err := netip.ParseAddr(source)
	if err != nil || address.Zone() != "" {
		return "", "", false
	}
	address = address.Unmap()
	if address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		return "", "", false
	}
	region, ok := s.regionResolver.Region(ctx, address)
	if !ok || len(region) < 2 || len(region) > 32 {
		return "", "", false
	}
	return region, address.String(), true
}

// recordSessionRegion sets the family's baseline at sign-in.
func (s *Service) recordSessionRegion(ctx context.Context, familyID, userID uuid.UUID, source string) {
	if !s.sessionRegionEnabled(ctx) {
		return
	}
	region, address, ok := s.regionOf(ctx, source)
	if !ok {
		return
	}
	if _, err := s.store.pool.Exec(ctx, `INSERT INTO identity_session_regions(family_id,user_id,region,source_ip,updated_at)
		VALUES($1,$2,$3,$4,$5) ON CONFLICT (family_id) DO UPDATE SET region=EXCLUDED.region,source_ip=EXCLUDED.source_ip,
		challenged_region=NULL,updated_at=EXCLUDED.updated_at`, familyID, userID, region, address, s.now().UTC()); err != nil {
		slog.WarnContext(ctx, "session region baseline failed", "error", err)
	}
}

// checkSessionRegion runs on every session request.
func (s *Service) checkSessionRegion(ctx context.Context, principal Principal, sessionID uuid.UUID) error {
	if !s.sessionRegionEnabled(ctx) {
		return nil
	}
	region, address, ok := s.regionOf(ctx, audit.SourceIPFrom(ctx))
	if !ok {
		return nil
	}
	var familyID uuid.UUID
	var baseline, challenged *string
	err := s.store.pool.QueryRow(ctx, `SELECT sess.family_id, r.region, r.challenged_region FROM auth_sessions sess
		LEFT JOIN identity_session_regions r ON r.family_id = sess.family_id WHERE sess.id=$1`, sessionID).Scan(&familyID, &baseline, &challenged)
	if err != nil {
		return fmt.Errorf("read session region: %w", err)
	}
	if baseline == nil {
		// Signed in from an unknown region: the first known one becomes the baseline.
		s.recordSessionRegion(ctx, familyID, principal.UserID, address)
		return nil
	}
	if *baseline == region {
		return nil
	}
	if challenged == nil || *challenged != region {
		tag, err := s.store.pool.Exec(ctx, `UPDATE identity_session_regions SET challenged_region=$2 WHERE family_id=$1
			AND challenged_region IS DISTINCT FROM $2`, familyID, region)
		if err == nil && tag.RowsAffected() == 1 {
			s.auditSessionRegion(ctx, principal, "auth.session_region.challenge", "denied", *baseline, region, address)
		}
	}
	return ErrSessionRegionChanged
}

// VerifySessionRegion re-binds the session family to the current region after
// the user re-entered the password. It goes through the sign-in throttle.
func (s *Service) VerifySessionRegion(ctx context.Context, rawAccessToken, password string, request RequestInfo) error {
	userID, scopeID, sessionID, err := s.tokens.Parse(rawAccessToken)
	if err != nil {
		return ErrInvalidSession
	}
	principal, err := s.store.PrincipalForSession(ctx, userID, scopeID, sessionID)
	if err != nil {
		return err
	}
	if err := s.checkAdminAccess(ctx, principal.ScopeKind, request.SourceIP); err != nil {
		return err
	}
	if len(password) == 0 || len(password) > 1024 {
		return ErrInvalidCredentials
	}
	reservation, err := s.reserveLoginAttempt(ctx, principal.Username, request, nil)
	if err != nil {
		return err
	}
	var hash string
	if err := s.store.pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, userID).Scan(&hash); err != nil {
		reservation.settle(ctx, err)
		return fmt.Errorf("read password hash: %w", err)
	}
	if !verifyPasswordHash(hash, password).matches {
		reservation.settle(ctx, ErrInvalidCredentials)
		s.auditSessionRegion(ctx, principal, "auth.session_region.verify", "denied", "", "", request.SourceIP)
		return ErrInvalidCredentials
	}
	reservation.settle(ctx, nil)
	region, address, ok := s.regionOf(ctx, request.SourceIP)
	if !ok {
		return nil
	}
	var previous string
	err = pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		var familyID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT family_id FROM auth_sessions WHERE id=$1`, sessionID).Scan(&familyID); err != nil {
			return err
		}
		_ = tx.QueryRow(ctx, `SELECT region FROM identity_session_regions WHERE family_id=$1 FOR UPDATE`, familyID).Scan(&previous)
		_, err := tx.Exec(ctx, `INSERT INTO identity_session_regions(family_id,user_id,region,source_ip,updated_at)
			VALUES($1,$2,$3,$4,$5) ON CONFLICT (family_id) DO UPDATE SET region=EXCLUDED.region,source_ip=EXCLUDED.source_ip,
			challenged_region=NULL,updated_at=EXCLUDED.updated_at`, familyID, userID, region, address, s.now().UTC())
		return err
	})
	if err != nil {
		return fmt.Errorf("verify session region: %w", err)
	}
	s.auditSessionRegion(ctx, principal, "auth.session_region.verify", "success", previous, region, address)
	return nil
}

func (s *Service) auditSessionRegion(ctx context.Context, principal Principal, action, result, before, after, source string) {
	address := source
	if _, err := netip.ParseAddr(address); err != nil {
		address = ""
	}
	event := audit.Event{
		ScopeID: principal.ScopeID, ActorUserID: &principal.UserID, Action: action, ResourceType: "user",
		ResourceID: principal.UserID.String(), RequestID: "session-region-" + uuid.NewString()[:8], Result: result, SourceIP: address,
		Payload: map[string]any{"source_ip": address},
	}
	if result == "denied" {
		event.ReasonCode = "region_changed"
		if action == "auth.session_region.verify" {
			event.ReasonCode = "invalid_credentials"
		}
	}
	if before != "" || after != "" {
		event.Changes = []audit.Change{{Field: "region", Before: before, After: after}}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error { return s.store.auditor.Append(ctx, tx, event) }); err != nil {
		slog.WarnContext(ctx, "session region audit failed", "action", action, "error", err)
	}
}
