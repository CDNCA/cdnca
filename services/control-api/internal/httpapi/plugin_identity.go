package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonationhttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 插件身份（ADR 0007 §3.2，control 迁移 604）：绑定了插件安装的 API Key。
// 每个写请求按安装限频；审计事件记 actor_kind=plugin 与 plugin_id/installation_id。
const (
	pluginWriteLimitPerInstallation = 120
	pluginWriteLimitWindow          = time.Minute
)

type apiKeyAuthenticationKey struct{}

// apiKeyAuthentication is the CdncaKey result of withPluginIdentity, reused by
// authenticatedPrincipalWithAPIKey so a request authenticates its key once.
type apiKeyAuthentication struct {
	raw             string
	principal       identity.Principal
	keyID           uuid.UUID
	authenticatedAt time.Time
	err             error
}

func cachedAPIKeyAuthentication(ctx context.Context, raw string) (apiKeyAuthentication, bool) {
	cached, ok := ctx.Value(apiKeyAuthenticationKey{}).(apiKeyAuthentication)
	return cached, ok && cached.raw == raw
}

// withPluginIdentity authenticates a CdncaKey request once and records the
// key on the request's audit events (actor_ref api_key:<id>). A key bound to a
// plugin installation marks the request's audit events as the plugin and
// counts its writes against the installation's window (429 + Retry-After).
// Unbound keys, sessions and impersonation are passed through unchanged.
func (s *Server) withPluginIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, rawToken, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		raw := strings.TrimSpace(rawToken)
		if s.apiKeys == nil || !found || raw == "" || !strings.EqualFold(scheme, "CdncaKey") || hasImpersonationCookie(r) {
			next.ServeHTTP(w, r)
			return
		}
		principal, keyID, authenticatedAt, binding, err := s.apiKeys.AuthenticateWithPluginBinding(r.Context(), raw)
		ctx := context.WithValue(r.Context(), apiKeyAuthenticationKey{}, apiKeyAuthentication{
			raw: raw, principal: principal, keyID: keyID, authenticatedAt: authenticatedAt, err: err,
		})
		if err == nil && keyID != uuid.Nil {
			// Every audit event of this request records which key acted (api_key:<id>).
			ctx = audit.WithAPIKeyActor(ctx, keyID.String())
		}
		if err == nil && binding != nil {
			if isWriteMethod(r.Method) {
				if retryAfter, first, allowed := s.pluginWriteLimiter.allow(binding.AuthorizationID); !allowed {
					if first {
						s.auditPluginRateLimited(ctx, principal, keyID, *binding, r)
					}
					w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
					s.writeAPIError(w, r.WithContext(ctx), http.StatusTooManyRequests, "plugin_rate_limited",
						"too many write requests from this plugin installation")
					return
				}
			}
			ctx = audit.WithPluginActor(ctx, audit.PluginActor{
				PluginID: binding.PluginID, InstallationID: binding.InstallationID.String(), APIKeyID: keyID.String(),
			})
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// auditPluginRateLimited records the first refused write of a window (later
// refusals in the same window are not logged, so a runaway plugin cannot
// flood the audit chain). A failed write is not surfaced to the plugin.
func (s *Server) auditPluginRateLimited(
	ctx context.Context, principal identity.Principal, keyID uuid.UUID, binding apikey.PluginBinding, r *http.Request,
) {
	if s.pool == nil {
		return
	}
	actorID := principal.UserID
	_ = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return audit.New(s.pool).Append(audit.WithPluginActor(ctx, audit.PluginActor{
			PluginID: binding.PluginID, InstallationID: binding.InstallationID.String(), APIKeyID: keyID.String(),
		}), tx, audit.Event{
			ScopeID: principal.ScopeID, ActorUserID: &actorID, Action: "plugin.api.rate_limited",
			ResourceType: "plugin_installation", ResourceID: binding.AuthorizationID.String(),
			RequestID: requestID(ctx), Result: "denied",
			Payload: map[string]any{
				"reason_code": "plugin_rate_limited", "method": r.Method, "path": r.URL.Path,
				"limit": pluginWriteLimitPerInstallation, "window_seconds": int(pluginWriteLimitWindow / time.Second),
			},
		})
	})
}

func hasImpersonationCookie(r *http.Request) bool {
	_, err := r.Cookie(impersonationhttp.CookieName)
	return err == nil
}

func isWriteMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// pluginWriteLimiter is a fixed window per plugin installation. Like the node
// registration limiter it is process-local: each control-api replica enforces
// its own window.
type pluginWriteLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	limit   int
	window  time.Duration
	buckets map[uuid.UUID]pluginWriteBucket
}

type pluginWriteBucket struct {
	start   time.Time
	count   int
	refused bool
}

func newPluginWriteLimiter(now func() time.Time) *pluginWriteLimiter {
	if now == nil {
		now = time.Now
	}
	return &pluginWriteLimiter{
		now: now, limit: pluginWriteLimitPerInstallation, window: pluginWriteLimitWindow,
		buckets: map[uuid.UUID]pluginWriteBucket{},
	}
}

// allow counts one write; when refused it returns the whole seconds until the
// window ends (at least 1) and whether this is the window's first refusal.
func (l *pluginWriteLimiter) allow(installation uuid.UUID) (int, bool, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	bucket := l.buckets[installation]
	if now.Sub(bucket.start) >= l.window || now.Before(bucket.start) {
		bucket = pluginWriteBucket{start: now}
	}
	if bucket.count >= l.limit {
		first := !bucket.refused
		bucket.refused = true
		l.buckets[installation] = bucket
		retry := int((bucket.start.Add(l.window).Sub(now) + time.Second - 1) / time.Second)
		return max(retry, 1), first, false
	}
	bucket.count++
	l.buckets[installation] = bucket
	if len(l.buckets) > 10000 {
		for candidate, value := range l.buckets {
			if now.Sub(value.start) >= l.window {
				delete(l.buckets, candidate)
			}
		}
	}
	return 0, false, true
}
