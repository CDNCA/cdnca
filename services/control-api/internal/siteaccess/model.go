// Package siteaccess is a site's request handling (
// 站点“访问控制”页): host redirects, HSTS, compression, per-client
// limits, basic authentication and a maintenance page, plus the forced HTTPS
// status and excluded domains. The stored and published form is
// edgeconfig.SiteAccess; basic auth passwords are hashed at write time with
// a fresh random salt per user (edgeconfig.NewBasicAuthUser) and never stored
// or returned.
//
// A write is a site setting under sites.manage: it advances sites.revision
// (GET ETag / PUT If-Match), which advances the scope's source revision as
// every site write does, so a manual scope shows it pending and an automatic
// scope publishes it (edgeautopublish.EnqueueSiteSettingTx).
package siteaccess

import (
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid site access input")
	ErrNotFound            = errors.New("site not found")
	ErrRevisionConflict    = errors.New("site revision conflict")
	ErrIdempotencyConflict = errors.New("site access idempotency conflict")
	ErrLocked              = errors.New("site is locked")
	// ErrNeedsHTTPS: HSTS or forced HTTPS settings on a site without HTTPS.
	ErrNeedsHTTPS = errors.New("site access setting needs HTTPS")
)

// AuditAction is the audit event of a site access write.
const AuditAction = "site.access.update"

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

// BasicAuthUser is a user as written: Password set adds or replaces the
// user's secret; empty keeps the stored one (a user must exist to keep it).
type BasicAuthUser struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
}

type BasicAuth struct {
	Realm               string          `json:"realm"`
	Users               []BasicAuthUser `json:"users"`
	ExcludePathPrefixes []string        `json:"exclude_path_prefixes"`
}

// ForceHTTPS is the forced HTTPS status and excluded domains; forcing itself
// stays on the site (force_https, https_redirect_port).
type ForceHTTPS struct {
	Status       int      `json:"status"`
	ExcludeHosts []string `json:"exclude_hosts"`
}

// Settings is what a write carries and a read returns (passwords never).
type Settings struct {
	HostRedirects []edgeconfig.HostRedirect       `json:"host_redirects"`
	HSTS          *edgeconfig.SiteHSTS            `json:"hsts"`
	Compression   *edgeconfig.SiteCompression     `json:"compression"`
	Limits        *edgeconfig.SiteRequestLimits   `json:"limits"`
	BasicAuth     *BasicAuth                      `json:"basic_auth"`
	Maintenance   *edgeconfig.SiteMaintenancePage `json:"maintenance"`
	WebP          *edgeconfig.SiteWebP            `json:"webp"`
	// ResponseRules are evaluated in order on the response status and
	// headers (EDGE_RESPONSE_RULES).
	ResponseRules []edgeconfig.SiteResponseRule `json:"response_rules"`
	ForceHTTPS    ForceHTTPS                    `json:"force_https"`
}

// State is a site's access settings.
type State struct {
	SiteID uuid.UUID `json:"site_id"`
	// Version is sites.revision (ETag / If-Match).
	Version    int64      `json:"version"`
	Settings   Settings   `json:"settings"`
	HTTPS      bool       `json:"https_enabled"`
	ForceHTTPS bool       `json:"force_https"`
	Domains    []string   `json:"domains"`
	UpdatedAt  *time.Time `json:"updated_at"`
	// BasicAuthUsers is the stored users' salted hashes (never returned
	// over HTTP; a market leaf compares them).
	BasicAuthUsers []edgeconfig.BasicAuthUser `json:"-"`
}

type UpdateRequest struct {
	SiteID           uuid.UUID
	ExpectedRevision int64
	Settings         Settings
	IdempotencyKey   string
	RequestID        string
	SourceIP         string
	// HashedUsers (market leaf only): basic auth users
	// already hashed by the subscriber (salt + sha256); a user named here is
	// listed in Settings.BasicAuth without a password and stored as given.
	HashedUsers []edgeconfig.BasicAuthUser `json:"-"`
}

// siteFacts are what a write is checked against.
type siteFacts struct {
	domains    []string
	https      bool
	forceHTTPS bool
}

// normalize canonicalizes settings for the site: lists sorted, hosts lower
// case, compression types lower case and sorted. It returns the published
// form (users hashed with stored secrets kept) and the readable form.
// normalizeHashed is normalize with users given as salted hashes (they
// replace the stored ones; a user must not have a password as well).
func normalizeHashed(input Settings, facts siteFacts, stored map[string]edgeconfig.BasicAuthUser,
	hashed []edgeconfig.BasicAuthUser,
) (edgeconfig.SiteAccess, Settings, error) {
	if len(hashed) == 0 {
		return normalize(input, facts, stored)
	}
	if input.BasicAuth == nil {
		return edgeconfig.SiteAccess{}, Settings{}, ErrInvalidInput
	}
	merged := make(map[string]edgeconfig.BasicAuthUser, len(stored)+len(hashed))
	for name, user := range stored {
		merged[name] = user
	}
	for _, user := range hashed {
		if !basicAuthHashPattern.MatchString(user.Salt + ":" + user.SHA256) {
			return edgeconfig.SiteAccess{}, Settings{}, ErrInvalidInput
		}
		for _, wanted := range input.BasicAuth.Users {
			if wanted.Username == user.Username && wanted.Password != "" {
				return edgeconfig.SiteAccess{}, Settings{}, ErrInvalidInput
			}
		}
		merged[user.Username] = user
	}
	return normalize(input, facts, merged)
}

var basicAuthHashPattern = regexp.MustCompile(`^[0-9a-f]{32}:[0-9a-f]{64}$`)

func normalize(input Settings, facts siteFacts, stored map[string]edgeconfig.BasicAuthUser) (edgeconfig.SiteAccess, Settings, error) {
	settings := Settings{
		HSTS: input.HSTS, Limits: input.Limits, Maintenance: input.Maintenance, WebP: input.WebP,
		HostRedirects: make([]edgeconfig.HostRedirect, len(input.HostRedirects)),
		ForceHTTPS:    ForceHTTPS{Status: input.ForceHTTPS.Status, ExcludeHosts: []string{}},
		ResponseRules: normalizeResponseRules(input.ResponseRules),
	}
	if settings.ForceHTTPS.Status == 0 {
		settings.ForceHTTPS.Status = 301
	}
	if !slices.Contains([]int{301, 302, 307, 308}, settings.ForceHTTPS.Status) {
		return edgeconfig.SiteAccess{}, Settings{}, ErrInvalidInput
	}
	for _, host := range input.ForceHTTPS.ExcludeHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if !slices.Contains(facts.domains, host) || strings.HasPrefix(host, "*.") || slices.Contains(settings.ForceHTTPS.ExcludeHosts, host) {
			return edgeconfig.SiteAccess{}, Settings{}, ErrInvalidInput
		}
		settings.ForceHTTPS.ExcludeHosts = append(settings.ForceHTTPS.ExcludeHosts, host)
	}
	sort.Strings(settings.ForceHTTPS.ExcludeHosts)
	if len(settings.ForceHTTPS.ExcludeHosts) != 0 && len(settings.ForceHTTPS.ExcludeHosts) == len(facts.domains) {
		return edgeconfig.SiteAccess{}, Settings{}, ErrInvalidInput
	}
	if (settings.ForceHTTPS.Status != 301 || len(settings.ForceHTTPS.ExcludeHosts) != 0) && !facts.https {
		return edgeconfig.SiteAccess{}, Settings{}, ErrNeedsHTTPS
	}
	for index, redirect := range input.HostRedirects {
		redirect.SourceHost = strings.ToLower(strings.TrimSpace(redirect.SourceHost))
		redirect.TargetHost = strings.ToLower(strings.TrimSpace(redirect.TargetHost))
		settings.HostRedirects[index] = redirect
	}
	sort.Slice(settings.HostRedirects, func(left, right int) bool {
		return settings.HostRedirects[left].SourceHost < settings.HostRedirects[right].SourceHost
	})
	if input.Compression != nil {
		compression := *input.Compression
		compression.Types = []string{}
		for _, value := range input.Compression.Types {
			value = strings.ToLower(strings.TrimSpace(value))
			if !slices.Contains(compression.Types, value) {
				compression.Types = append(compression.Types, value)
			}
		}
		sort.Strings(compression.Types)
		if input.Compression.Encodings != nil {
			// sorted and without duplicates; gzip only is the absent form
			compression.Encodings = []string{}
			for _, value := range input.Compression.Encodings {
				value = strings.ToLower(strings.TrimSpace(value))
				if !slices.Contains(compression.Encodings, value) {
					compression.Encodings = append(compression.Encodings, value)
				}
			}
			sort.Strings(compression.Encodings)
			if slices.Equal(compression.Encodings, []string{edgeconfig.SiteCompressionGzip}) {
				compression.Encodings = nil
			}
		}
		settings.Compression = &compression
	}
	if settings.HSTS != nil && !facts.https {
		return edgeconfig.SiteAccess{}, Settings{}, ErrNeedsHTTPS
	}
	if page := input.Maintenance; page != nil {
		value := *page
		value.AllowedCIDRs = append([]string(nil), page.AllowedCIDRs...)
		sort.Strings(value.AllowedCIDRs)
		settings.Maintenance = &value
	}
	published := edgeconfig.SiteAccess{
		HostRedirects: settings.HostRedirects, HSTS: settings.HSTS, Compression: settings.Compression,
		Limits: settings.Limits, Maintenance: settings.Maintenance, WebP: settings.WebP,
	}
	if len(settings.ResponseRules) != 0 {
		published.ResponseRules = settings.ResponseRules
	}
	if len(published.HostRedirects) == 0 {
		published.HostRedirects = nil
	}
	if auth := input.BasicAuth; auth != nil {
		readable := &BasicAuth{Realm: auth.Realm, Users: []BasicAuthUser{}, ExcludePathPrefixes: append([]string{}, auth.ExcludePathPrefixes...)}
		sort.Strings(readable.ExcludePathPrefixes)
		users := make([]edgeconfig.BasicAuthUser, 0, len(auth.Users))
		for _, user := range auth.Users {
			secret, kept := stored[user.Username]
			if user.Password != "" {
				if len(user.Password) < 8 || len(user.Password) > 128 {
					return edgeconfig.SiteAccess{}, Settings{}, ErrInvalidInput
				}
				var err error
				if secret, err = edgeconfig.NewBasicAuthUser(user.Username, user.Password); err != nil {
					return edgeconfig.SiteAccess{}, Settings{}, err
				}
			} else if !kept {
				return edgeconfig.SiteAccess{}, Settings{}, ErrInvalidInput
			}
			users = append(users, secret)
			readable.Users = append(readable.Users, BasicAuthUser{Username: user.Username})
		}
		sort.Slice(users, func(left, right int) bool { return users[left].Username < users[right].Username })
		sort.Slice(readable.Users, func(left, right int) bool { return readable.Users[left].Username < readable.Users[right].Username })
		published.BasicAuth = &edgeconfig.SiteBasicAuth{Realm: auth.Realm, Users: users, ExcludePathPrefixes: readable.ExcludePathPrefixes}
		if len(published.BasicAuth.ExcludePathPrefixes) == 0 {
			published.BasicAuth.ExcludePathPrefixes = nil
		}
		settings.BasicAuth = readable
	}
	if !published.Empty() && edgeconfig.ValidateSiteAccess(published, facts.domains, facts.https) != nil {
		return edgeconfig.SiteAccess{}, Settings{}, ErrInvalidInput
	}
	return published, settings, nil
}

// normalizeResponseRules keeps the rules' order (it is the evaluation
// order) and lower-cases header names; nil and empty are both "none" ([]).
func normalizeResponseRules(input []edgeconfig.SiteResponseRule) []edgeconfig.SiteResponseRule {
	result := make([]edgeconfig.SiteResponseRule, 0, len(input))
	for _, rule := range input {
		value := rule
		value.ID = strings.TrimSpace(rule.ID)
		value.Statuses = append([]edgeconfig.StatusRange(nil), rule.Statuses...)
		value.Headers = make([]edgeconfig.ResponseHeaderCondition, len(rule.Headers))
		for index, condition := range rule.Headers {
			condition.Name = strings.ToLower(strings.TrimSpace(condition.Name))
			value.Headers[index] = condition
		}
		value.HeaderActions = make([]edgeconfig.ResponseHeaderAction, len(rule.HeaderActions))
		for index, action := range rule.HeaderActions {
			action.Name = strings.ToLower(strings.TrimSpace(action.Name))
			value.HeaderActions[index] = action
		}
		if len(value.Statuses) == 0 {
			value.Statuses = nil
		}
		if len(value.Headers) == 0 {
			value.Headers = nil
		}
		if len(value.HeaderActions) == 0 {
			value.HeaderActions = nil
		}
		result = append(result, value)
	}
	return result
}

// readable is the read form of stored settings.
func readable(published edgeconfig.SiteAccess, status int, exclude []string) Settings {
	settings := Settings{
		HostRedirects: append([]edgeconfig.HostRedirect{}, published.HostRedirects...),
		HSTS:          published.HSTS, Compression: published.Compression, Limits: published.Limits,
		Maintenance: published.Maintenance, WebP: published.WebP,
		ResponseRules: normalizeResponseRules(published.ResponseRules),
		ForceHTTPS:    ForceHTTPS{Status: status, ExcludeHosts: append([]string{}, exclude...)},
	}
	if auth := published.BasicAuth; auth != nil {
		settings.BasicAuth = &BasicAuth{Realm: auth.Realm, Users: []BasicAuthUser{},
			ExcludePathPrefixes: append([]string{}, auth.ExcludePathPrefixes...)}
		for _, user := range auth.Users {
			settings.BasicAuth.Users = append(settings.BasicAuth.Users, BasicAuthUser{Username: user.Username})
		}
	}
	return settings
}

// summary is the audit form of settings: what is on, never secrets.
func summary(settings Settings) map[string]any {
	result := map[string]any{
		"host_redirects":      len(settings.HostRedirects),
		"hsts":                settings.HSTS != nil,
		"compression":         "inherit",
		"connections_per_ip":  0,
		"rate_bytes_per_sec":  int64(0),
		"basic_auth_users":    0,
		"maintenance":         settings.Maintenance != nil,
		"webp":                settings.WebP != nil,
		"response_rules":      len(settings.ResponseRules),
		"force_https_status":  settings.ForceHTTPS.Status,
		"force_https_exclude": len(settings.ForceHTTPS.ExcludeHosts),
	}
	if settings.HSTS != nil {
		result["hsts_max_age"] = settings.HSTS.MaxAgeSeconds
	}
	if settings.Compression != nil {
		result["compression"] = settings.Compression.Enabled
		if settings.Compression.Enabled {
			encodings := settings.Compression.Encodings
			if encodings == nil {
				encodings = []string{edgeconfig.SiteCompressionGzip}
			}
			result["compression_encodings"] = strings.Join(encodings, ",")
			result["compression_gzip_level"] = settings.Compression.GzipLevel
			result["compression_brotli_level"] = settings.Compression.BrotliLevel
		}
	}
	if settings.Limits != nil {
		result["connections_per_ip"] = settings.Limits.ConnectionsPerIP
		result["rate_bytes_per_sec"] = settings.Limits.RateBytesPerSecond
	}
	if settings.BasicAuth != nil {
		result["basic_auth_users"] = len(settings.BasicAuth.Users)
	}
	return result
}
