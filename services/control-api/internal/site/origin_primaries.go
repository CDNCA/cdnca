package site

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Primary origins as "host[:port]" lines, for callers that edit only the origin list (the billing bridge's
// 客户区改源站): PrimaryOriginEndpoints reads them, WithPrimaryOrigins writes them back into a pool.

// PrimaryOriginEndpoints lists the pool's primary origins (level 0). An origin on the pool's own origin port
// (inherited, or the same port written out) shows the host only.
func PrimaryOriginEndpoints(pool OriginPool) []string {
	defaultOriginPorts(&pool)
	endpoints := []string{}
	for _, origin := range pool.Origins {
		if origin.Level != 0 {
			continue
		}
		if origin.PortInherited || origin.Port == inheritedOriginPort(pool) {
			endpoints = append(endpoints, origin.Host)
			continue
		}
		endpoints = append(endpoints, net.JoinHostPort(origin.Host, strconv.Itoa(origin.Port)))
	}
	return endpoints
}

// WithPrimaryOrigins returns pool with its primary origins replaced by raws ("host[:port]", as basic.origins):
// weight 1, enabled; one without a port follows the pool's origin port. The pool's other settings and its backup
// origins stay (a backup repeating a new primary is dropped), and failover tries shrink to the enabled origins.
// UpdateOrigin validates the result as any origin write.
func WithPrimaryOrigins(pool OriginPool, raws []string) (OriginPool, error) {
	if len(raws) < 1 || len(raws) > 32 {
		return OriginPool{}, fieldError("origins", "count")
	}
	defaultOriginPorts(&pool)
	seen := make(map[string]struct{}, len(raws))
	origins := make([]Origin, 0, len(raws)+len(pool.Origins))
	for _, raw := range raws {
		endpoint, host, err := normalizeOrigin(raw)
		if err != nil {
			return OriginPool{}, fieldError("origins", "invalid")
		}
		if host, err = normalizeOriginHost(host); err != nil {
			return OriginPool{}, fieldError("origins", "invalid")
		}
		origin := Origin{Host: host, Weight: 1, Enabled: true}
		if endpoint == host || endpoint == "["+host+"]" {
			origin.PortInherited, origin.Port = true, inheritedOriginPort(pool)
		} else {
			_, port, splitErr := net.SplitHostPort(endpoint)
			if splitErr != nil {
				return OriginPool{}, fieldError("origins", "invalid")
			}
			origin.Port = mustAtoi(port)
		}
		key := originCompatibilityEndpoint(origin)
		if _, exists := seen[key]; exists {
			return OriginPool{}, fieldError("origins", "duplicate")
		}
		seen[key] = struct{}{}
		origins = append(origins, origin)
	}
	for _, origin := range pool.Origins {
		if origin.Level == 0 {
			continue
		}
		if _, exists := seen[originCompatibilityEndpoint(origin)]; exists {
			continue
		}
		origins = append(origins, origin)
	}
	pool.Origins, pool.BackupOrigins = origins, nil
	enabled := 0
	for _, origin := range origins {
		if origin.Enabled {
			enabled++
		}
	}
	if pool.FailoverTries > enabled {
		pool.FailoverTries = enabled
	}
	if pool.FailoverTries < 1 {
		pool.FailoverTries = 1
	}
	return pool, nil
}

// UpdatePrimaryOrigins is UpdateOrigin of WithPrimaryOrigins(stored pool, request.Origins). The replay digest is
// the request itself (site, expected revision, normalized lines), never the pool it is merged into: a retry
// after the site page changed another pool setting replays the receipt and keeps that edit.
func (s *Service) UpdatePrimaryOrigins(ctx context.Context, actor Actor, request UpdatePrimaryOriginsRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) || len(request.Origins) < 1 || len(request.Origins) > 32 {
		return WriteResult{}, ErrInvalidInput
	}
	if request.Scheme != "" && request.Scheme != OriginSchemeHTTP && request.Scheme != OriginSchemeHTTPS {
		return WriteResult{}, &PrimaryOriginError{Field: "origin_scheme", Index: -1, Reason: OriginReasonSchemeUnsupported}
	}
	lines := make([]string, len(request.Origins))
	for index, raw := range request.Origins {
		endpoint, host, err := normalizeOrigin(raw)
		if err != nil {
			return WriteResult{}, fieldError("origins", "invalid")
		}
		if endpoint == "["+host+"]" {
			endpoint = host
		}
		lines[index] = endpoint
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
		PrimaryOrigins   []string  `json:"primary_origins"`
		Scheme           string    `json:"scheme,omitempty"`
	}{request.ID, request.ExpectedRevision, lines, request.Scheme})
	if err != nil {
		return WriteResult{}, err
	}
	result, err := s.store.UpdateOrigin(ctx, actor, UpdateOriginRequest{ID: request.ID,
		ExpectedRevision: request.ExpectedRevision, IdempotencyKey: request.IdempotencyKey,
		RequestID: request.RequestID, primaryOrigins: request.Origins, primaryScheme: request.Scheme}, digest)
	if err != nil {
		return WriteResult{}, err
	}
	redact(&result.Site, actor.ScopeKind)
	return result, nil
}

// PrimaryOrigins are a site's primary origins (PrimaryOriginEndpoints) and its 回源协议 (http, https, follow).
type PrimaryOrigins struct {
	Scheme    string
	Endpoints []string
}

// ListPrimaryOrigins is PrimaryOrigins of the sites in ids, read in one statement for a list page; a tenant actor
// reads only its own sites (others are left out).
func (s *Service) ListPrimaryOrigins(ctx context.Context, actor Actor, ids []uuid.UUID) (map[uuid.UUID]PrimaryOrigins, error) {
	if !validActor(actor) || len(ids) > 100 {
		return nil, ErrInvalidInput
	}
	var scope *uuid.UUID
	if actor.ScopeKind == "tenant" {
		scope = &actor.ScopeID
	}
	rows, err := s.store.pool.Query(ctx, `SELECT origin.site_id, origin.host, origin.port, origin.port_inherited,
		pool.origin_scheme, pool.http_port, pool.https_port
		FROM site_origins origin
		JOIN site_origin_pools pool ON pool.site_id = origin.site_id
		JOIN sites site ON site.id = origin.site_id AND site.deleted_at IS NULL
		WHERE origin.site_id = ANY($1::uuid[]) AND origin.level = 0 AND ($2::uuid IS NULL OR site.scope_id = $2)
		ORDER BY origin.site_id, origin.position`, ids, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pools := map[uuid.UUID]*OriginPool{}
	for rows.Next() {
		var id uuid.UUID
		var origin Origin
		var pool OriginPool
		if err := rows.Scan(&id, &origin.Host, &origin.Port, &origin.PortInherited, &pool.Scheme, &pool.HTTPPort,
			&pool.HTTPSPort); err != nil {
			return nil, err
		}
		if pools[id] == nil {
			pools[id] = &pool
		}
		pools[id].Origins = append(pools[id].Origins, origin)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make(map[uuid.UUID]PrimaryOrigins, len(pools))
	for id, pool := range pools {
		defaultOriginPorts(pool)
		result[id] = PrimaryOrigins{Scheme: pool.Scheme, Endpoints: PrimaryOriginEndpoints(*pool)}
	}
	return result, nil
}

// PrimaryOriginError is an ErrInvalidInput naming the refused 客户区源站 input: Field "origins" with Index its
// 0-based line, or "origin_scheme" (Index -1); Reason is one of the OriginReason codes.
type PrimaryOriginError struct {
	Field  string
	Index  int
	Reason string
}

func (e *PrimaryOriginError) Error() string {
	if e.Index < 0 {
		return "invalid site field " + e.Field + ": " + e.Reason
	}
	return "invalid site field " + e.Field + "[" + strconv.Itoa(e.Index) + "]: " + e.Reason
}

func (e *PrimaryOriginError) Unwrap() error { return ErrInvalidInput }

// Reasons of a PrimaryOriginError.
const (
	OriginReasonSchemeUnsupported = "origin_scheme_unsupported" // not http / https
	OriginReasonSchemeMismatch    = "origin_scheme_mismatch"    // the line's scheme is not the 回源协议 chosen
	OriginReasonHasPath           = "origin_has_path"           // a path, query or fragment after the host
	OriginReasonHasUserinfo       = "origin_has_userinfo"       // user:password@
	OriginReasonPortInvalid       = "origin_port_invalid"       // not 1–65535
	OriginReasonHostInvalid       = "origin_host_invalid"       // not an IP address or domain name
	OriginReasonDuplicate         = "origin_duplicate"          // the same origin as an earlier line
)

// ParsePrimaryOrigins reads the 客户区 源站 lines: "host[:port]", or the same written as a URL
// "http://host[:port]" / "https://host[:port]" (one trailing "/" is accepted; a path, query, fragment or user
// info is refused). scheme is the form's 回源协议 ("" when none was chosen); a line's own scheme must agree with
// it and with the other lines'. It returns the 回源协议 (scheme, else the lines', else "") and the canonical
// "host[:port]" lines (UpdatePrimaryOriginsRequest.Origins, NewPrimaryOriginPool). Errors are PrimaryOriginError.
func ParsePrimaryOrigins(scheme string, raws []string) (string, []string, error) {
	switch scheme {
	case "", OriginSchemeHTTP, OriginSchemeHTTPS:
	default:
		return "", nil, &PrimaryOriginError{Field: "origin_scheme", Index: -1, Reason: OriginReasonSchemeUnsupported}
	}
	lines := make([]string, len(raws))
	seen := make(map[string]struct{}, len(raws))
	for index, raw := range raws {
		lineScheme, line, reason := parsePrimaryOrigin(raw)
		switch {
		case reason != "":
		case lineScheme != "" && scheme == "":
			scheme = lineScheme
		case lineScheme != "" && lineScheme != scheme:
			reason = OriginReasonSchemeMismatch
		}
		if _, exists := seen[line]; reason == "" && exists {
			reason = OriginReasonDuplicate
		}
		if reason != "" {
			return "", nil, &PrimaryOriginError{Field: "origins", Index: index, Reason: reason}
		}
		seen[line] = struct{}{}
		lines[index] = line
	}
	return scheme, lines, nil
}

// parsePrimaryOrigin is one ParsePrimaryOrigins line: its URL scheme ("" when written without one), the
// canonical "host[:port]" and the refusal reason ("" when valid).
func parsePrimaryOrigin(raw string) (string, string, string) {
	value := strings.TrimSpace(raw)
	scheme := ""
	if index := strings.Index(value, "://"); index >= 0 {
		scheme = strings.ToLower(value[:index])
		if scheme != OriginSchemeHTTP && scheme != OriginSchemeHTTPS {
			return "", "", OriginReasonSchemeUnsupported
		}
		value = value[index+3:]
	}
	if index := strings.IndexAny(value, "/?#"); index >= 0 {
		if value[index:] != "/" {
			return "", "", OriginReasonHasPath
		}
		value = value[:index]
	}
	if strings.Contains(value, "@") {
		return "", "", OriginReasonHasUserinfo
	}
	port, hasPort := "", false
	switch {
	case strings.HasPrefix(value, "["):
		end := strings.Index(value, "]")
		if end < 0 || end+1 < len(value) && value[end+1] != ':' {
			return "", "", OriginReasonHostInvalid
		}
		port, hasPort = strings.TrimPrefix(value[end+1:], ":"), end+1 < len(value)
	case strings.Count(value, ":") == 1:
		port, hasPort = value[strings.Index(value, ":")+1:], true
	}
	if hasPort && !portDigits(port) {
		return "", "", OriginReasonPortInvalid
	}
	endpoint, host, err := normalizeOrigin(value)
	if err != nil {
		return "", "", OriginReasonHostInvalid
	}
	if _, err := normalizeOriginHost(host); err != nil {
		return "", "", OriginReasonHostInvalid
	}
	if endpoint == "["+host+"]" {
		endpoint = host
	}
	return scheme, endpoint, ""
}

// portDigits: 1–65535 written in digits only.
func portDigits(raw string) bool {
	if raw == "" || len(raw) > 5 || strings.Trim(raw, "0123456789") != "" {
		return false
	}
	return validPort(raw)
}

// NewPrimaryOriginPool is the origin pool a create names (CreateRequest.OriginPool) for the primary origins
// lines ("host[:port]", ParsePrimaryOrigins) fetched over scheme (http or https): a line without a port uses the
// scheme's default port (80, 443). It also returns the matching basic.origins lines (SiteFields.Origins). The
// settings it leaves unset follow the owner's 默认设置 and the system defaults as in any create naming a pool.
func NewPrimaryOriginPool(scheme string, lines []string) (OriginPool, []string, error) {
	if scheme != OriginSchemeHTTP && scheme != OriginSchemeHTTPS {
		return OriginPool{}, nil, &PrimaryOriginError{Field: "origin_scheme", Index: -1, Reason: OriginReasonSchemeUnsupported}
	}
	pool, err := WithPrimaryOrigins(OriginPool{Scheme: scheme, HTTPPort: 80, HTTPSPort: 443}, lines)
	if err != nil {
		return OriginPool{}, nil, err
	}
	fields := make([]string, len(pool.Origins))
	for index, origin := range pool.Origins {
		fields[index] = originCompatibilityEndpoint(origin)
	}
	return pool, fields, nil
}

// withOriginScheme sets the pool's 回源协议 to scheme (http or https; "" or the stored one keeps the pool as it
// is). The port the new scheme does not use goes back to its default (normalizeOriginPool: http keeps HTTPS port
// 443, https HTTP port 80), 跟随端口 is off, and http drops the HTTPS-only settings (SNI, trust, CA).
func withOriginScheme(pool OriginPool, scheme string) OriginPool {
	defaultOriginPorts(&pool)
	if scheme == "" || scheme == pool.Scheme {
		return pool
	}
	pool.Scheme, pool.FollowPort = scheme, false
	if scheme == OriginSchemeHTTP {
		pool.HTTPSPort, pool.TLS = 443, OriginTLS{Trust: OriginTrustSystem}
	} else {
		pool.HTTPPort = 80
	}
	return pool
}

// originPoolChangedSince reports whether the site's origin pool changed after the site revision seen, i.e. a
// read at seen did not show the pool now stored; current is the locked site's revision. The pool's version is
// site_origin_pools.site_revision (migration 703, written by replaceOriginPool and insertOriginPool); a pool
// without one (written before 713) counts as changed unless seen is current.
func originPoolChangedSince(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, seen, current int64) (bool, error) {
	if seen > current {
		return true, nil
	}
	var changedAt *int64
	if err := tx.QueryRow(ctx, `SELECT site_revision FROM site_origin_pools WHERE site_id = $1`, siteID).Scan(&changedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}
	if changedAt == nil {
		return seen != current, nil
	}
	return seen < *changedAt, nil
}
