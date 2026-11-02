package dnsacme

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Accept-time checks of a certificate order: an
// order the dispatcher can only fail is refused when it is placed, with the
// domain to fix, instead of sitting in 申请中.
var (
	// ErrDNSZoneUnavailable: the DNS account of a DNS-01 order hosts no
	// zone covering every domain (the dispatcher fails an older order with
	// the same rule, acme_dns_zone_unavailable).
	ErrDNSZoneUnavailable = errors.New("the DNS account hosts no zone for the domains")
	// ErrHTTP01NotServing: an HTTP-01 domain is not a live site of the scope,
	// or its line groups have no serving node (acme_http01_no_serving_node).
	ErrHTTP01NotServing = errors.New("the domain is not a live site with a serving node")
)

// OrderDomainError names the domain an order was refused for.
type OrderDomainError struct {
	Err    error
	Domain string
}

func (e *OrderDomainError) Error() string { return e.Err.Error() + ": " + e.Domain }
func (e *OrderDomainError) Unwrap() error { return e.Err }

// dnsZoneUnavailableReasonFormat is also the format() of migration 621.
const dnsZoneUnavailableReasonFormat = "所选 DNS API 下没有托管 %s 的解析域，无法用 DNS 验证；请添加该域名所在 DNS 服务商的 API，或改用 HTTP 验证"

// DNSZoneUnavailableReason is the failure_reason of an order failed with
// acme_dns_zone_unavailable.
func DNSZoneUnavailableReason(domain string) string {
	return fmt.Sprintf(dnsZoneUnavailableReasonFormat, domain)
}

// HTTP01Readiness reports, for an HTTP-01 order, the first domain that is not
// a live site of scopeID with a serving node (notServing, "" when all are),
// and the domains whose last access check found DNS pointing elsewhere
// (validation will fail until fixed; the order is still accepted). The
// production check is acmehttp01.OrderReadiness, the rule its Publish uses.
type HTTP01Readiness func(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, domains []string) (notServing string, pointsElsewhere []string, err error)

// CheckHTTP01With makes CreateOrder refuse an HTTP-01 order whose domain no
// node serves. Without it the order is accepted unchecked. Call before use.
func (s *Store) CheckHTTP01With(check HTTP01Readiness) { s.http01 = check }

// ManagedZoneFor is the zone of providerID (in scopeID) that a DNS-01 order
// for domains publishes its TXT records in: the longest zone name that is
// every domain (a wildcard by its base) or a parent of it. found is false
// when no zone covers them all; uncovered is then the first domain that no
// zone of the account covers (the first domain when each is covered by some
// zone but none covers all). The zone rows are locked FOR SHARE.
func ManagedZoneFor(ctx context.Context, tx pgx.Tx, scopeID, providerID uuid.UUID, domains []string) (
	zoneID uuid.UUID, uncovered string, found bool, err error,
) {
	rows, err := tx.Query(ctx, `SELECT zone.id,zone.name FROM dns_zones zone
		WHERE zone.scope_id=$1 AND zone.provider_id=$2
		ORDER BY char_length(zone.name) DESC,zone.id FOR SHARE OF zone`, scopeID, providerID)
	if err != nil {
		return uuid.Nil, "", false, err
	}
	defer rows.Close()
	type zone struct {
		id   uuid.UUID
		name string
	}
	var zones []zone
	for rows.Next() {
		var item zone
		if err := rows.Scan(&item.id, &item.name); err != nil {
			return uuid.Nil, "", false, err
		}
		if item.id != uuid.Nil && item.name != "" && item.name == strings.ToLower(strings.TrimSpace(item.name)) {
			zones = append(zones, item)
		}
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, "", false, err
	}
	inZone := func(domain, name string) bool {
		base := strings.TrimPrefix(domain, "*.")
		return base == name || strings.HasSuffix(base, "."+name)
	}
	for _, item := range zones {
		covers := true
		for _, domain := range domains {
			if !inZone(domain, item.name) {
				covers = false
				break
			}
		}
		if covers {
			return item.id, "", true, nil
		}
	}
	for _, domain := range domains {
		covered := false
		for _, item := range zones {
			if inZone(domain, item.name) {
				covered = true
				break
			}
		}
		if !covered {
			return uuid.Nil, strings.TrimPrefix(domain, "*."), false, nil
		}
	}
	if len(domains) > 0 {
		uncovered = strings.TrimPrefix(domains[0], "*.")
	}
	return uuid.Nil, uncovered, false, nil
}

// refusePlatformDNSCopyOrder: a DNS-01 certificate order never uses the
// platform DNS copy, whoever orders (refusePlatformManagedUse lets a platform
// administrator use it for zones): it only hosts the platform's CNAME zones,
// so the order could only fail.
func refusePlatformDNSCopyOrder(ctx context.Context, tx pgx.Tx, scopeID, providerID uuid.UUID) error {
	var managedBy string
	err := tx.QueryRow(ctx, `SELECT managed_by FROM dns_providers WHERE scope_id=$1 AND id=$2`, scopeID, providerID).
		Scan(&managedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // the insert's foreign key refuses it
	}
	if err != nil {
		return err
	}
	if IsPlatformManagedProvider(managedBy, scopeID, providerID) {
		return ErrPlatformManagedProvider
	}
	return nil
}

// checkOrderChallenge refuses an order the dispatcher could only fail: a
// DNS-01 order needs a DNS account hosting every domain; an HTTP-01 order
// needs each domain to be a live site with a serving node (when
// CheckHTTP01With is set). It returns the HTTP-01 domains whose DNS points
// elsewhere (accepted, with a warning).
func (s *Store) checkOrderChallenge(ctx context.Context, tx pgx.Tx, request CreateOrderRequest) ([]string, error) {
	switch {
	case request.ChallengeType == "dns-01" && request.DNSProviderID != nil:
		_, uncovered, found, err := ManagedZoneFor(ctx, tx, request.TargetScopeID, *request.DNSProviderID, request.Domains)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, &OrderDomainError{Err: ErrDNSZoneUnavailable, Domain: uncovered}
		}
	case request.ChallengeType == "http-01" && s.http01 != nil:
		notServing, elsewhere, err := s.http01(ctx, tx, request.TargetScopeID, request.Domains)
		if err != nil {
			return nil, err
		}
		if notServing != "" {
			return nil, &OrderDomainError{Err: ErrHTTP01NotServing, Domain: notServing}
		}
		return elsewhere, nil
	}
	return nil, nil
}

// codeOrderSuperseded / orderSupersededReason: an unfinished order a new
// order for the same domains replaced (失败或卡住的申请不能一直占用).
const (
	codeOrderSuperseded   = "acme_order_superseded"
	orderSupersededReason = "申请超时未完成，已被新的申请取代"
)

// refuseOrderInFlight: ErrOrderInFlight when the scope has an order for
// exactly this domain set (set equality: an order's domains are unique) that
// is running now, i.e. its issuance outbox row is leased with an unexpired
// lease; a second ACME order then could be handed the same CA order. Any
// other unfinished order for the set (queued, waiting for a retry, stalled,
// its outbox already failed) is failed here as acme_order_superseded, so a
// failed or stuck order never blocks the next one. The advisory lock (on the
// sorted set normalizeDomains leaves) serializes two concurrent orders for
// one set; the order rows are locked so a dispatcher claim of a superseded
// order sees it failed.
func refuseOrderInFlight(ctx context.Context, tx pgx.Tx, auditor func(pgx.Tx, uuid.UUID, map[string]any) error,
	scopeID uuid.UUID, domains []string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('certificate_orders.in_flight:' || $1::text || ':' || array_to_string($2::text[], ','), 0))`,
		scopeID, domains); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT certificate_order.id,certificate_order.status,certificate_order.revision,
		EXISTS(SELECT 1 FROM dns_acme_outbox outbox
			WHERE outbox.scope_id=certificate_order.scope_id AND outbox.aggregate_id=certificate_order.id
			  AND outbox.status='processing' AND outbox.lease_expires_at > statement_timestamp())
		FROM certificate_orders certificate_order
		WHERE certificate_order.scope_id=$1 AND certificate_order.status IN ('pending','validating','issuing')
		  AND certificate_order.domains @> $2::text[] AND certificate_order.domains <@ $2::text[]
		ORDER BY certificate_order.id FOR UPDATE OF certificate_order`, scopeID, domains)
	if err != nil {
		return err
	}
	type unfinished struct {
		id       uuid.UUID
		status   string
		revision int64
		running  bool
	}
	orders, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (unfinished, error) {
		var item unfinished
		return item, row.Scan(&item.id, &item.status, &item.revision, &item.running)
	})
	if err != nil {
		return err
	}
	for _, order := range orders {
		if order.running {
			return ErrOrderInFlight
		}
	}
	for _, order := range orders {
		command, err := tx.Exec(ctx, `UPDATE certificate_orders SET status='failed',failure_code=$4,failure_reason=$5,
			revision=revision+1,updated_at=greatest(updated_at,statement_timestamp())
			WHERE scope_id=$1 AND id=$2 AND status=$3 AND revision=$6`,
			scopeID, order.id, order.status, codeOrderSuperseded, orderSupersededReason, order.revision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		if err := auditor(tx, order.id, map[string]any{
			"from_status": order.status, "to_status": "failed",
			"operation": "supersede", "reason": codeOrderSuperseded,
		}); err != nil {
			return err
		}
	}
	return nil
}
