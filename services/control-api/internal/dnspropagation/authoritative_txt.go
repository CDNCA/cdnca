package dnspropagation

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// AuthoritativeTXT checks an ACME DNS-01 TXT value against every
// authoritative name server of the zone that holds the record (FX05②), so
// the CA is not asked to validate while a provider is still propagating.
type AuthoritativeTXT struct {
	source          Source
	endpointTimeout time.Duration
	logger          *slog.Logger
}

func NewAuthoritativeTXT(source Source) (*AuthoritativeTXT, error) {
	if source == nil {
		return nil, ErrInvalidInput
	}
	return &AuthoritativeTXT{source: source, endpointTimeout: defaultEndpointTimeout, logger: slog.Default()}, nil
}

// maxZoneWalk bounds the parent labels tried while looking for the zone cut.
const maxZoneWalk = 8

// TXTVisible reports whether all authoritative servers of the closest
// enclosing zone answer value for name. A server that errors, or a zone that
// cannot be discovered, counts as not visible yet.
func (checker *AuthoritativeTXT) TXTVisible(ctx context.Context, name, value string) (bool, error) {
	if checker == nil || ctx == nil || value == "" {
		return false, ErrInvalidInput
	}
	owner := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")) + "."
	if owner == "." {
		return false, ErrInvalidInput
	}
	const operationID = "acme-dns01-authoritative-txt"
	var delegation Delegation
	for zone, step := owner, 0; zone != "" && step < maxZoneWalk; step++ {
		found, err := checker.source.Discover(ctx, operationID, zone)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		if err == nil && len(found.Authorities) > 0 {
			delegation = found
			break
		}
		_, parent, ok := strings.Cut(zone, ".")
		if !ok || parent == "" || !strings.Contains(strings.TrimSuffix(parent, "."), ".") {
			// Never treat a TLD as the zone of an ACME challenge.
			break
		}
		zone = parent
	}
	if len(delegation.Authorities) == 0 {
		return false, nil
	}
	// N21: authorities are queried concurrently with a per-endpoint timeout;
	// unreachable, refused, timed-out or unsupported-family endpoints are
	// skipped. A strict majority of NS host names must have an answering
	// address (same rule as Engine), and every answering endpoint must serve
	// the value.
	results, skipped, err := observeConcurrently(ctx, checker.source, checker.endpointTimeout, operationID, owner,
		[]dnscheck.RecordType{dnscheck.RecordTXT}, delegation.Authorities, len(delegation.Authorities))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		return false, nil
	}
	if len(skipped) != 0 {
		checker.logger.Debug("acme dns-01 authoritative txt check skipped unavailable endpoints",
			"zone", delegation.Zone, "skipped", skipped)
	}
	answered := make([]Resolver, 0, len(results))
	for _, result := range results {
		if result.skipped {
			continue
		}
		answered = append(answered, result.resolver)
		visible := false
		for _, set := range result.observation.Records {
			if set.Type == dnscheck.RecordTXT && slices.Contains(set.Values, value) {
				visible = true
			}
		}
		if !visible {
			return false, nil
		}
	}
	if !authorityNamesQuorum(delegation.Authorities, answered) {
		return false, nil
	}
	return true, nil
}
