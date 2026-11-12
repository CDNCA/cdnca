package cnameallocation

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Administrator-defined CNAME names (migration 658).
//
//	complete name: sites.cname_custom_label -> <name>.<CNAME domain>
//	prefix:        cname_label_settings(line_group) -> <prefix>-<8 random>
const (
	// MaxLabelLength is the DNS label limit.
	MaxLabelLength = 63
	// MaxPrefixLength leaves room for "-" and the LabelLength random characters.
	MaxPrefixLength = MaxLabelLength - 1 - LabelLength
)

// Error codes of an invalid administrator-defined name; the HTTP layers map
// them to 400 / 409 (taken) with the same code.
const (
	CodeLabelInvalid  = "cname_label_invalid"
	CodeLabelReserved = "cname_label_reserved"
	CodeLabelTaken    = "cname_label_taken"
	// FailureLabelTaken: the name was free when it was set but is claimed now.
	FailureLabelTaken = CodeLabelTaken
)

var (
	ErrLabelInvalid  = errors.New("CNAME name is invalid")
	ErrLabelReserved = errors.New("CNAME name is reserved")
	ErrLabelTaken    = errors.New("CNAME name is already taken")
)

var labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// reservedLabels cannot be handed out: they collide with infrastructure names.
var reservedLabels = map[string]bool{
	"www": true, "ns": true, "ns1": true, "ns2": true, "ns3": true, "ns4": true, "mail": true, "smtp": true,
	"imap": true, "pop": true, "mx": true, "ftp": true, "api": true, "admin": true, "root": true,
	"localhost": true, "autodiscover": true, "autoconfig": true, "_acme-challenge": true, "acme-challenge": true,
	"wpad": true, "_dmarc": true, "_domainkey": true,
}

// RelabelRequestPrefix starts the request ID of an intent that re-allocates a
// CNAME under a new administrator-defined name or prefix. Such an intent
// advances the allocation to a new hostname; an ordinary platform intent
// refreshes the allocation in place and keeps it.
const RelabelRequestPrefix = "cname-label/"

// ValidateLabel checks a complete host label (1–63 characters).
func ValidateLabel(value string) error { return validateName(value, MaxLabelLength, true) }

// ValidatePrefix checks a prefix template (1–54 characters, "-"+8 more fit in 63).
// A prefix may equal a reserved name: "www-k3d9x2ab" is not "www".
func ValidatePrefix(value string) error { return validateName(value, MaxPrefixLength, false) }

func validateName(value string, maximum int, rejectReserved bool) error {
	if value == "" || len(value) > maximum || value != strings.ToLower(value) || !labelPattern.MatchString(value) {
		return ErrLabelInvalid
	}
	if rejectReserved && (reservedLabels[value] || strings.HasPrefix(value, "_")) {
		return ErrLabelReserved
	}
	return nil
}

// PrefixedLabel is <prefix>-<random>: the random part is the keyed HMAC label.
func PrefixedLabel(prefix, random string) string { return prefix + "-" + random }

// labelSource is every administrator-defined name that can decide the label of
// one allocation. Empty means "not set" and falls through to the next source.
type labelSource struct {
	// custom: the complete name of the site (site mode only).
	custom     string
	linePrefix string
}

// effectiveLabel is the generation order, highest first:
//
//	site name > (explicit hostname, handled by the caller) > line group prefix > random
//
// custom is returned as a complete label; prefix is returned for the caller to
// combine with the HMAC label (PrefixedLabel).
func (source labelSource) effectiveLabel(legacyExplicit bool) (custom, prefix string) {
	if source.custom != "" {
		return source.custom, ""
	}
	if legacyExplicit {
		return "", ""
	}
	return "", source.linePrefix
}

// loadLabelSource reads the names that apply to the allocation. Invalid stored
// values (written outside the API) are ignored so a bad row never blocks DNS.
// A site in package mode shares its CNAME with the package, so only the line
// group prefix applies to it.
func loadLabelSource(ctx context.Context, tx pgx.Tx, req AllocateRequest) (labelSource, error) {
	var custom, linePrefix *string
	err := tx.QueryRow(ctx, `SELECT s.cname_custom_label,
			(SELECT l.label FROM cname_label_settings l WHERE l.subject_kind='line_group' AND l.subject_id=COALESCE(
				s.node_group_id,
				(SELECT NULLIF(sub.product_snapshot->'spec'->>'node_group_id','')::uuid FROM package_subscriptions sub
				 WHERE sub.tenant_scope_id=s.scope_id AND sub.id=s.package_subscription_id),
				(SELECT g.id FROM node_line_groups g WHERE g.is_platform_default AND g.deleted_at IS NULL LIMIT 1)))
		FROM sites s WHERE s.scope_id=$1 AND s.id=$2`, req.TargetScopeID, req.SiteID).Scan(&custom, &linePrefix)
	if errors.Is(err, pgx.ErrNoRows) {
		return labelSource{}, nil
	}
	if err != nil {
		return labelSource{}, err
	}
	var source labelSource
	if req.Mode == ModeSite && custom != nil && ValidateLabel(*custom) == nil {
		source.custom = *custom
	}
	if linePrefix != nil && ValidatePrefix(*linePrefix) == nil {
		source.linePrefix = *linePrefix
	}
	return source, nil
}

// labelTaken reports whether hostname is claimed by an allocation other than
// ownAllocation (a regenerate may keep the name it already holds).
func labelTaken(ctx context.Context, tx pgx.Tx, hostname string, ownAllocation uuid.UUID) (bool, error) {
	var taken bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cname_hostname_claims
		WHERE lower(hostname)=$1 AND allocation_id<>$2)`, hostname, ownAllocation).Scan(&taken)
	return taken, err
}
