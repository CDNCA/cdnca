package securitypolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// QuickBlockOverride is one site's own quick block settings (
// 站点“防护”页“快速屏蔽”): the site's WAF rule library
// policy holds the defaults (Policy.QuickBlock), and an item the site sets
// replaces the library's for this site only. Each item is nil (inherit),
// or the site's value: the switches on or off; the lists replaced as a
// whole, an empty list being off. A site whose override inherits everything
// runs its library's quick block as it is.
type QuickBlockOverride struct {
	BlockIDCCN      *bool             `json:"block_idc_cn"`
	BlockIDCGlobal  *bool             `json:"block_idc_global"`
	Carriers        *[]string         `json:"carriers"`
	AllowedCrawlers *[]TrustedCrawler `json:"allowed_crawlers"`
}

// Inherits reports whether the override sets nothing.
func (override QuickBlockOverride) Inherits() bool {
	return override.BlockIDCCN == nil && override.BlockIDCGlobal == nil && override.Carriers == nil && override.AllowedCrawlers == nil
}

// TurnsOn reports whether the override itself turns a block on (which, as
// on the library, needs the IP intelligence library).
func (override QuickBlockOverride) TurnsOn() bool {
	return override.BlockIDCCN != nil && *override.BlockIDCCN || override.BlockIDCGlobal != nil && *override.BlockIDCGlobal ||
		override.Carriers != nil && len(*override.Carriers) > 0
}

// NormalizeQuickBlockOverride validates the items the override sets and puts
// them in the library's canonical form (NormalizeQuickBlock).
func NormalizeQuickBlockOverride(override *QuickBlockOverride) error {
	probe := QuickBlock{}
	if override.Carriers != nil {
		probe.Carriers = *override.Carriers
	}
	if override.AllowedCrawlers != nil {
		probe.AllowedCrawlers = *override.AllowedCrawlers
	}
	if err := NormalizeQuickBlock(&probe); err != nil {
		return err
	}
	if override.Carriers != nil {
		override.Carriers = &probe.Carriers
	}
	if override.AllowedCrawlers != nil {
		override.AllowedCrawlers = &probe.AllowedCrawlers
	}
	return nil
}

// EffectiveQuickBlock is what a site runs: the library's quick block (nil:
// never configured, all off) with the override's items in place.
func EffectiveQuickBlock(library *QuickBlock, override QuickBlockOverride) QuickBlock {
	effective := QuickBlock{Carriers: []string{}, AllowedCrawlers: []TrustedCrawler{}}
	if library != nil {
		effective = *cloneQuickBlock(library)
	}
	if override.BlockIDCCN != nil {
		effective.BlockIDCCN = *override.BlockIDCCN
	}
	if override.BlockIDCGlobal != nil {
		effective.BlockIDCGlobal = *override.BlockIDCGlobal
	}
	if override.Carriers != nil {
		effective.Carriers = slices.Clone(*override.Carriers)
	}
	if override.AllowedCrawlers != nil {
		effective.AllowedCrawlers = cloneQuickBlock(&QuickBlock{AllowedCrawlers: *override.AllowedCrawlers}).AllowedCrawlers
	}
	if effective.Carriers == nil {
		effective.Carriers = []string{}
	}
	if effective.AllowedCrawlers == nil {
		effective.AllowedCrawlers = []TrustedCrawler{}
	}
	return effective
}

// SiteQuickBlockPolicy is a site's copy of its WAF library policy (a stored
// version) with the effective quick block's system rules in place of the
// library's: same reserved IDs, same slot ahead of the user rules. An
// override that inherits everything returns policy as it is. As on the
// library: a quick block that blocks anything needs a default-allow,
// unsubscribed WAF policy; the rules may not end up empty or above 100.
func SiteQuickBlockPolicy(policy Policy, override QuickBlockOverride) (Policy, error) {
	if override.Inherits() {
		return policy, nil
	}
	if policy.Kind != KindWAF {
		return Policy{}, ErrQuickBlockUnsupported
	}
	effective := EffectiveQuickBlock(policy.QuickBlock, override)
	if effective.Active() && !QuickBlockSupported(policy) {
		return Policy{}, ErrQuickBlockUnsupported
	}
	rules := MergeQuickBlockRules(policy.ID, cloneRules(policy.Rules), &effective)
	if len(rules) == 0 {
		return Policy{}, ErrQuickBlockLastRules
	}
	if len(rules) > 100 {
		return Policy{}, ErrQuickBlockRuleBudget
	}
	site := policy
	site.Rules = rules
	site.QuickBlock = &effective
	return site, nil
}

// DecodeQuickBlockOverride decodes a stored override
// (site_quick_block_overrides.override): known items only, valid, and
// setting at least one item (a site that inherits everything has no row).
func DecodeQuickBlockOverride(raw []byte) (QuickBlockOverride, error) {
	var override QuickBlockOverride
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&override) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		NormalizeQuickBlockOverride(&override) != nil || override.Inherits() {
		return QuickBlockOverride{}, ErrInvalidInput
	}
	return override, nil
}

// ErrQuickBlockSiteOverrides: a rule library change would leave the quick
// block override of a site bound to the library unable to apply
// (QuickBlockSiteOverrideError names the sites).
var ErrQuickBlockSiteOverrides = errors.New("rule library change conflicts with site quick block overrides")

// QuickBlockSiteOverrideError is the library write guard's refusal: the new
// library version cannot carry these sites' overrides (Cause is the first
// site's SiteQuickBlockPolicy error). The site sets the item back to inherit,
// or the library change is made so the override still applies.
type QuickBlockSiteOverrideError struct {
	SiteIDs []uuid.UUID
	Cause   error
}

// Error names at most the first 10 sites (in site ID order) and the count.
func (err *QuickBlockSiteOverrideError) Error() string {
	shown := err.SiteIDs[:min(len(err.SiteIDs), 10)]
	names := make([]string, len(shown))
	for index, siteID := range shown {
		names[index] = siteID.String()
	}
	return fmt.Sprintf("%v: %d site(s) [%s]: %v", ErrQuickBlockSiteOverrides, len(err.SiteIDs), strings.Join(names, ","), err.Cause)
}

func (err *QuickBlockSiteOverrideError) Is(target error) bool {
	return target == ErrQuickBlockSiteOverrides
}

// CheckSiteQuickBlockOverridesTx is the rule library write guard: every live
// site bound to policy (its new version, written in tx) whose quick block
// override no longer applies to it refuses the write. The caller holds the
// policy row; the override rows are read FOR SHARE, so a concurrent site
// write either finished first (and is checked) or validates against this
// version once tx commits.
func CheckSiteQuickBlockOverridesTx(ctx context.Context, tx pgx.Tx, policy Policy) error {
	if policy.Kind != KindWAF {
		// Overrides apply to a site's WAF binding only.
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT override.site_id,override.override
		FROM site_quick_block_overrides override
		JOIN security_policy_site_bindings binding
		  ON binding.tenant_scope_id=override.scope_id AND binding.site_id=override.site_id
		JOIN sites site ON site.scope_id=override.scope_id AND site.id=override.site_id AND site.deleted_at IS NULL
		WHERE binding.policy_id=$1 AND binding.tenant_scope_id=$2 AND binding.policy_kind=$3
		ORDER BY override.site_id
		FOR SHARE OF override`, policy.ID, policy.ScopeID, KindWAF)
	if err != nil {
		return fmt.Errorf("read site quick block overrides: %w", err)
	}
	defer rows.Close()
	conflict := &QuickBlockSiteOverrideError{}
	for rows.Next() {
		var siteID uuid.UUID
		var raw []byte
		if err := rows.Scan(&siteID, &raw); err != nil {
			return fmt.Errorf("scan site quick block override: %w", err)
		}
		override, err := DecodeQuickBlockOverride(raw)
		if err != nil {
			return fmt.Errorf("decode site quick block override %s: %w", siteID, err)
		}
		if _, err := SiteQuickBlockPolicy(policy, override); err != nil {
			conflict.SiteIDs = append(conflict.SiteIDs, siteID)
			if conflict.Cause == nil {
				conflict.Cause = err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate site quick block overrides: %w", err)
	}
	if len(conflict.SiteIDs) > 0 {
		return conflict
	}
	return nil
}

// QuickBlockSupported reports whether policy can carry a quick block that
// blocks anything: a WAF policy of the tenant's own (not a subscribed
// library) whose default is allow.
func QuickBlockSupported(policy Policy) bool {
	_, protected := licensedWAFMetadata(policy)
	return policy.Kind == KindWAF && policy.DefaultAction == ActionAllow && !protected
}
