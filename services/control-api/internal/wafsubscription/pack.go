package wafsubscription

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
)

// Revision is a subscriber pack version "<major>.<minor>.0": major is the
// subscription revision (bumped when the compiled rules change), minor counts
// changes of the pack text within one revision (the operator renamed the
// subscription or edited its description).
type Revision struct {
	Major int64
	Minor int64
}

func (r Revision) String() string { return fmt.Sprintf("%d.%d.0", r.Major, r.Minor) }

func parseRevision(version string) (Revision, bool) {
	parts := strings.Split(version, ".")
	if len(parts) != 3 || parts[2] != "0" {
		return Revision{}, false
	}
	major, majorErr := strconv.ParseInt(parts[0], 10, 64)
	minor, minorErr := strconv.ParseInt(parts[1], 10, 64)
	if majorErr != nil || minorErr != nil || major < 0 || minor < 0 {
		return Revision{}, false
	}
	return Revision{Major: major, Minor: minor}, true
}

func (r Revision) less(other Revision) bool {
	return r.Major < other.Major || r.Major == other.Major && r.Minor < other.Minor
}

// PackID is the user layer pack a tenant's subscription keeps:
// user/<tenant scope>/waf-sub-<subscription id without dashes>.
func PackID(tenantScope, subscriptionID uuid.UUID) string {
	return "user/" + tenantScope.String() + "/" + rulepackcontrol.SubscriptionPackPrefix +
		strings.ReplaceAll(subscriptionID.String(), "-", "")
}

// Pack is the cdnca.rule-pack/v1 document of a subscriber pack. Every rule
// is exported, so a conflicting rule can be switched off on its own at any
// level instead of the whole pack.
func Pack(tenantScope, subscriptionID uuid.UUID, name, description string, version Revision, rules []rulepack.Rule) rulepack.Pack {
	exports := make([]string, 0, len(rules))
	for _, rule := range rules {
		exports = append(exports, rule.ID)
	}
	name = packText(name, 128)
	if name == "" {
		name = "WAF subscription"
	}
	return rulepack.Pack{Schema: rulepack.Schema, PackID: PackID(tenantScope, subscriptionID), Version: version.String(),
		Layer: rulepack.LayerUser, Engine: rulepack.EngineWAFV2, EngineMinVersion: 1, Name: name,
		Description: packText(description, 1000), ParamsSchema: map[string]rulepack.ParamSpec{}, Exports: exports,
		Rules: rules, Defaults: rulepack.Params{}}
}

// packText makes operator text valid pack text: control characters become
// spaces, trimmed, at most limit runes.
func packText(value string, limit int) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value))
	if runes := []rune(value); len(runes) > limit {
		value = strings.TrimSpace(string(runes[:limit]))
	}
	return value
}
