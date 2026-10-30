package siteconf

import (
	"regexp"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/google/uuid"
)

// Origin auth (回源鉴权, fix-mktsiteconf5): the site's published object
// storage signing rules with their credentials. A credential never travels
// in clear: for each leaf it is sealed to that leaf's card X25519 key
// (envelope.Box, OriginAuthBoxDomain, OriginAuthAAD), keyed by the leaf's
// member ID, so this config and every stored copy of it hold ciphertext
// only. A leaf opens its own box and stores the credential under its own key.

// OriginAuthBoxDomain separates origin auth credential boxes.
const OriginAuthBoxDomain = "cdnca.market.siteconf.origin-auth/v1"

const maxOriginAuthRules = maxOrigins

var originAuthName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

type OriginAuth struct {
	Rules []OriginAuthRule `json:"rules"`
}

// OriginAuthRule is one rule; Endpoint is https://<origin host> of the
// site's port 443 origin it signs for.
type OriginAuthRule struct {
	RuleID              uuid.UUID `json:"rule_id"`
	Provider            string    `json:"provider"`
	Algorithm           string    `json:"algorithm"`
	Endpoint            string    `json:"endpoint"`
	Bucket              string    `json:"bucket,omitempty"`
	PathPrefix          string    `json:"path_prefix,omitempty"`
	Region              string    `json:"region"`
	Service             string    `json:"service"`
	SignatureTTLSeconds int       `json:"signature_ttl_seconds"`
	// EgressPolicyReference names the egress policy a non-AWS S3 endpoint
	// needs; the leaf must have one of that name allowing the host.
	EgressPolicyReference string         `json:"egress_policy_reference,omitempty"`
	Current               OriginAuthKey  `json:"current"`
	Previous              *OriginAuthKey `json:"previous,omitempty"`
	// ActivateCurrentAt (unix seconds, with Previous): Previous signs until then.
	ActivateCurrentAt int64 `json:"activate_current_at,omitempty"`
}

// OriginAuthKey is one credential: the sender's revision ref (public), its
// validity and one box per leaf member.
type OriginAuthKey struct {
	Ref       uuid.UUID                  `json:"ref"`
	NotBefore int64                      `json:"not_before"`
	ExpiresAt int64                      `json:"expires_at"`
	Sealed    map[uuid.UUID]envelope.Box `json:"sealed"`
}

// OriginAuthSecret is a box's plaintext.
type OriginAuthSecret struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

// OriginAuthAAD binds a box to its site, rule, credential and leaf.
func OriginAuthAAD(siteID, ruleID, ref, leaf uuid.UUID) []byte {
	return []byte("site=" + siteID.String() + "\x00rule=" + ruleID.String() + "\x00ref=" + ref.String() +
		"\x00leaf=" + leaf.String())
}

func (c *Config) normalizeOriginAuth() error {
	a := c.OriginAuth
	if a == nil {
		return nil
	}
	if len(a.Rules) == 0 {
		c.OriginAuth = nil
		return nil
	}
	// The signature is for https://<host>: the leaf connects over HTTPS.
	if len(a.Rules) > maxOriginAuthRules || c.OriginScheme != "https" {
		return ErrInvalid
	}
	for i := range a.Rules {
		r := &a.Rules[i]
		host, ok := strings.CutPrefix(r.Endpoint, "https://")
		if r.RuleID == uuid.Nil || !slices.Contains([]string{"s3", "oss", "cos"}, r.Provider) || !ok ||
			!slices.ContainsFunc(c.Origins, func(o Origin) bool { return o.Host == host && o.Port == 443 }) ||
			!validText(r.Algorithm, 32) || !validText(r.Bucket, 63) || !validText(r.PathPrefix, 1024) ||
			!validText(r.EgressPolicyReference, 128) ||
			!originAuthName.MatchString(r.Region) || !originAuthName.MatchString(r.Service) ||
			r.SignatureTTLSeconds < 1 || r.SignatureTTLSeconds > 3600 || !r.Current.valid() ||
			(r.Previous == nil) != (r.ActivateCurrentAt == 0) || r.Previous != nil && !r.Previous.valid() {
			return ErrInvalid
		}
	}
	slices.SortFunc(a.Rules, func(x, y OriginAuthRule) int { return strings.Compare(x.RuleID.String(), y.RuleID.String()) })
	for i := 1; i < len(a.Rules); i++ {
		if a.Rules[i].RuleID == a.Rules[i-1].RuleID {
			return ErrInvalid
		}
	}
	return nil
}

func (k OriginAuthKey) valid() bool {
	if k.Ref == uuid.Nil || k.ExpiresAt <= k.NotBefore || len(k.Sealed) == 0 || len(k.Sealed) > 256 {
		return false
	}
	for member, b := range k.Sealed {
		if member == uuid.Nil || len(b.Ephemeral) != 32 || len(b.Nonce) != 24 || len(b.Ciphertext) < 16 ||
			len(b.Ciphertext) > 16<<10 {
			return false
		}
	}
	return true
}
