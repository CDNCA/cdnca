package marketsubscribe

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

// Origin auth (回源鉴权, fix-mktsiteconf5): the site's live rules go into
// siteconf with each credential sealed to every leaf's card box key, keyed by
// leaf member ID (10-28 decision ③); siteconf, its stored revisions and the
// preview never hold a credential in clear. Plaintext lives only between
// SiteRulesSystem and the seal, then is wiped.

// OriginAuthReader reads a site's live rules with credentials in clear
// (originauthcontrol.Service.SiteRulesSystem).
type OriginAuthReader interface {
	SiteRulesSystem(ctx context.Context, siteID uuid.UUID) ([]originauthcontrol.SiteRule, error)
}

// WithOriginAuth lets PlanSite carry origin auth rules (the leaves' cards
// come from WithDigests' Cards); without it a site with live rules is blocked
// (site_origin_auth).
func (s *Service) WithOriginAuth(reader OriginAuthReader) *Service {
	s.originAuth = reader
	return s
}

// leafBoxKeys returns the card box key of every leaf behind the site.
func (s *Service) leafBoxKeys(ctx context.Context, siteID uuid.UUID) (map[uuid.UUID][]byte, error) {
	targets, err := s.targets(ctx, siteID)
	if err != nil {
		return nil, err
	}
	keys := map[uuid.UUID][]byte{}
	for _, t := range targets {
		if _, done := keys[t.leaf.LeafMemberID]; done {
			continue
		}
		c, err := s.cards.Card(ctx, t.leaf.LeafMemberID)
		if err != nil {
			return nil, err
		}
		keys[t.leaf.LeafMemberID] = c.BoxPublicKey
	}
	return keys, nil
}

// compileOriginAuth puts the site's live rules into cfg; Unsupported when
// they cannot be carried (Detail: origin_auth_off — no reader or no cards;
// no_leaf — no market binding; credential — a credential cannot be read).
func (s *Service) compileOriginAuth(ctx context.Context, current site.Site, cfg *siteconf.Config, live bool) ([]Unsupported, error) {
	if !live || current.OriginPool.OriginAuthEnabled != nil && !*current.OriginPool.OriginAuthEnabled {
		return nil, nil
	}
	if s.originAuth == nil || s.cards == nil {
		return []Unsupported{{Code: "site_origin_auth", Detail: "origin_auth_off"}}, nil
	}
	keys, err := s.leafBoxKeys(ctx, current.ID)
	if errors.Is(err, ErrNoMarketBinding) || errors.Is(err, ErrNoLeaves) {
		return []Unsupported{{Code: "site_origin_auth", Detail: "no_leaf"}}, nil
	}
	if err != nil {
		return nil, err
	}
	rules, err := s.originAuth.SiteRulesSystem(ctx, current.ID)
	if errors.Is(err, originauthcontrol.ErrCredentialUnverified) || errors.Is(err, originauthcontrol.ErrEncryptionUnavailable) {
		return []Unsupported{{Code: "site_origin_auth", Detail: "credential"}}, nil
	}
	if err != nil {
		return nil, err
	}
	defer originauthcontrol.ClearSiteRules(rules)
	if cfg.OriginAuth, err = sealOriginAuth(current.ID, rules, keys); err != nil {
		return nil, err
	}
	return nil, nil
}

// sealOriginAuth is the origin_auth block of rules for the leaves' box keys.
// Boxes are derived from each credential's keyring seed, so recompiling the
// same rules for the same leaves (preview, then apply) gives the same digest.
func sealOriginAuth(siteID uuid.UUID, rules []originauthcontrol.SiteRule, keys map[uuid.UUID][]byte) (*siteconf.OriginAuth, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	out := &siteconf.OriginAuth{}
	for _, r := range rules {
		rule := siteconf.OriginAuthRule{RuleID: r.RuleID, Provider: r.Provider, Algorithm: r.Algorithm, Endpoint: r.Endpoint,
			Bucket: r.Bucket, PathPrefix: r.PathPrefix, Region: r.Region, Service: r.Service,
			SignatureTTLSeconds: r.SignatureTTLSeconds, EgressPolicyReference: r.EgressPolicyReference}
		var err error
		if rule.Current, err = sealOriginAuthKey(siteID, r.RuleID, r.Current, keys); err != nil {
			return nil, err
		}
		if r.Previous != nil && r.ActivateCurrentAt != nil {
			previous, err := sealOriginAuthKey(siteID, r.RuleID, *r.Previous, keys)
			if err != nil {
				return nil, err
			}
			rule.Previous, rule.ActivateCurrentAt = &previous, r.ActivateCurrentAt.Unix()
		}
		out.Rules = append(out.Rules, rule)
	}
	return out, nil
}

func sealOriginAuthKey(siteID, ruleID uuid.UUID, key originauthcontrol.SiteKey, keys map[uuid.UUID][]byte) (siteconf.OriginAuthKey, error) {
	plaintext, err := json.Marshal(siteconf.OriginAuthSecret{AccessKeyID: key.Secret.AccessKeyID,
		SecretAccessKey: key.Secret.SecretAccessKey, SessionToken: key.Secret.SessionToken})
	if err != nil {
		return siteconf.OriginAuthKey{}, err
	}
	defer clear(plaintext)
	out := siteconf.OriginAuthKey{Ref: key.RevisionRef, NotBefore: key.NotBefore.Unix(), ExpiresAt: key.ExpiresAt.Unix(),
		Sealed: map[uuid.UUID]envelope.Box{}}
	for leaf, public := range keys {
		aad := siteconf.OriginAuthAAD(siteID, ruleID, key.RevisionRef, leaf)
		// One seed per (credential, leaf key, context): no two boxes share an
		// ephemeral key.
		material := make([]byte, 0, len(key.Seed)+len(public)+len(aad))
		material = append(append(append(material, key.Seed[:]...), public...), aad...)
		seed := sha256.Sum256(material)
		clear(material)
		box, err := envelope.SealBoxSeeded(seed, siteconf.OriginAuthBoxDomain, plaintext, aad, public)
		clear(seed[:])
		if err != nil {
			return siteconf.OriginAuthKey{}, err
		}
		out.Sealed[leaf] = box
	}
	return out, nil
}
