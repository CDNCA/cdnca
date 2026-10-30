package marketsupply

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The site's origin auth on the leaf (fix-mktsiteconf5): the leaf opens its
// own box of each credential with its market box key, writes the rules
// through originauthcontrol's system site write (the credential re-sealed
// with this controller's keyring at once, no cloud verification) and wipes
// the plaintext. Rules the config no longer has are deleted before the site
// commit (a live rule pins its origin, site.checkOriginAuthHTTPS), the rest
// is written after it.

// SiteOriginAuth is the subset of originauthcontrol.Service the leaf drives.
type SiteOriginAuth interface {
	ValidateSiteRule(rule originauthcontrol.SiteRule) error
	SetSiteSystem(ctx context.Context, request originauthcontrol.SystemSiteWrite) (bool, error)
}

// WithOriginAuth lets market sites carry origin auth; self returns this
// leaf's member ID and box private key (marketruntime identity). Without
// both an origin_auth block is refused (unsupported_origin_auth).
func (s *Service) WithOriginAuth(store SiteOriginAuth, self func() (uuid.UUID, []byte)) *Service {
	s.originAuth, s.boxSelf = store, self
	return s
}

// originAuthBlockers: a block whose rules this leaf cannot hold
// (origin_auth_invalid, detail the rule ID), one without this leaf's box or
// that does not open (origin_auth_sealed), or a leaf without the system
// write (unsupported_origin_auth).
func (s *Service) originAuthBlockers(c siteconf.Config, siteID uuid.UUID) []siteconf.Blocker {
	if c.OriginAuth == nil {
		return nil
	}
	if s.originAuth == nil || s.boxSelf == nil {
		return []siteconf.Blocker{{Code: "unsupported_origin_auth"}}
	}
	rules, err := s.openOriginAuth(c, siteID)
	defer originauthcontrol.ClearSiteRules(rules)
	var sealed originAuthSealedError
	if errors.As(err, &sealed) {
		return []siteconf.Blocker{{Code: "origin_auth_sealed", Detail: sealed.rule.String()}}
	}
	if err != nil {
		return []siteconf.Blocker{{Code: "origin_auth_invalid"}}
	}
	for _, rule := range rules {
		if err := s.originAuth.ValidateSiteRule(rule); err != nil {
			return []siteconf.Blocker{{Code: "origin_auth_invalid", Detail: rule.RuleID.String()}}
		}
	}
	return nil
}

type originAuthSealedError struct{ rule uuid.UUID }

func (e originAuthSealedError) Error() string {
	return "origin auth credential box does not open: " + e.rule.String()
}

// openOriginAuth decrypts this leaf's boxes into rules at the leaf's source
// positions (the config's origins in order, as siteFields writes them). The
// caller clears them.
func (s *Service) openOriginAuth(c siteconf.Config, siteID uuid.UUID) ([]originauthcontrol.SiteRule, error) {
	if c.OriginAuth == nil {
		return nil, nil
	}
	self, private := s.boxSelf()
	var out []originauthcontrol.SiteRule
	for _, r := range c.OriginAuth.Rules {
		position := 0
		for i, o := range c.Origins {
			if "https://"+o.Host == r.Endpoint && o.Port == 443 {
				position = i + 1
				break
			}
		}
		rule := originauthcontrol.SiteRule{RuleID: r.RuleID, SourcePosition: position, Provider: r.Provider,
			Algorithm: r.Algorithm, Endpoint: r.Endpoint, Bucket: r.Bucket, PathPrefix: r.PathPrefix, Region: r.Region,
			Service: r.Service, SignatureTTLSeconds: r.SignatureTTLSeconds, EgressPolicyReference: r.EgressPolicyReference}
		var err error
		if rule.Current, err = openOriginAuthKey(siteID, r.RuleID, r.Current, self, private); err != nil {
			originauthcontrol.ClearSiteRules(append(out, rule))
			return nil, err
		}
		if r.Previous != nil {
			previous, err := openOriginAuthKey(siteID, r.RuleID, *r.Previous, self, private)
			if err != nil {
				originauthcontrol.ClearSiteRules(append(out, rule))
				return nil, err
			}
			at := time.Unix(r.ActivateCurrentAt, 0).UTC()
			rule.Previous, rule.ActivateCurrentAt = &previous, &at
		}
		out = append(out, rule)
	}
	return out, nil
}

func openOriginAuthKey(siteID, ruleID uuid.UUID, key siteconf.OriginAuthKey, self uuid.UUID, private []byte) (originauthcontrol.SiteKey, error) {
	box, found := key.Sealed[self]
	if !found {
		return originauthcontrol.SiteKey{}, originAuthSealedError{rule: ruleID}
	}
	plaintext, err := envelope.OpenBox(siteconf.OriginAuthBoxDomain, box,
		siteconf.OriginAuthAAD(siteID, ruleID, key.Ref, self), private)
	if err != nil {
		return originauthcontrol.SiteKey{}, originAuthSealedError{rule: ruleID}
	}
	defer clear(plaintext)
	var secret siteconf.OriginAuthSecret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return originauthcontrol.SiteKey{}, originAuthSealedError{rule: ruleID}
	}
	return originauthcontrol.SiteKey{RevisionRef: key.Ref, NotBefore: time.Unix(key.NotBefore, 0).UTC(),
		ExpiresAt: time.Unix(key.ExpiresAt, 0).UTC(), Secret: originauthcontrol.CredentialSecret{
			AccessKeyID: secret.AccessKeyID, SecretAccessKey: secret.SecretAccessKey, SessionToken: secret.SessionToken}}, nil
}

// applyOriginAuth makes the leaf site's origin auth what the block says;
// prune only deletes the rules it will not keep (before the site commit).
func (s *Service) applyOriginAuth(ctx context.Context, tenant tenantRef, leafSiteID uuid.UUID, req siteconf.CommitRequest, prune bool) error {
	if s.originAuth == nil || s.boxSelf == nil {
		if req.Config.OriginAuth != nil {
			return errors.New("market supply: origin auth is not configured")
		}
		return nil
	}
	rules, err := s.openOriginAuth(req.Config, req.SiteID)
	defer originauthcontrol.ClearSiteRules(rules)
	if err != nil {
		return errors.Join(siteconf.ErrInvalid, err)
	}
	step := "set"
	if prune {
		step = "prune"
	}
	_, err = s.originAuth.SetSiteSystem(ctx, originauthcontrol.SystemSiteWrite{ScopeID: tenant.scopeID, SiteID: leafSiteID,
		OwnerUserID: tenant.userID, Rules: rules, PruneOnly: prune, ActorRef: "job:market_leaf_sync",
		RequestID: "market-auth-" + step + "-" + req.SiteID.String() + "-" + strconv.FormatInt(req.Revision, 10)})
	return err
}

// OriginAuthDelivery is the subset of edgepublish.OriginAuthDeliverer the
// leaf drives (fix-mktsiteconf6): the credentials the leaf wrote go to the
// nodes by a system secret rollout, with no manual "publish to nodes".
type OriginAuthDelivery interface {
	Deliver(ctx context.Context, scopeID, ownerID uuid.UUID) (edgepublish.OriginAuthDeliveryStatus, error)
	Status(ctx context.Context, scopeID uuid.UUID) (edgepublish.OriginAuthDeliveryStatus, error)
}

func (s *Service) WithOriginAuthDelivery(delivery OriginAuthDelivery) *Service {
	s.originAuthDelivery = delivery
	return s
}

// deliverOriginAuth starts the tenant's origin auth delivery after a commit
// and returns what the subscriber should know (advisory: the site is
// committed; the background loop retries). Delivered or on its way says
// nothing; otherwise origin_auth_delivery with the reason (or the state).
func (s *Service) deliverOriginAuth(ctx context.Context, tenant tenantRef, c siteconf.Config) []siteconf.Blocker {
	if c.OriginAuth == nil || s.originAuthDelivery == nil {
		return nil
	}
	status, err := s.originAuthDelivery.Deliver(ctx, tenant.scopeID, tenant.userID)
	if err != nil {
		return []siteconf.Blocker{{Code: "origin_auth_delivery", Detail: edgepublish.OriginAuthDeliveryUnavailable}}
	}
	return originAuthDeliveryAdvisory(status)
}

func originAuthDeliveryAdvisory(status edgepublish.OriginAuthDeliveryStatus) []siteconf.Blocker {
	switch status.State {
	case edgepublish.OriginAuthDeliveryNone, edgepublish.OriginAuthDeliveryDelivered, edgepublish.OriginAuthDeliveryDelivering:
		return nil
	}
	detail := status.Reason
	if detail == "" {
		detail = status.State
	}
	return []siteconf.Blocker{{Code: "origin_auth_delivery", Detail: detail}}
}

// originAuthDeliveryEvery is how often the background loop retries the
// market tenants' deliveries (nodes coming online, backoff expiring).
const originAuthDeliveryEvery = 30 * time.Second

// ReconcileOriginAuthDelivery delivers the latest origin auth publication of
// every market tenant scope that has one.
func (s *Service) ReconcileOriginAuthDelivery(ctx context.Context) error {
	if s.originAuthDelivery == nil {
		return nil
	}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT publication.tenant_scope_id, account.id
		FROM origin_auth_publications publication
		JOIN memberships membership ON membership.scope_id=publication.tenant_scope_id
		JOIN users account ON account.id=membership.user_id AND account.username LIKE $1
		ORDER BY 1`, tenantPrefix+"%")
	if err != nil {
		return err
	}
	tenants, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenantRef, error) {
		var tenant tenantRef
		return tenant, row.Scan(&tenant.scopeID, &tenant.userID)
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, tenant := range tenants {
		if _, err := s.originAuthDelivery.Deliver(ctx, tenant.scopeID, tenant.userID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RunOriginAuthDelivery reconciles every originAuthDeliveryEvery until ctx ends.
func (s *Service) RunOriginAuthDelivery(ctx context.Context, logf func(string, ...any)) error {
	ticker := time.NewTicker(originAuthDeliveryEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if err := s.ReconcileOriginAuthDelivery(ctx); err != nil && ctx.Err() == nil {
			logf("market origin auth delivery failed", "err", err)
		}
	}
}
