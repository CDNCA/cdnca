package marketsupply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/google/uuid"
)

// The site's HTTP policy on the leaf (fix-mktsiteconf3 ③): written through
// httppolicycontrol's system site write as the leaf tenant's owner, audited
// with the system actor; absent removes the leaf's.

// SiteHTTPPolicies is the subset of httppolicycontrol.Store the leaf drives.
type SiteHTTPPolicies interface {
	SetSiteSystem(ctx context.Context, request httppolicycontrol.SystemSiteWrite) (bool, error)
}

// WithHTTPPolicies lets market sites carry their HTTP policy; without it an
// http_policy block is refused (unsupported_http_policy).
func (s *Service) WithHTTPPolicies(policies SiteHTTPPolicies) *Service {
	s.httpPolicies = policies
	return s
}

func decodeHTTPPolicy(c siteconf.Config) (*httppolicycontrol.Config, error) {
	if len(c.HTTPPolicy) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(c.HTTPPolicy))
	decoder.DisallowUnknownFields()
	var config httppolicycontrol.Config
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	if _, err := httppolicycontrol.NormalizeConfig(config); err != nil {
		return nil, err
	}
	return &config, nil
}

// httpPolicyBlockers: a malformed block (http_policy_invalid), or one on a
// leaf without the system site write (unsupported_http_policy).
func (s *Service) httpPolicyBlockers(c siteconf.Config) []siteconf.Blocker {
	config, err := decodeHTTPPolicy(c)
	if err != nil {
		return []siteconf.Blocker{{Code: "http_policy_invalid"}}
	}
	if config != nil && s.httpPolicies == nil {
		return []siteconf.Blocker{{Code: "unsupported_http_policy"}}
	}
	return nil
}

// applyHTTPPolicy makes the leaf site's HTTP policy what the block says.
func (s *Service) applyHTTPPolicy(ctx context.Context, tenant tenantRef, leafSiteID uuid.UUID, req siteconf.CommitRequest) error {
	config, err := decodeHTTPPolicy(req.Config)
	if err != nil {
		return errors.Join(siteconf.ErrInvalid, err)
	}
	if s.httpPolicies == nil {
		if config != nil {
			return errors.New("market supply: HTTP policies are not configured")
		}
		return nil
	}
	_, err = s.httpPolicies.SetSiteSystem(ctx, httppolicycontrol.SystemSiteWrite{ScopeID: tenant.scopeID, SiteID: leafSiteID,
		OwnerUserID: tenant.userID, Config: config, ActorRef: "job:market_leaf_sync",
		RequestID: "market-http-" + req.SiteID.String() + "-" + strconv.FormatInt(req.Revision, 10)})
	return err
}
