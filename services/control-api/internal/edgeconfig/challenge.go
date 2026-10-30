package edgeconfig

import (
	"errors"
	"strings"

	runtimeconfig "github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

var ErrInvalidChallengeBinding = errors.New("invalid site challenge binding")

const maxSafeChallengeRevision = int64(1<<53 - 1)

type ChallengeBindingFact struct {
	TenantScopeID, SiteID, PolicyID, SecretConfigVersionID uuid.UUID
	Host                                                   string
	PolicyRevision, BindingRevision                        int64
}

type ChallengeProjection struct {
	PolicyID              string                         `json:"policy_id"`
	PolicyRevision        int64                          `json:"policy_revision"`
	BindingRevision       int64                          `json:"binding_revision"`
	SecretConfigVersionID string                         `json:"secret_config_version_id"`
	Runtime               runtimeconfig.ChallengeBinding `json:"-"`
}

func ProjectSiteChallenge(scopeID, siteID uuid.UUID, host string,
	fact *ChallengeBindingFact) (*ChallengeProjection, error) {
	if fact == nil {
		return nil, nil
	}
	if scopeID == uuid.Nil || siteID == uuid.Nil || !canonicalChallengeHost(host) ||
		fact.TenantScopeID != scopeID || fact.SiteID != siteID || !ChallengeHostCoversSite(host, fact.Host) ||
		fact.PolicyID == uuid.Nil || fact.SecretConfigVersionID == uuid.Nil ||
		fact.PolicyRevision < 1 || fact.PolicyRevision > maxSafeChallengeRevision ||
		fact.BindingRevision < 1 || fact.BindingRevision > maxSafeChallengeRevision {
		return nil, ErrInvalidChallengeBinding
	}
	policyID := fact.PolicyID.String()
	return &ChallengeProjection{
		PolicyID: policyID, PolicyRevision: fact.PolicyRevision, BindingRevision: fact.BindingRevision,
		SecretConfigVersionID: fact.SecretConfigVersionID.String(),
		Runtime:               runtimeconfig.ChallengeBinding{PolicyID: policyID, PolicyVersion: uint64(fact.PolicyRevision)},
	}, nil
}

func canonicalChallengeHost(host string) bool {
	return host != "" && len(host) <= 253 && host == strings.ToLower(host) && strings.TrimSpace(host) == host
}

// ChallengeHostCoversSite reports whether a challenge binding's host fits the
// site: the site domain itself, or for a wildcard site ("*.x.example") one
// concrete host under it (not the bare suffix), as the policy's 053 trigger
// and authorizeSiteHost require. The node matches the bound rule by site
// identity, so it challenges every host the site serves.
func ChallengeHostCoversSite(siteDomain, host string) bool {
	if suffix, wildcard := strings.CutPrefix(siteDomain, "*."); wildcard {
		return !strings.Contains(host, "*") && strings.HasSuffix(host, "."+suffix)
	}
	return host == siteDomain
}
