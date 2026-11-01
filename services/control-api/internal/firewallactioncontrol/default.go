package firewallactioncontrol

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
)

// SystemDefaultPolicy is the effective policy of a site whose tenant never
// saved a default (the console's former new-policy values). It is shown, not
// delivered: its block network is a documentation range.
func SystemDefaultPolicy() PolicyInput {
	return PolicyInput{
		NormalAction: ActionReturnPage, EscalatedAction: ActionNFTables,
		EngageThreshold: 100, RecoverThreshold: 20, RecoveryWindows: 3,
		BlockNetworks: []string{"198.51.100.0/24"}, TrustedProxies: []string{}, TrustedCrawlers: []TrustedCrawler{},
		ReturnPage: ReturnPage{Status: 429, ContentType: "text/plain; charset=utf-8", Body: "Request limited"},
	}
}

// OwnPolicyID is the policy ID of a site's own policy.
func OwnPolicyID(scopeID, siteID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("cdnca/firewall-action/"+scopeID.String()+"/"+siteID.String()))
}

// InheritedPolicyID is the policy ID of a site's inherited delivery. It
// differs from the site's own policy ID, so the node's escalation state and
// nftables scope of an earlier own policy never carry over to the default.
func InheritedPolicyID(scopeID, siteID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("cdnca/firewall-action-default/"+scopeID.String()+"/"+siteID.String()))
}

// encodeDefaultDocument is the stored tenant default: the normalized policy.
func encodeDefaultDocument(policy PolicyInput) ([]byte, error) {
	if policy.TrustedProxies == nil {
		policy.TrustedProxies = []string{}
	}
	if policy.TrustedCrawlers == nil {
		policy.TrustedCrawlers = []TrustedCrawler{}
	}
	return json.Marshal(policy)
}

func decodeDefaultDocument(raw []byte) (PolicyInput, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy PolicyInput
	if err := decoder.Decode(&policy); err != nil {
		return PolicyInput{}, errors.New("invalid firewall action tenant default document")
	}
	return policy, nil
}

func inheritedEdgePolicy(scopeID, siteID uuid.UUID, defaultRevision int64, policy PolicyInput) EdgePolicy {
	if policy.TrustedProxies == nil {
		policy.TrustedProxies = []string{}
	}
	if policy.TrustedCrawlers == nil {
		policy.TrustedCrawlers = []TrustedCrawler{}
	}
	return EdgePolicy{
		SchemaVersion: SchemaVersion, PolicyVersion: uint64(defaultRevision),
		TenantID: scopeID.String(), SiteID: siteID.String(), PolicyID: InheritedPolicyID(scopeID, siteID).String(),
		NormalAction: policy.NormalAction, EscalatedAction: policy.EscalatedAction,
		EngageThreshold: policy.EngageThreshold, RecoverThreshold: policy.RecoverThreshold, RecoveryWindows: policy.RecoveryWindows,
		BlockNetworks: policy.BlockNetworks, TrustedProxies: policy.TrustedProxies, TrustedCrawlers: policy.TrustedCrawlers,
		ReturnPage: policy.ReturnPage,
	}
}

// InheritedDocument is the node document of a site inheriting its tenant's
// default revision (stored document defaultDocument): the default's fields
// under the site's inherited policy ID, versioned by the default revision.
func InheritedDocument(scopeID, siteID uuid.UUID, defaultRevision int64, defaultDocument []byte) ([]byte, error) {
	if scopeID == uuid.Nil || siteID == uuid.Nil || defaultRevision < 1 {
		return nil, ErrInvalidInput
	}
	policy, err := decodeDefaultDocument(defaultDocument)
	if err != nil {
		return nil, err
	}
	return json.Marshal(inheritedEdgePolicy(scopeID, siteID, defaultRevision, policy))
}
