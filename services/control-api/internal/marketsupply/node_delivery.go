package marketsupply

import (
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// Node delivery in OpStatus (fix-mktsiteconf7 §1): after a commit the
// subscriber asks, now and then, whether the site took effect on this
// leaf's nodes. Evidence: the site's derived sync status (site_sync_status_503,
// its latest automatic publication), the leaf security policies and the
// origin auth delivery. No error text crosses to the subscriber.

// Node delivery states.
const (
	NodeDeliveryDelivering = "delivering" // on its way to the nodes
	NodeDeliveryEffective  = "effective"  // in effect on the nodes
	NodeDeliveryFailed     = "failed"     // part of it failed
)

// Node delivery reasons.
const (
	NodeReasonSiteSyncing          = "site_syncing"
	NodeReasonSiteSyncFailed       = "site_sync_failed"
	NodeReasonSecurityActivating   = "security_activating"
	NodeReasonSecurityFailed       = "security_failed"
	NodeReasonOriginAuthDelivering = "origin_auth_delivering"
	NodeReasonOriginAuthFailed     = "origin_auth_failed"
)

// NodeDelivery is OpStatus "nodes".
type NodeDelivery struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// nodeDelivery: a failure anywhere is the answer; else the first part still
// on its way; else in effect. auth is nil when the leaf has no delivery.
func nodeDelivery(syncStatus string, security []SecurityState, auth *edgepublish.OriginAuthDeliveryStatus) NodeDelivery {
	if syncStatus == site.SyncStatusFailed {
		return NodeDelivery{State: NodeDeliveryFailed, Reason: NodeReasonSiteSyncFailed}
	}
	for _, s := range security {
		if s.State == securityFailed {
			return NodeDelivery{State: NodeDeliveryFailed, Reason: NodeReasonSecurityFailed, Detail: s.Kind + ":" + s.Reason}
		}
	}
	if auth != nil && auth.State == edgepublish.OriginAuthDeliveryFailed {
		return NodeDelivery{State: NodeDeliveryFailed, Reason: NodeReasonOriginAuthFailed, Detail: auth.Reason}
	}
	if syncStatus != site.SyncStatusSynced {
		return NodeDelivery{State: NodeDeliveryDelivering, Reason: NodeReasonSiteSyncing}
	}
	for _, s := range security {
		if s.State != securityActive {
			return NodeDelivery{State: NodeDeliveryDelivering, Reason: NodeReasonSecurityActivating, Detail: s.Kind}
		}
	}
	if auth != nil && auth.State != edgepublish.OriginAuthDeliveryNone && auth.State != edgepublish.OriginAuthDeliveryDelivered {
		return NodeDelivery{State: NodeDeliveryDelivering, Reason: NodeReasonOriginAuthDelivering, Detail: auth.Reason}
	}
	return NodeDelivery{State: NodeDeliveryEffective}
}
