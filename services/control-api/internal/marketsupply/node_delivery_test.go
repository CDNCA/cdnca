package marketsupply

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// fix-mktsiteconf7 §1: OpStatus says whether the committed site took effect
// on the leaf's nodes — from the site's derived sync status, its leaf
// security policies and its origin auth delivery.
func TestNodeDeliveryFromTheSiteSecurityAndOriginAuth(t *testing.T) {
	delivered := &edgepublish.OriginAuthDeliveryStatus{State: edgepublish.OriginAuthDeliveryDelivered}
	for name, tc := range map[string]struct {
		sync     string
		security []SecurityState
		auth     *edgepublish.OriginAuthDeliveryStatus
		want     NodeDelivery
	}{
		"synced, nothing else": {sync: site.SyncStatusSynced, want: NodeDelivery{State: NodeDeliveryEffective}},
		"synced with everything active": {sync: site.SyncStatusSynced, auth: delivered,
			security: []SecurityState{{Kind: "waf", State: securityActive}},
			want:     NodeDelivery{State: NodeDeliveryEffective}},
		"site still syncing": {sync: site.SyncStatusPending,
			want: NodeDelivery{State: NodeDeliveryDelivering, Reason: NodeReasonSiteSyncing}},
		"site sync failed": {sync: site.SyncStatusFailed,
			want: NodeDelivery{State: NodeDeliveryFailed, Reason: NodeReasonSiteSyncFailed}},
		"a policy still activating": {sync: site.SyncStatusSynced,
			security: []SecurityState{{Kind: "cc", State: securityActive}, {Kind: "waf", State: securityWaitingNodes}},
			want:     NodeDelivery{State: NodeDeliveryDelivering, Reason: NodeReasonSecurityActivating, Detail: "waf"}},
		"a policy failed": {sync: site.SyncStatusSynced,
			security: []SecurityState{{Kind: "acl", State: securityFailed, Reason: "candidate_rejected"}},
			want:     NodeDelivery{State: NodeDeliveryFailed, Reason: NodeReasonSecurityFailed, Detail: "acl:candidate_rejected"}},
		"origin auth on its way": {sync: site.SyncStatusSynced,
			auth: &edgepublish.OriginAuthDeliveryStatus{State: edgepublish.OriginAuthDeliveryRetrying, Reason: edgepublish.OriginAuthDeliveryNodeRejected},
			want: NodeDelivery{State: NodeDeliveryDelivering, Reason: NodeReasonOriginAuthDelivering, Detail: edgepublish.OriginAuthDeliveryNodeRejected}},
		"origin auth failed": {sync: site.SyncStatusSynced,
			auth: &edgepublish.OriginAuthDeliveryStatus{State: edgepublish.OriginAuthDeliveryFailed, Reason: edgepublish.OriginAuthDeliveryCredential},
			want: NodeDelivery{State: NodeDeliveryFailed, Reason: NodeReasonOriginAuthFailed, Detail: edgepublish.OriginAuthDeliveryCredential}},
		// A failure anywhere wins over what is still on its way.
		"failure first": {sync: site.SyncStatusPending,
			auth: &edgepublish.OriginAuthDeliveryStatus{State: edgepublish.OriginAuthDeliveryFailed, Reason: edgepublish.OriginAuthDeliveryCredential},
			want: NodeDelivery{State: NodeDeliveryFailed, Reason: NodeReasonOriginAuthFailed, Detail: edgepublish.OriginAuthDeliveryCredential}},
		"origin auth without rules": {sync: site.SyncStatusSynced,
			auth: &edgepublish.OriginAuthDeliveryStatus{State: edgepublish.OriginAuthDeliveryNone},
			want: NodeDelivery{State: NodeDeliveryEffective}},
	} {
		if got := nodeDelivery(tc.sync, tc.security, tc.auth); got != tc.want {
			t.Errorf("%s: nodeDelivery = %+v, want %+v", name, got, tc.want)
		}
	}
}
