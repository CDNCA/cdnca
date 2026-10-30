package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// sec-rebind: a detach candidate renders the site without its binding of
// the kind; other kinds stay.
func TestReplaceSecurityBindingDetach(t *testing.T) {
	siteID := uuid.New()
	waf := securityBindingFact{siteID: siteID, bindingID: uuid.New(), policy: securitypolicy.Policy{ID: uuid.New(), Kind: securitypolicy.KindWAF}}
	cc := securityBindingFact{siteID: siteID, bindingID: uuid.New(), policy: securitypolicy.Policy{ID: uuid.New(), Kind: securitypolicy.KindCC}}
	bindings := map[uuid.UUID][]securityBindingFact{siteID: {waf, cc}}
	replaceSecurityBinding(bindings, securityBindingFact{siteID: siteID, policy: cc.policy, detach: true})
	if got := bindings[siteID]; len(got) != 1 || got[0].policy.Kind != securitypolicy.KindWAF {
		t.Fatalf("after detaching cc = %+v", got)
	}
	replaceSecurityBinding(bindings, securityBindingFact{siteID: siteID, policy: waf.policy, detach: true})
	if _, found := bindings[siteID]; found {
		t.Fatalf("after detaching every kind the site keeps bindings: %+v", bindings[siteID])
	}
	rebound := securityBindingFact{siteID: siteID, policy: securitypolicy.Policy{ID: uuid.New(), Kind: securitypolicy.KindCC}}
	replaceSecurityBinding(bindings, rebound)
	if got := bindings[siteID]; len(got) != 1 || got[0].policy.ID != rebound.policy.ID {
		t.Fatalf("after binding again = %+v", got)
	}
}
