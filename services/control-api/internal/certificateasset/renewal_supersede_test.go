package certificateasset

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fix-dnscert4：续签下发途中用户改绑/发布同一站点。每条用户绑定写入（激活迁移、绑定、解绑）都必须
// ①在写绑定事实前撤销覆盖该站点的在途续签下发（续签让位于用户），②从 nextBindingRevisionTx 取号
// （跳过续签已占的号），不能再用“最新事实+1”，否则节点上已收到续签版本的会与用户发布同号冲突。
func TestUserBindingMutationsSupersedeRenewalAndSkipReservedRevision(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve certificate asset test path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "store.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, mutation := range []struct{ name, start, end string }{
		{"activate", "func (s *Store) activateTx", "func (s *Store) advanceActivatedACMEOrder"},
		{"bind", "func (s *Store) bindTx", "func (s *Store) unbind"},
		{"unbind", "func (s *Store) unbind", "func (s *Store) delete"},
	} {
		body := certificateAssetSourceSlice39(t, text, mutation.start, mutation.end)
		insert := strings.Index(body, "INSERT INTO certificate_site_binding_facts")
		supersede := strings.Index(body, "s.supersedeRenewalDeliveriesTx(")
		next := strings.Index(body, "nextBindingRevisionTx(")
		if insert < 0 || supersede < 0 || supersede > insert {
			t.Errorf("%s: in-flight renewal delivery is not superseded before the binding fact", mutation.name)
		}
		if next < 0 || next > insert {
			t.Errorf("%s: binding revision is not taken past the renewal reservation", mutation.name)
		}
		for _, contiguous := range []string{"binding.Revision + 1", "currentRevision + 1", "result.Revision++"} {
			if strings.Contains(body, contiguous) {
				t.Errorf("%s still numbers the binding as latest+1 (%q)", mutation.name, contiguous)
			}
		}
	}
}

// 续签切换只认它自己占的号：站点的预留号仍是本轮的、且没有更新的绑定事实；前一版本取最新事实，
// 不再假设 R-1 有事实（跳过的号没有事实）。
func TestRenewalActivationChecksItsReservation(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve certificate asset test path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "renewal_activation.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := certificateAssetSourceSlice39(t, string(source), "func (s *Store) ActivateRenewalTx", "func settleRenewalPublicationIntentTx")
	if !strings.Contains(body, "requireRenewalReservationsTx(") {
		t.Error("renewal switch does not check the reserved binding revisions")
	}
	if strings.Contains(body, "sequence=$3`, request.TenantScopeID, site.SiteID,\n\t\t\tsite.BindingRevision-1") {
		t.Error("renewal switch still reads the previous version at R-1")
	}
}

func TestSameRenewalSiteSetComparesSitesAndDefaultOnly(t *testing.T) {
	a, b := RenewalSiteRevision{SiteID: [16]byte{1}, BindingRevision: 3}, RenewalSiteRevision{SiteID: [16]byte{2}, Default: true}
	if !sameRenewalSiteSet([]RenewalSiteRevision{a, b}, []RenewalSiteRevision{{SiteID: a.SiteID, BindingRevision: 7},
		{SiteID: b.SiteID, Default: true, BindingRevision: 9}}) {
		t.Fatal("same sites with other revisions refused (revisions are checked against the reservations)")
	}
	if sameRenewalSiteSet([]RenewalSiteRevision{a, b}, []RenewalSiteRevision{a}) ||
		sameRenewalSiteSet([]RenewalSiteRevision{a, b}, []RenewalSiteRevision{a, {SiteID: b.SiteID}}) {
		t.Fatal("changed site set or default flag accepted")
	}
}
