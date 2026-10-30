package systemconfig

import (
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestDDoSProtectionCategoryNormalizesAndRoundTrips(t *testing.T) {
	base := ProjectBootstrapConfiguration()
	if effective := EffectiveDDoSProtection(base.DDoSProtection); base.DDoSProtection != nil ||
		effective.MaxConnectionsPerIP != 0 || effective.NewConnectionsPerSecond != 0 || effective.EmptyConnection != nil ||
		!effective.TCPFlagFilter || !effective.DropInvalid ||
		!slices.Equal(effective.TCPFlagTypes, []string{"null", "xmas", "syn_fin", "syn_rst"}) {
		t.Fatalf("the never saved default = %+v", effective)
	}
	// Never saved: nodes get the default packet filters.
	if published := EdgeDDoSProtection(nil); published == nil || !published.DropInvalid || !published.FiltersTCPFlag("xmas") ||
		published.FiltersTCPFlag("fin") || published.FiltersTCPFlag("all") {
		t.Fatalf("default publication = %+v", published)
	}
	change := CategoryChange{DDoSProtection: &edgeconfig.DDoSProtection{
		MaxConnectionsPerIP: 300, NewConnectionsPerSecond: 100, RateBanSeconds: 600,
		AllowNetworks: []string{"2001:db8::5", "192.0.2.0/24"}, CCKernelBan: edgeconfig.CCKernelBanOff,
	}}
	if !validCategoryChange(CategoryDDoSProtection, change) || validCategoryChange(CategoryNginx, change) {
		t.Fatal("category change shape")
	}
	next := applyCategoryChange(base, CategoryDDoSProtection, change)
	normalized, snapshot, digest, err := CanonicalSnapshot(next)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(normalized.DDoSProtection.AllowNetworks, ","); got != "192.0.2.0/24,2001:db8::5/128" {
		t.Fatalf("allow networks = %s", got)
	}
	if !strings.Contains(string(snapshot), `"ddos_protection": {`) {
		t.Fatalf("snapshot lacks the category: %s", snapshot)
	}
	decoded, err := decodeCanonicalSnapshot(snapshot, digest)
	if err != nil || decoded.DDoSProtection == nil || decoded.DDoSProtection.MaxConnectionsPerIP != 300 {
		t.Fatalf("round trip = %+v, %v", decoded.DDoSProtection, err)
	}
	if categoryChangeExpands(base, normalized, CategoryDDoSProtection) {
		t.Fatal("kernel limits consume no entitlement")
	}
	if EdgeDDoSProtection(normalized.DDoSProtection) == nil {
		t.Fatal("an enabled category is published")
	}
	off := applyCategoryChange(base, CategoryDDoSProtection, CategoryChange{DDoSProtection: &edgeconfig.DDoSProtection{
		AllowNetworks: []string{}, CCKernelBan: edgeconfig.CCKernelBanOff}})
	// every limit off still publishes the block: it carries the node
	// networks (L2 trusts an L1 hop by them, fix-l2trust); nodes install no
	// table for it (ddos.NewSpec: !Enabled)
	if published := EdgeDDoSProtection(off.DDoSProtection); published == nil || published.Enabled() || published.Active() {
		t.Fatalf("every limit off publishes %+v", published)
	}
	// The flag types are canonicalized, kept while the switch is off, and the
	// switch needs a type.
	flags := applyCategoryChange(base, CategoryDDoSProtection, CategoryChange{DDoSProtection: &edgeconfig.DDoSProtection{
		AllowNetworks: []string{}, CCKernelBan: edgeconfig.CCKernelBanOff, TCPFlagFilter: true,
		TCPFlagTypes: []string{"all", "null", "fin", "null"}}})
	normalized, snapshot, _, err = CanonicalSnapshot(flags)
	if err != nil || !slices.Equal(normalized.DDoSProtection.TCPFlagTypes, []string{"null", "fin", "all"}) ||
		!strings.Contains(string(snapshot), `"tcp_flag_filter": true`) || strings.Contains(string(snapshot), `"drop_invalid"`) {
		t.Fatalf("flag types = %+v %v: %s", normalized.DDoSProtection, err, snapshot)
	}
	if published := EdgeDDoSProtection(normalized.DDoSProtection); published == nil || published.DropInvalid || !published.FiltersTCPFlag("fin") {
		t.Fatalf("flags only publication = %+v", published)
	}
	kept := applyCategoryChange(base, CategoryDDoSProtection, CategoryChange{DDoSProtection: &edgeconfig.DDoSProtection{
		AllowNetworks: []string{}, CCKernelBan: edgeconfig.CCKernelBanOff, TCPFlagTypes: []string{"xmas"}}})
	if normalized, _, _, err := CanonicalSnapshot(kept); err != nil || EdgeDDoSProtection(normalized.DDoSProtection).FiltersTCPFlag("xmas") {
		t.Fatalf("types with the switch off filter: %v", err)
	}
	for name, value := range map[string]edgeconfig.DDoSProtection{
		"switch without types": {AllowNetworks: []string{}, CCKernelBan: edgeconfig.CCKernelBanOff, TCPFlagFilter: true},
		"unknown type":         {AllowNetworks: []string{}, CCKernelBan: edgeconfig.CCKernelBanOff, TCPFlagFilter: true, TCPFlagTypes: []string{"ack"}},
	} {
		if _, _, _, err := CanonicalSnapshot(applyCategoryChange(base, CategoryDDoSProtection, CategoryChange{DDoSProtection: &value})); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	bad := applyCategoryChange(base, CategoryDDoSProtection, CategoryChange{DDoSProtection: &edgeconfig.DDoSProtection{
		RateBanSeconds: 10, AllowNetworks: []string{}, CCKernelBan: edgeconfig.CCKernelBanOff}})
	if _, _, _, err := CanonicalSnapshot(bad); err == nil {
		t.Fatal("a ban without a rate is accepted")
	}
}
