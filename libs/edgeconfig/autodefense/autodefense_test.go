package autodefense

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	testNode   = "11111111-1111-4111-8111-111111111111"
	testTenant = "22222222-2222-4222-8222-222222222222"
	testSite   = "33333333-3333-4333-8333-333333333333"
	testSite2  = "44444444-4444-4444-8444-444444444444"
	testJA4    = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	testKeyID  = "edge-publish-1"
	testNow    = int64(1_800_000_000)
)

func ptr(value int64) *int64 { return &value }

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	return private.Public().(ed25519.PublicKey), private
}

func trusted(public ed25519.PublicKey) TrustedKeyFunc {
	return func(keyID string) (ed25519.PublicKey, bool) { return public, keyID == testKeyID }
}

func testBaseline(features []string) Baseline {
	bands := make([]Band, 0, len(features))
	for _, feature := range features {
		bands = append(bands, Band{Feature: feature, P50: 1000, MAD: 100, P99: 3000, Samples: 360})
	}
	return Baseline{Version: 7, GeneratedAt: testNow - 60, Maturity: MaturityWeek, CanBan: true, SharePermille: 500,
		Slots: []Slot{{Slot: 49, Bands: bands, Distributions: []Distribution{{Feature: "ja4", Values: []Share{
			{Value: testJA4, Permille: 600}, {Value: "other", Permille: 100}}}}}, {Slot: 50, Bands: bands}}}
}

func l4Baseline() Baseline {
	baseline := testBaseline([]string{"new_conn_rate", "syn_rate"})
	baseline.Slots[0].Distributions = []Distribution{{Feature: "packet_length", Values: []Share{{Value: "0-63", Permille: 900}}}}
	return baseline
}

func testSiteState(siteID string) Site {
	conditions := []Condition{{Dim: DimPathTemplate, Value: "/api/search"}, {Dim: DimJA4, Value: testJA4}}
	return Site{
		SiteID: siteID, TenantID: testTenant, Mode: SiteProtect, Sensitivity: SensitivityMedium,
		MaxLevel:  Item{Field: "site.max_level", State: ItemAuto, Manual: int64(LevelBan), Auto: ptr(int64(LevelXDP)), Min: 0, Max: int64(LevelXDP)},
		CrossSite: true, Circuit: Circuit{State: CircuitClosed}, Baseline: testBaseline([]string{"request_rate", "unique_ip"}),
		Whitelist: Whitelist{Networks: []AllowNetwork{{CIDR: "203.0.113.0/24", Source: "user"}},
			JA4: []AllowJA4{{JA4: testJA4, Until: testNow + 7*86400}}},
		Login: []Endpoint{{Method: "POST", PathTemplate: "/login", Source: "auto"}},
		Modules: []Module{
			{Name: ModuleCC, Mode: ModuleAuto, Items: []Item{
				{Field: "cc.challenge", State: ItemManual, Manual: 1, Min: 0, Max: 3, LockedBy: "user:alice", LockedAt: testNow - 3600},
				{Field: "cc.per_ip_requests", State: ItemAuto, Manual: 100, Auto: ptr(40), Min: 10, Max: 100,
					ResumedBy: "user:alice", ResumedAt: testNow - 600},
			}},
			{Name: ModuleWAF, Mode: ModuleSuggest, Items: []Item{
				{Field: "waf.group:sqli", State: ItemAuto, Manual: 0, Auto: ptr(1), Min: 0, Max: 1},
				{Field: "waf.tier", State: ItemAuto, Manual: 1, Auto: ptr(3), Min: 1, Max: 2},
			}},
		},
		Signatures: []Signature{{ID: SignatureID(conditions), Conditions: conditions, Stage: StageChallenge,
			CoverPermille: 710, FPRPPM: 200, LiftMilli: 3_550_000, AttackSamples: 4096, NormalSamples: 10000,
			Origin: "node", OriginNodeID: testNode, GeneratedAt: testNow - 30, Reason: "ja4 ∧ path=/api/search: 攻击覆盖 71%，正常命中 0.02%"}},
		Mitigations: []Mitigation{
			{Kind: TargetIP, Target: "198.51.100.7", Level: LevelKernel, Scope: ScopeSite, Since: testNow - 10, Until: testNow + 590,
				Offences: 1, Score: 90, Reason: "rate_outlier(312rps>p99 41rps); rhythm(cv=0.03)"},
			{Kind: TargetCIDR, Target: "2001:db8:1::/48", Level: LevelXDP, Scope: ScopeSite, Since: testNow - 10, Until: testNow + 1200,
				Offences: 2, Score: 100, Reason: "l4 syn flood"},
			{Kind: TargetJA4, Target: testJA4, Level: LevelRateLimit, RateMilli: 2500, Scope: ScopeTenant, Since: testNow, Until: testNow + 600,
				Offences: 1, Score: 60, Reason: "tenant federation"},
			{Kind: TargetSite, Target: "*", Level: LevelChallenge, Scope: ScopeSite, Since: testNow, Until: testNow + 120,
				Offences: 1, Score: 0, Reason: "protect_origin"},
		},
	}
}

func testSnapshot() Snapshot {
	return Snapshot{
		Schema: Schema, NodeID: testNode, Revision: 3, Part: 1, Parts: 1, IssuedAt: testNow, AutoMitigation: true,
		PlatformAllow: []string{"10.0.0.0/8", "192.0.2.0/24"},
		PortGroups: []PortGroup{{ID: "tcp-443", Protocol: "tcp", Ports: []PortRange{{From: 443, To: 443}, {From: 8443, To: 8450}},
			Baseline: l4Baseline(),
			Module: Module{Name: ModuleL4, Mode: ModuleAuto, Items: []Item{
				{Field: "l4.max_conns_per_ip", State: ItemAuto, Manual: 200, Auto: ptr(50), Min: 4, Max: 200},
				{Field: "l4.syn_tier", State: ItemManual, Manual: 1, Min: 0, Max: 3, LockedBy: "user:bob", LockedAt: testNow - 5},
			}}}},
		Prior: &Prior{Version: 1, Classes: []PriorClass{
			{Class: "small", MaxRequestMilli: 10_000, Bands: []PriorBand{{Metric: "ratio_4xx", P50: 20, MAD: 10}, {Metric: "request_rate", P50: 2_000, MAD: 1_000}}},
			{Class: "large", Bands: []PriorBand{{Metric: "request_rate", P50: 50_000, MAD: 20_000}}}}},
		Sites:     []Site{testSiteState(testSite2), testSiteState(testSite)},
		Algorithm: Algorithm, KeyID: testKeyID,
	}
}

func TestSignOpenRoundTrip(t *testing.T) {
	public, private := testKey(t)
	encoded, err := Sign(testSnapshot(), testKeyID, private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	opened, err := Open(encoded, testNode, trusted(public))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if opened.Sites[0].SiteID != testSite || opened.Sites[1].SiteID != testSite2 {
		t.Fatalf("sites not canonical: %s %s", opened.Sites[0].SiteID, opened.Sites[1].SiteID)
	}
	reencoded, err := json.Marshal(opened)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		t.Fatalf("round trip differs: %v", err)
	}
	node, revision, err := Route(encoded)
	if err != nil || node != testNode || revision != 3 {
		t.Fatalf("route = %q %d %v", node, revision, err)
	}
	if len(Digest(encoded)) != 32 {
		t.Fatal("digest size")
	}
	// The signature covers Domain + the body without signature.
	payload, err := SigningPayload(opened)
	if err != nil || !bytes.HasPrefix(payload, []byte("cdnca.autodefense/v1\n")) {
		t.Fatalf("payload: %v", err)
	}
	signature, _ := hex.DecodeString(opened.Signature)
	if !ed25519.Verify(public, payload, signature) {
		t.Fatal("signature does not cover the payload")
	}
}

func TestEmptySnapshotStopsDefense(t *testing.T) {
	public, private := testKey(t)
	empty := Snapshot{Schema: Schema, NodeID: testNode, Revision: 9, Part: 1, Parts: 1, IssuedAt: testNow}
	encoded, err := Sign(empty, testKeyID, private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	opened, err := Open(encoded, testNode, trusted(public))
	if err != nil || len(opened.Sites) != 0 || opened.AutoMitigation {
		t.Fatalf("open empty: %+v %v", opened, err)
	}
}

// Node autonomy: the control plane omits baselines (zero value); a partial
// baseline is still refused.
func TestOmittedBaseline(t *testing.T) {
	public, private := testKey(t)
	snapshot := testSnapshot()
	for index := range snapshot.Sites {
		snapshot.Sites[index].Baseline = Baseline{}
		snapshot.Sites[index].Mitigations = nil
	}
	for index := range snapshot.PortGroups {
		snapshot.PortGroups[index].Baseline = Baseline{}
	}
	encoded, err := Sign(snapshot, testKeyID, private)
	if err != nil {
		t.Fatalf("sign omitted baselines: %v", err)
	}
	opened, err := Open(encoded, testNode, trusted(public))
	if err != nil || !opened.Sites[0].Baseline.Omitted() || opened.Sites[0].Baseline.CanBan {
		t.Fatalf("open omitted baselines: %v", err)
	}
	partial := snapshot
	partial.Sites = append([]Site(nil), snapshot.Sites...)
	partial.Sites[0].Baseline = Baseline{Version: 1}
	if err := partial.Validate(); err == nil {
		t.Fatal("partial baseline accepted")
	}
	ban := snapshot
	ban.Sites = append([]Site(nil), snapshot.Sites...)
	ban.Sites[0].Mitigations = []Mitigation{{Kind: TargetIP, Target: "198.51.100.7", Level: LevelBan, Scope: ScopeSite,
		Since: testNow, Until: testNow + 600, Offences: 1, Score: 90, Reason: "r"}}
	if err := ban.Validate(); err == nil {
		t.Fatal("L3 mitigation accepted without a baseline")
	}
}

func TestOpenRejects(t *testing.T) {
	public, private := testKey(t)
	encoded, err := Sign(testSnapshot(), testKeyID, private)
	if err != nil {
		t.Fatal(err)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	foreign, _ := Sign(testSnapshot(), testKeyID, other)
	cases := map[string]struct {
		encoded []byte
		node    string
		want    error
	}{
		"wrong key":       {foreign, testNode, ErrUntrusted},
		"wrong node":      {encoded, testSite, ErrInvalid},
		"tampered":        {bytes.Replace(encoded, []byte(`"revision":3`), []byte(`"revision":4`), 1), testNode, ErrUntrusted},
		"unknown field":   {bytes.Replace(encoded, []byte(`{"schema"`), []byte(`{"x":1,"schema"`), 1), testNode, ErrInvalid},
		"trailing data":   {append(append([]byte(nil), encoded...), []byte(" {}")...), testNode, ErrInvalid},
		"not canonical":   {bytes.Replace(encoded, []byte(`"schema":`), []byte(`"schema" :`), 1), testNode, ErrInvalid},
		"empty":           {nil, testNode, ErrInvalid},
		"unsigned":        {bytes.Replace(encoded, []byte(`,"signature":"`), []byte(`,"signaturX":"`), 1), testNode, ErrInvalid},
		"upper hex":       {upperSignature(encoded), testNode, ErrInvalid},
		"unknown key id":  {bytes.Replace(encoded, []byte(testKeyID), []byte("edge-publish-2"), 1), testNode, ErrUntrusted},
		"oversized input": {bytes.Repeat([]byte(" "), MaxPartBytes+1), testNode, ErrInvalid},
	}
	for name, test := range cases {
		if _, err := Open(test.encoded, test.node, trusted(public)); !errors.Is(err, test.want) {
			t.Errorf("%s: err = %v, want %v", name, err, test.want)
		}
	}
	if _, err := Open(encoded, testNode, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("nil trust: %v", err)
	}
}

func upperSignature(encoded []byte) []byte {
	index := bytes.Index(encoded, []byte(`"signature":"`)) + len(`"signature":"`)
	out := append([]byte(nil), encoded...)
	copy(out[index:index+128], bytes.ToUpper(out[index:index+128]))
	return out
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Snapshot){
		"schema":                   func(s *Snapshot) { s.Schema = "cdnca.autodefense/v2" },
		"node":                     func(s *Snapshot) { s.NodeID = "node-1" },
		"revision zero":            func(s *Snapshot) { s.Revision = 0 },
		"part beyond parts":        func(s *Snapshot) { s.Part, s.Parts = 2, 1 },
		"parts over max":           func(s *Snapshot) { s.Parts = MaxParts + 1 },
		"algorithm":                func(s *Snapshot) { s.Algorithm = "rsa" },
		"node lists on part 2":     func(s *Snapshot) { s.Part, s.Parts = 2, 2 },
		"platform allow not canon": func(s *Snapshot) { s.PlatformAllow = []string{"10.1.2.3/8"} },
		"platform allow order":     func(s *Snapshot) { s.PlatformAllow = []string{"192.0.2.0/24", "10.0.0.0/8"} },
		"duplicate site":           func(s *Snapshot) { s.Sites[1] = s.Sites[0] },
		"site order":               func(s *Snapshot) { s.Sites[0], s.Sites[1] = s.Sites[1], s.Sites[0] },
		"mode":                     func(s *Snapshot) { s.Sites[0].Mode = "off" },
		"sensitivity":              func(s *Snapshot) { s.Sites[0].Sensitivity = "max" },
		"observe mitigates":        func(s *Snapshot) { s.Sites[0].Mode = SiteObserve },
		"unlicensed mitigates":     func(s *Snapshot) { s.AutoMitigation = false },
		"circuit open no reason":   func(s *Snapshot) { s.Sites[0].Circuit = Circuit{State: CircuitOpen, Since: testNow} },
		"circuit closed reason":    func(s *Snapshot) { s.Sites[0].Circuit.Reason = CircuitReasonAgent },
		"prior can ban":            func(s *Snapshot) { s.Sites[0].Baseline.Maturity = MaturityPrior },
		"slot range":               func(s *Snapshot) { s.Sites[0].Baseline.Slots[1].Slot = 168 },
		"slot order":               func(s *Snapshot) { s.Sites[0].Baseline.Slots[1].Slot = 49 },
		"three slots": func(s *Snapshot) {
			s.Sites[0].Baseline.Slots = append(s.Sites[0].Baseline.Slots, Slot{Slot: 51, Bands: s.Sites[0].Baseline.Slots[0].Bands})
		},
		"unknown feature":     func(s *Snapshot) { s.Sites[0].Baseline.Slots[0].Bands[0].Feature = "magic" },
		"l4 feature on site":  func(s *Snapshot) { s.Sites[0].Baseline.Slots[0].Bands[0].Feature = "syn_rate" },
		"p99 below p50":       func(s *Snapshot) { s.Sites[0].Baseline.Slots[0].Bands[0].P99 = 1 },
		"negative mad":        func(s *Snapshot) { s.Sites[0].Baseline.Slots[0].Bands[0].MAD = -1 },
		"share over 1000":     func(s *Snapshot) { s.Sites[0].Baseline.Slots[0].Distributions[0].Values[1].Permille = 901 },
		"share permille":      func(s *Snapshot) { s.Sites[0].Baseline.SharePermille = 1001 },
		"whitelist not canon": func(s *Snapshot) { s.Sites[0].Whitelist.Networks[0].CIDR = "203.0.113.9/24" },
		"whitelist source":    func(s *Snapshot) { s.Sites[0].Whitelist.Networks[0].Source = "anyone" },
		"ja4 allow bad":       func(s *Snapshot) { s.Sites[0].Whitelist.JA4[0].JA4 = "chrome" },
		"login method":        func(s *Snapshot) { s.Sites[0].Login[0].Method = "post" },
		"module unknown":      func(s *Snapshot) { s.Sites[0].Modules[0].Name = "geo" },
		"l4 module on site":   func(s *Snapshot) { s.Sites[0].Modules[0].Name = ModuleL4 },
		"module order":        func(s *Snapshot) { m := s.Sites[0].Modules; m[0], m[1] = m[1], m[0] },
		"module mode":         func(s *Snapshot) { s.Sites[0].Modules[0].Mode = "on" },
		"item other module":   func(s *Snapshot) { s.Sites[0].Modules[0].Items[0].Field = "waf.tier" },
		"item unknown":        func(s *Snapshot) { s.Sites[0].Modules[0].Items[0].Field = "cc.magic" },
		"item order":          func(s *Snapshot) { i := s.Sites[0].Modules[0].Items; i[0], i[1] = i[1], i[0] },
		"manual without lock": func(s *Snapshot) { s.Sites[0].Modules[0].Items[0].LockedBy = "" },
		"manual lock time":    func(s *Snapshot) { s.Sites[0].Modules[0].Items[0].LockedAt = 0 },
		"lock actor":          func(s *Snapshot) { s.Sites[0].Modules[0].Items[0].LockedBy = "alice" },
		"auto with lock": func(s *Snapshot) {
			s.Sites[0].Modules[0].Items[1].LockedBy, s.Sites[0].Modules[0].Items[1].LockedAt = "user:alice", testNow
		},
		"resumed half":        func(s *Snapshot) { s.Sites[0].Modules[0].Items[1].ResumedAt = 0 },
		"min over max":        func(s *Snapshot) { s.Sites[0].Modules[0].Items[1].Min = 101 },
		"auto beyond plat":    func(s *Snapshot) { s.Sites[0].Modules[0].Items[1].Auto = ptr(0) },
		"cc max over manual":  func(s *Snapshot) { s.Sites[0].Modules[0].Items[1].Max = 101 },
		"waf min below tier":  func(s *Snapshot) { s.Sites[0].Modules[1].Items[1].Min = 0 },
		"waf group no slug":   func(s *Snapshot) { s.Sites[0].Modules[1].Items[0].Field = "waf.group" },
		"waf group bad slug":  func(s *Snapshot) { s.Sites[0].Modules[1].Items[0].Field = "waf.group:SQLi" },
		"state":               func(s *Snapshot) { s.Sites[0].Modules[0].Items[1].State = "locked" },
		"items nil":           func(s *Snapshot) { s.Sites[0].Modules[0].Items = nil },
		"l4 conns below 4":    func(s *Snapshot) { s.PortGroups[0].Module.Items[0].Min = 3 },
		"port group protocol": func(s *Snapshot) { s.PortGroups[0].Protocol = "sctp" },
		"port overlap":        func(s *Snapshot) { s.PortGroups[0].Ports[1].From = 443 },
		"port zero":           func(s *Snapshot) { s.PortGroups[0].Ports[0].From = 0 },
		"port group module":   func(s *Snapshot) { s.PortGroups[0].Module.Name = ModuleCC },
		"site feature on l4":  func(s *Snapshot) { s.PortGroups[0].Baseline.Slots[0].Bands[0].Feature = "request_rate" },
		"max level field":     func(s *Snapshot) { s.Sites[0].MaxLevel.Field = "cc.challenge" },
		"prior version":       func(s *Snapshot) { s.Prior.Version = 0 },
		"prior no classes":    func(s *Snapshot) { s.Prior.Classes = nil },
		"prior metric":        func(s *Snapshot) { s.Prior.Classes[1].Bands[0].Metric = "per_ip_p99" },
		"prior unbounded mid": func(s *Snapshot) { s.Prior.Classes[0].MaxRequestMilli = 0 },
		"prior bounded last":  func(s *Snapshot) { s.Prior.Classes[1].MaxRequestMilli = 20_000 },
		"prior class dup":     func(s *Snapshot) { s.Prior.Classes[1].Class = "small" },
		"site prior class":    func(s *Snapshot) { s.Sites[0].PriorClass = "Not A Slug" },
		"prior band order":    func(s *Snapshot) { b := s.Prior.Classes[0].Bands; b[0], b[1] = b[1], b[0] },
		"prior negative":      func(s *Snapshot) { s.Prior.Classes[0].Bands[0].MAD = -1 },
		"prior on part 2":     func(s *Snapshot) { s.Part, s.Parts, s.PlatformAllow, s.PortGroups = 2, 2, nil, nil },
		"max level beyond":    func(s *Snapshot) { s.Sites[0].MaxLevel.Auto = ptr(6) },
		"signature id":        func(s *Snapshot) { s.Sites[0].Signatures[0].ID = "0000000000000000" },
		"signature too long": func(s *Snapshot) {
			sig := &s.Sites[0].Signatures[0]
			sig.Conditions = []Condition{{DimASN, "1"}, {DimCountry, "CN"}, {DimJA4, testJA4}, {DimMethod, "GET"}}
			sig.ID = SignatureID(sig.Conditions)
		},
		"signature dup dim": func(s *Snapshot) {
			sig := &s.Sites[0].Signatures[0]
			sig.Conditions = []Condition{{DimASN, "1"}, {DimASN, "2"}}
			sig.ID = SignatureID(sig.Conditions)
		},
		"signature bad value": func(s *Snapshot) {
			sig := &s.Sites[0].Signatures[0]
			sig.Conditions = []Condition{{DimCIDR, "198.51.100.0/25"}}
			sig.ID = SignatureID(sig.Conditions)
		},
		"signature stage":         func(s *Snapshot) { s.Sites[0].Signatures[0].Stage = "live" },
		"standby without resume":  func(s *Snapshot) { s.Sites[0].Signatures[0].Stage = StageStandby },
		"resume outside standby":  func(s *Snapshot) { s.Sites[0].Signatures[0].Resume = StageBlock },
		"signature origin":        func(s *Snapshot) { s.Sites[0].Signatures[0].OriginNodeID = "" },
		"signature reason":        func(s *Snapshot) { s.Sites[0].Signatures[0].Reason = "a\nb" },
		"cover over 1000":         func(s *Snapshot) { s.Sites[0].Signatures[0].CoverPermille = 1001 },
		"mitigation l0":           func(s *Snapshot) { s.Sites[0].Mitigations[0].Level = LevelObserve },
		"mitigation l6":           func(s *Snapshot) { s.Sites[0].Mitigations[0].Level = 6 },
		"mitigation over ceiling": func(s *Snapshot) { s.Sites[0].MaxLevel.Auto = ptr(int64(LevelBan)) },
		"locked ceiling": func(s *Snapshot) {
			s.Sites[0].MaxLevel = Item{Field: "site.max_level", State: ItemManual, Manual: int64(LevelBan), Auto: ptr(5), Max: 5,
				LockedBy: "user:alice", LockedAt: testNow}
		},
		"ban before can ban": func(s *Snapshot) {
			s.Sites[0].Baseline.CanBan = false
		},
		"mitigation ttl":     func(s *Snapshot) { s.Sites[0].Mitigations[0].Until = testNow + MaxMitigationSeconds },
		"mitigation until":   func(s *Snapshot) { s.Sites[0].Mitigations[0].Until = testNow - 10 },
		"rate without rate":  func(s *Snapshot) { s.Sites[0].Mitigations[2].RateMilli = 0 },
		"rate on ban":        func(s *Snapshot) { s.Sites[0].Mitigations[0].RateMilli = 5 },
		"tenant scope ban":   func(s *Snapshot) { s.Sites[0].Mitigations[0].Scope = ScopeTenant },
		"ip not canon":       func(s *Snapshot) { s.Sites[0].Mitigations[0].Target = "::ffff:198.51.100.7" },
		"cidr too wide v6":   func(s *Snapshot) { s.Sites[0].Mitigations[1].Target = "2001:db8::/32" },
		"ja4 kernel":         func(s *Snapshot) { s.Sites[0].Mitigations[2].Level, s.Sites[0].Mitigations[2].RateMilli = LevelBan, 0 },
		"site target ban":    func(s *Snapshot) { s.Sites[0].Mitigations[3].Level = LevelRateLimit },
		"mitigation order":   func(s *Snapshot) { m := s.Sites[0].Mitigations; m[0], m[1] = m[1], m[0] },
		"mitigation offence": func(s *Snapshot) { s.Sites[0].Mitigations[0].Offences = 0 },
		"mitigation reason":  func(s *Snapshot) { s.Sites[0].Mitigations[0].Reason = "" },
	}
	if err := sorted(testSnapshot()).Validate(); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	for name, mutate := range cases {
		snapshot := sorted(testSnapshot())
		mutate(&snapshot)
		if err := snapshot.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func sorted(snapshot Snapshot) Snapshot {
	snapshot.Canonical()
	return snapshot
}

func TestOverlayComposition(t *testing.T) {
	snapshot := sorted(testSnapshot())
	site := snapshot.Sites[0]
	cc := site.Modules[0]
	threshold, _ := cc.Item("cc.per_ip_requests")
	challenge, _ := cc.Item("cc.challenge")
	active := Active(snapshot, site, cc, testNow)
	if !active {
		t.Fatal("cc overlay should be active")
	}
	// Auto item: clamp(auto 40, 10, 100) = 40; locked item: the manual value.
	if got := threshold.Effective(active); got != 40 {
		t.Errorf("auto effective = %d", got)
	}
	if got := challenge.Effective(active); got != 1 {
		t.Errorf("locked effective = %d", got)
	}
	// Clamp both ways.
	threshold.Auto = ptr(3)
	if got := threshold.Effective(true); got != 10 {
		t.Errorf("clamp low = %d", got)
	}
	// Inactive overlay or no auto value: the manual value.
	if got := threshold.Effective(false); got != 100 {
		t.Errorf("inactive = %d", got)
	}
	threshold.Auto = nil
	if got := threshold.Effective(true); got != 100 {
		t.Errorf("no auto = %d", got)
	}
	// Suggest mode never applies but shows the clamped value.
	waf := site.Modules[1]
	if Active(snapshot, site, waf, testNow) {
		t.Error("suggest mode applied")
	}
	tier, _ := waf.Item("waf.tier")
	if value, ok := tier.Suggestion(); !ok || value != 2 {
		t.Errorf("suggestion = %d %v", value, ok)
	}
	if _, ok := challenge.Suggestion(); ok {
		t.Error("locked item suggested")
	}
	// Overlay off when unlicensed, circuit open, observe hold or not protecting.
	for name, mutate := range map[string]func(*Snapshot, *Site){
		"unlicensed": func(s *Snapshot, _ *Site) { s.AutoMitigation = false },
		"circuit":    func(_ *Snapshot, s *Site) { s.Circuit.State = CircuitOpen },
		"observe":    func(_ *Snapshot, s *Site) { s.ObserveUntil = testNow + 1 },
		"learning":   func(_ *Snapshot, s *Site) { s.Mode = SiteLearning },
	} {
		copySnapshot, copySite := snapshot, site
		mutate(&copySnapshot, &copySite)
		if Active(copySnapshot, copySite, cc, testNow) {
			t.Errorf("%s: overlay active", name)
		}
	}
	// No default ceiling (Q3): unlocked max level reaches XDP; locked holds the
	// manual level until resumed.
	if site.MaxLevelOf() != LevelXDP {
		t.Errorf("max level = %d", site.MaxLevelOf())
	}
	site.MaxLevel.State, site.MaxLevel.LockedBy, site.MaxLevel.LockedAt = ItemManual, "user:alice", testNow
	if site.MaxLevelOf() != LevelBan {
		t.Errorf("locked max level = %d", site.MaxLevelOf())
	}
	if NodeLevel(LevelXDP, false) != LevelKernel || NodeLevel(LevelXDP, true) != LevelXDP || NodeLevel(LevelBan, false) != LevelBan {
		t.Error("xdp placeholder")
	}
}

func TestFieldRegistry(t *testing.T) {
	specs := FieldSpecs()
	for index, spec := range specs {
		if index > 0 && specs[index-1].Field >= spec.Field {
			t.Fatalf("registry order/duplicate at %s", spec.Field)
		}
		if spec.PlatformMin > spec.DefaultMin || spec.DefaultMin > spec.DefaultMax || spec.DefaultMax > spec.PlatformMax {
			t.Errorf("%s: default range outside platform range", spec.Field)
		}
		if spec.Kind == FieldEnum && int64(len(spec.Enum)-1) != spec.PlatformMax {
			t.Errorf("%s: enum size", spec.Field)
		}
		if spec.Module != "" && !strings.HasPrefix(spec.Field, string(spec.Module)+".") {
			t.Errorf("%s: module prefix", spec.Field)
		}
		if spec.Section == "" {
			t.Errorf("%s: no ADR section", spec.Field)
		}
	}
	// ADR 0010 section 7A defaults that the contract freezes.
	frozen := map[string][2]int64{
		"site.max_level":                 {0, int64(LevelXDP)},
		"waf.tier":                       {1, 2},
		"l4.max_conns_per_ip":            {4, 1000000},
		"l4.new_conns_per_second":        {5, 1000000},
		"scan.not_found_threshold":       {10, 200},
		"scan.login_failures_per_minute": {5, 100000},
		"cc.ban_seconds":                 {600, 86400},
	}
	for field, want := range frozen {
		spec, ok := LookupField(field)
		if !ok || spec.DefaultMin != want[0] || spec.DefaultMax != want[1] {
			t.Errorf("%s default = %d-%d, want %v", field, spec.DefaultMin, spec.DefaultMax, want)
		}
	}
	if _, ok := LookupField("waf.group:crs-942"); !ok {
		t.Error("suffixed group field")
	}
	if len(LevelNames) != int(LevelXDP)+1 || WAFTierNames[0] != "log_only" || len(WAFTierNames) != 4 {
		t.Error("enum names")
	}
}

func TestJA4PatternMatchesEdgeconfig(t *testing.T) {
	if ja4Pattern.String() != edgeconfig.JA4Pattern.String() {
		t.Fatalf("ja4 pattern drifted from edgeconfig.JA4Pattern")
	}
}

func TestSignatureID(t *testing.T) {
	a := SignatureID([]Condition{{DimJA4, testJA4}, {DimPathTemplate, "/x"}})
	b := SignatureID([]Condition{{DimPathTemplate, "/x"}, {DimJA4, testJA4}})
	if a != b || len(a) != 16 {
		t.Fatalf("signature id not order independent: %s %s", a, b)
	}
}

func TestValidConditionDimensions(t *testing.T) {
	good := map[string]string{
		DimJA4: testJA4, DimUAHash: "0123456789abcdef", DimUAFamily: "chrome", DimPathTemplate: "/api/{n}/item",
		DimQueryNamesHash: "fedcba9876543210", DimHeaderOrderHash: "00112233445566ff", DimMissingHeader: "referer",
		DimHTTPVersion: "2", DimMethod: "POST", DimASN: "4134", DimCIDR: "198.51.100.0/24", DimCountry: "CN",
		DimIPTag: "idc", DimStatus: "404", DimBytesBucket: "12", DimIntervalCV: "lt0.1", DimUniquePathRatio: "lt0.05",
		DimStaticRatio: "none", DimChallengePassed: "0",
	}
	bad := map[string]string{
		DimJA4: "x", DimUAHash: "0123", DimPathTemplate: "api", DimASN: "0", DimCIDR: "2001:db8::/64", DimCountry: "cn",
		DimStatus: "600", DimBytesBucket: "41", DimIntervalCV: "0.1", DimMissingHeader: "host",
	}
	for _, dim := range Dimensions() {
		value, ok := good[dim]
		if !ok || !ValidCondition(dim, value) {
			t.Errorf("%s=%q rejected", dim, value)
		}
	}
	for dim, value := range bad {
		if ValidCondition(dim, value) {
			t.Errorf("%s=%q accepted", dim, value)
		}
	}
	if ValidCondition("host", "example.com") {
		t.Error("unknown dimension accepted")
	}
	if !ValidCondition(DimCIDR, "2001:db8:1::/48") || ValidCondition(DimASN, "01") {
		t.Error("cidr/asn canonical")
	}
}

func TestSplitAssemble(t *testing.T) {
	public, private := testKey(t)
	whole := testSnapshot()
	whole.Sites = nil
	for index := 0; index < 600; index++ {
		site := testSiteState(fmt.Sprintf("%08x-0000-4000-8000-000000000000", index))
		whole.Sites = append(whole.Sites, site)
	}
	parts, err := Split(whole, testKeyID)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(parts) < 2 {
		t.Fatalf("expected several parts, got %d", len(parts))
	}
	opened := make([]Snapshot, 0, len(parts))
	for index := len(parts) - 1; index >= 0; index-- { // any order
		encoded, err := Sign(parts[index], testKeyID, private)
		if err != nil {
			t.Fatalf("sign part %d: %v", index+1, err)
		}
		if len(encoded) > MaxPartBytes || len(encoded)+4<<10 > MaxCarrierBytes {
			t.Fatalf("part %d is %d bytes", index+1, len(encoded))
		}
		part, err := Open(encoded, testNode, trusted(public))
		if err != nil {
			t.Fatalf("open part %d: %v", index+1, err)
		}
		opened = append(opened, part)
	}
	assembled, err := Assemble(opened)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(assembled.Sites) != 600 || len(assembled.PortGroups) != 1 || len(assembled.PlatformAllow) != 2 ||
		assembled.Prior == nil || len(assembled.Prior.Classes) != 2 {
		t.Fatalf("assembled %d sites %d groups", len(assembled.Sites), len(assembled.PortGroups))
	}
	if _, err := Assemble(opened[1:]); !errors.Is(err, ErrIncomplete) {
		t.Errorf("missing part: %v", err)
	}
	duplicate := append([]Snapshot{opened[0]}, opened[:len(opened)-1]...)
	if _, err := Assemble(duplicate); !errors.Is(err, ErrInvalid) {
		t.Errorf("duplicate part: %v", err)
	}
	mixed := append([]Snapshot(nil), opened...)
	mixed[0].Revision++
	if _, err := Assemble(mixed); !errors.Is(err, ErrInvalid) {
		t.Errorf("mixed revision: %v", err)
	}
	if _, err := Assemble(nil); !errors.Is(err, ErrIncomplete) {
		t.Errorf("no parts: %v", err)
	}
}
