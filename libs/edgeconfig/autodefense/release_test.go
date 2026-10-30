package autodefense

import (
	"strconv"
	"testing"
)

// fix-adwhitelist2 §3: Site.Releases (单条解除) round trips canonically sorted; a site target, an invalid target or
// time, a duplicate and more than MaxReleasesPerSite are rejected.
func TestSiteReleasesContract(t *testing.T) {
	public, private := testKey(t)
	const ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
	with := func(releases ...Release) Snapshot {
		s := testSnapshot()
		s.Sites[0].Releases = releases
		return s
	}
	ok := with(Release{Kind: TargetJA4, Target: ja4, At: testNow}, Release{Kind: TargetIP, Target: "198.51.100.5", At: testNow},
		Release{Kind: TargetCIDR, Target: "203.0.113.0/24", At: testNow - 60})
	encoded, err := Sign(ok, testKeyID, private)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(encoded, testNode, trusted(public))
	if err != nil {
		t.Fatal(err)
	}
	var got []Release
	for _, site := range opened.Sites {
		if len(site.Releases) > 0 {
			got = site.Releases
		}
	}
	if len(got) != 3 || got[0].Kind != TargetCIDR || got[1].Kind != TargetIP || got[2].Kind != TargetJA4 {
		t.Fatalf("releases not canonical: %+v", got)
	}
	many := make([]Release, MaxReleasesPerSite+1)
	for i := range many {
		many[i] = Release{Kind: TargetIP, Target: "198.51." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250+1), At: testNow}
	}
	for name, snapshot := range map[string]Snapshot{
		"site target":    with(Release{Kind: TargetSite, Target: "*", At: testNow}),
		"invalid ip":     with(Release{Kind: TargetIP, Target: "198.51.100.300", At: testNow}),
		"wide cidr":      with(Release{Kind: TargetCIDR, Target: "10.0.0.0/8", At: testNow}),
		"zero time":      with(Release{Kind: TargetIP, Target: "198.51.100.5"}),
		"duplicate":      with(Release{Kind: TargetIP, Target: "198.51.100.5", At: testNow}, Release{Kind: TargetIP, Target: "198.51.100.5", At: testNow - 1}),
		"over the limit": with(many...),
	} {
		if _, err := Sign(snapshot, testKeyID, private); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

// fix-adwhitelist3 §1: a 解除并加白 JA4 rides Whitelist.JA4 permanently (until 0) or until its chosen expiry; the
// node's own 7 day entries keep a non-zero until.
func TestPermanentJA4WhitelistContract(t *testing.T) {
	public, private := testKey(t)
	s := testSnapshot()
	s.Sites[0].Whitelist.JA4 = []AllowJA4{{JA4: "t13d1516h2_8daaf6152771_02713d6af862"}}
	encoded, err := Sign(s, testKeyID, private)
	if err != nil {
		t.Fatalf("permanent JA4 allow refused: %v", err)
	}
	if _, err := Open(encoded, testNode, trusted(public)); err != nil {
		t.Fatal(err)
	}
	s.Sites[0].Whitelist.JA4 = []AllowJA4{{JA4: "t13d1516h2_8daaf6152771_02713d6af862", Until: -1}}
	if _, err := Sign(s, testKeyID, private); err == nil {
		t.Fatal("negative until signed")
	}
}

// fix-adwhitelist3 §2: a node answers each single release of a site it applied (release_acks: kind, target, the
// release's at and retry, applied or failed with a code); a retry of a release is its Retry (≤ MaxReleaseRetry).
func TestReleaseAcksReport(t *testing.T) {
	const ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
	ack := Report{Schema: ReportSchema, NodeID: testNode, SiteID: testSite, TenantID: testTenant, Seq: 9, At: testNow,
		Revision: 4, Kind: ReportReleaseAcks, ReleaseAcks: []ReleaseAck{
			{Kind: TargetIP, Target: "198.51.100.5", At: testNow - 5, Retry: 1, Applied: true},
			{Kind: TargetJA4, Target: ja4, At: testNow - 5, Error: ReleaseKernelUnbanFailed},
		}}
	encoded, err := EncodeReport(ack)
	if err != nil {
		t.Fatalf("release acks refused: %v", err)
	}
	if decoded, err := DecodeReport(encoded); err != nil || len(decoded.ReleaseAcks) != 2 {
		t.Fatalf("decode = %+v, %v", decoded, err)
	}
	for name, mutate := range map[string]func(*Report){
		"empty":            func(r *Report) { r.ReleaseAcks = []ReleaseAck{} },
		"no site":          func(r *Report) { r.SiteID, r.TenantID = "", "" },
		"site target":      func(r *Report) { r.ReleaseAcks[0] = ReleaseAck{Kind: TargetSite, Target: "*", At: testNow, Applied: true} },
		"applied and code": func(r *Report) { r.ReleaseAcks[0].Error = ReleaseGateWriteFailed },
		"failed no code":   func(r *Report) { r.ReleaseAcks[1].Error = "" },
		"unknown code":     func(r *Report) { r.ReleaseAcks[1].Error = "oops" },
		"retry too high":   func(r *Report) { r.ReleaseAcks[0].Retry = MaxReleaseRetry + 1 },
		"zero at":          func(r *Report) { r.ReleaseAcks[0].At = 0 },
		"on a state":       func(r *Report) { r.Kind, r.State = ReportState, &StateChange{From: StateNormal, To: StateAttack, Reason: "x"} },
		"acks on drift":    func(r *Report) { r.Kind, r.Drift = ReportDrift, &Drift{Metrics: []string{"ratio_404"}, Days: 1} },
	} {
		report := clone(t, ack)
		mutate(&report)
		if _, err := EncodeReport(report); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	public, private := testKey(t)
	s := testSnapshot()
	s.Sites[0].Releases = []Release{{Kind: TargetIP, Target: "198.51.100.5", At: testNow, Retry: 2}}
	signed, err := Sign(s, testKeyID, private)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(signed, testNode, trusted(public))
	if err != nil {
		t.Fatal(err)
	}
	retry := int64(-1)
	for _, site := range opened.Sites {
		if len(site.Releases) > 0 {
			retry = site.Releases[0].Retry
		}
	}
	if retry != 2 {
		t.Fatalf("release retry = %d, want 2", retry)
	}
	over := testSnapshot()
	over.Sites[0].Releases = []Release{{Kind: TargetIP, Target: "198.51.100.5", At: testNow, Retry: MaxReleaseRetry + 1}}
	if _, err := Sign(over, testKeyID, private); err == nil {
		t.Fatal("retry over the bound signed")
	}
}
