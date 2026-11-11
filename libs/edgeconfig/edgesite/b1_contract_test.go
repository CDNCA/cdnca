package edgesite

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// A site that uses none of the new features (server_timing, string
// sets, WAF v6 conditions) encodes byte for byte as before them: digests of
// fullSite / minimalSite encoded before these features.
func TestEncodingUnchangedWithoutNewFeatures(t *testing.T) {
	for name, want := range map[string]struct {
		size   int
		digest string
	}{
		"full":    {5347, "93243010a566de480b7763a196f52567c8695018104fb85280114e604e53b533"},
		"minimal": {852, "c8ca9f9529dce0bbe7df0833b1398d79416dc16ea22264f9e5d1147b8f582687"},
	} {
		site := minimalSite()
		if name == "full" {
			site = fullSite(t)
		}
		raw, err := Encode(site)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if len(raw) != want.size || hex.EncodeToString(sum[:]) != want.digest {
			t.Fatalf("%s: %d bytes %x, want %d bytes %s", name, len(raw), sum, want.size, want.digest)
		}
		for _, field := range []string{"server_timing", "string_sets", "browser", "device", `"time"`} {
			if strings.Contains(string(raw), field) {
				t.Fatalf("%s carries %s", name, field)
			}
		}
	}
}

// server_timing follows cache_status_header and round-trips.
func TestServerTimingEncoding(t *testing.T) {
	site := minimalSite()
	site.ServerTiming = true
	raw, err := Encode(site)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"range":false,"server_timing":true,"origin":`) {
		t.Fatalf("encoding %s", raw)
	}
	site.CacheStatusHeader = true
	raw, _ = Encode(site)
	if !strings.Contains(string(raw), `"cache_status_header":true,"server_timing":true,"origin":`) {
		t.Fatalf("encoding %s", raw)
	}
	decoded, err := Decode(raw)
	if err != nil || !decoded.ServerTiming || !decoded.CacheStatusHeader {
		t.Fatalf("decode %+v %v", decoded.ServerTiming, err)
	}
}

const (
	testSetA = "0190a000-0000-7000-8000-0000000000a1"
	testSetB = "0190a000-0000-7000-8000-0000000000b2"
)

func stringSetSite(refs ...edgeconfig.WAFStringSetRef) Site {
	site := minimalSite()
	site.Security.Rules.Policies = []RulePolicy{{
		Kind: edgeconfig.SecurityWAF, PolicyID: testUUID, PolicyVersion: 2, BindingRevision: 1, RuntimeSHA256: digestA,
		Enabled: true, DefaultAction: edgeconfig.WAFAllow,
		Rules: []edgeconfig.WAFRule{{RuleID: testUUID2, Match: edgeconfig.WAFMatch{StringSets: refs},
			Action: edgeconfig.WAFBlock, Control: edgeconfig.WAFStop}},
	}}
	return site
}

func TestStringSetsRoundTrip(t *testing.T) {
	site := stringSetSite(
		edgeconfig.WAFStringSetRef{SetID: testSetA, Revision: 2, Target: edgeconfig.StringSetTargetUserAgent},
		edgeconfig.WAFStringSetRef{SetID: testSetB, Revision: 1, Target: edgeconfig.StringSetTargetHeader, Key: "x-app", Negate: true},
	)
	site.Security.StringSets = []StringSet{
		{ID: testSetA, Revision: 2, Mode: edgeconfig.StringSetContains, CaseSensitive: false, Members: []string{"bot", "spider"}},
		{ID: testSetB, Revision: 1, Mode: edgeconfig.StringSetExact, CaseSensitive: true, Members: []string{"App"}},
	}
	raw, err := Encode(site)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"string_sets":[{"id":"`+testSetA+`","revision":2,"mode":"contains","case_sensitive":false,"members":["bot","spider"]}`) {
		t.Fatalf("encoding %s", raw)
	}
	decoded, err := Decode(raw)
	if err != nil || len(decoded.Security.StringSets) != 2 {
		t.Fatalf("decode %v", err)
	}
}

func TestStringSetsRejects(t *testing.T) {
	ref := edgeconfig.WAFStringSetRef{SetID: testSetA, Revision: 2, Target: edgeconfig.StringSetTargetPath}
	set := StringSet{ID: testSetA, Revision: 2, Mode: edgeconfig.StringSetPrefix, CaseSensitive: true, Members: []string{"/admin"}}
	other := StringSet{ID: testSetB, Revision: 1, Mode: edgeconfig.StringSetExact, CaseSensitive: true, Members: []string{"x"}}
	ja4 := edgeconfig.WAFStringSetRef{SetID: testSetA, Revision: 2, Target: edgeconfig.StringSetTargetJA4}
	for name, test := range map[string]struct {
		refs []edgeconfig.WAFStringSetRef
		sets []StringSet
	}{
		"missing set":        {[]edgeconfig.WAFStringSetRef{ref}, nil},
		"revision mismatch":  {[]edgeconfig.WAFStringSetRef{ref}, []StringSet{{ID: testSetA, Revision: 3, Mode: set.Mode, CaseSensitive: true, Members: set.Members}}},
		"unreferenced set":   {[]edgeconfig.WAFStringSetRef{ref}, []StringSet{set, other}},
		"set without rules":  {nil, []StringSet{other}},
		"unsorted":           {[]edgeconfig.WAFStringSetRef{ref, {SetID: testSetB, Revision: 1, Target: edgeconfig.StringSetTargetHost}}, []StringSet{other, set}},
		"duplicate":          {[]edgeconfig.WAFStringSetRef{ref}, []StringSet{set, set}},
		"not canonical":      {[]edgeconfig.WAFStringSetRef{ref}, []StringSet{{ID: testSetA, Revision: 2, Mode: set.Mode, CaseSensitive: true, Members: []string{"/b", "/a"}}}},
		"ja4 on prefix set":  {[]edgeconfig.WAFStringSetRef{ja4}, []StringSet{set}},
		"two revisions used": {[]edgeconfig.WAFStringSetRef{ref, {SetID: testSetA, Revision: 3, Target: edgeconfig.StringSetTargetHost}}, []StringSet{set}},
	} {
		var site Site
		if test.refs == nil {
			site = minimalSite()
		} else {
			site = stringSetSite(test.refs...)
		}
		site.Security.StringSets = test.sets
		if err := Validate(site); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestStringSetsSiteBounds(t *testing.T) {
	// 17 distinct sets: one over MaxSiteStringSets.
	refs := []edgeconfig.WAFStringSetRef{}
	sets := []StringSet{}
	for index := 0; index <= edgeconfig.MaxSiteStringSets; index++ {
		id := "0190a000-0000-7000-8000-0000000001" + strconv.FormatInt(int64(10+index), 10)
		refs = append(refs, edgeconfig.WAFStringSetRef{SetID: id, Revision: 1, Target: edgeconfig.StringSetTargetPath})
		sets = append(sets, StringSet{ID: id, Revision: 1, Mode: edgeconfig.StringSetExact, CaseSensitive: true, Members: []string{"/x"}})
	}
	site := stringSetSite(refs[:4]...)
	site.Security.StringSets = sets[:4]
	if err := Validate(site); err != nil {
		t.Fatalf("4 sets: %v", err)
	}
	site = minimalSite()
	policy := stringSetSite().Security.Rules.Policies[0]
	policy.Rules = nil
	for index := range refs {
		policy.Rules = append(policy.Rules, edgeconfig.WAFRule{RuleID: "0190a000-0000-7000-8000-0000000002" + strconv.FormatInt(int64(10+index), 10),
			Match: edgeconfig.WAFMatch{StringSets: refs[index : index+1]}, Action: edgeconfig.WAFBlock, Control: edgeconfig.WAFContinue})
	}
	site.Security.Rules.Policies = []RulePolicy{policy}
	site.Security.StringSets = sets[:edgeconfig.MaxSiteStringSets]
	policy.Rules = policy.Rules[:edgeconfig.MaxSiteStringSets]
	site.Security.Rules.Policies = []RulePolicy{policy}
	if err := Validate(site); err != nil {
		t.Fatalf("%d sets: %v", edgeconfig.MaxSiteStringSets, err)
	}
	policy.Rules = append(policy.Rules, edgeconfig.WAFRule{RuleID: "0190a000-0000-7000-8000-000000000299",
		Match: edgeconfig.WAFMatch{StringSets: refs[edgeconfig.MaxSiteStringSets:]}, Action: edgeconfig.WAFBlock, Control: edgeconfig.WAFContinue})
	site.Security.Rules.Policies = []RulePolicy{policy}
	site.Security.StringSets = sets
	if err := Validate(site); !errors.Is(err, ErrInvalid) {
		t.Fatalf("%d sets accepted: %v", len(sets), err)
	}
	// Three full 256 KiB sets: over the 512 KiB site member budget.
	big := func(id string, prefix string) StringSet {
		members := make([]string, 0, edgeconfig.MaxStringSetBytes/edgeconfig.MaxStringSetMemberBytes)
		for index := 0; index < cap(members); index++ {
			head := prefix + strconv.Itoa(1000+index)
			members = append(members, head+strings.Repeat("m", edgeconfig.MaxStringSetMemberBytes-len(head)))
		}
		return StringSet{ID: id, Revision: 1, Mode: edgeconfig.StringSetExact, CaseSensitive: true, Members: members}
	}
	ids := []string{sets[0].ID, sets[1].ID, sets[2].ID}
	site = stringSetSite(refs[0], refs[1])
	site.Security.StringSets = []StringSet{big(ids[0], "a"), big(ids[1], "b")}
	if err := Validate(site); err != nil {
		t.Fatalf("512 KiB of members: %v", err)
	}
	site = stringSetSite(refs[0], refs[1], refs[2])
	site.Security.StringSets = []StringSet{big(ids[0], "a"), big(ids[1], "b"), big(ids[2], "c")}
	if err := Validate(site); !errors.Is(err, ErrInvalid) {
		t.Fatalf("768 KiB of members accepted: %v", err)
	}
}
