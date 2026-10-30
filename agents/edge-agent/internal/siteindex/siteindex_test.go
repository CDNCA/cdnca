package siteindex

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

const (
	testScope  = "0d3a0000-0000-4000-8000-000000000001"
	testTenant = "0d3a0000-0000-4000-8000-000000000002"
)

// testSite is a minimal valid site object answering primary + aliases on
// ports (plain HTTP).
func testSite(number int, primary string, aliases []string, ports ...int) edgesite.Site {
	listeners := make([]edgesite.Listener, 0, len(ports))
	for _, port := range ports {
		listeners = append(listeners, edgesite.Listener{Port: port, AddressFamily: edgesite.FamilyIPv4})
	}
	if aliases == nil {
		aliases = []string{}
	}
	return edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: testScope, TenantID: testTenant,
		SiteID: fmt.Sprintf("0d3a0000-0000-4000-8000-%012d", 1000+number), Revision: 1,
		Hosts:     edgesite.Hosts{Primary: primary, Aliases: aliases},
		Listeners: listeners,
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "origin-0", Scheme: "http", Host: "192.0.2.1", Port: 80, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 10, ReadTimeoutMS: 10, TotalBudgetMS: 10}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
	}
}

func object(t testing.TB, site edgesite.Site) Object {
	t.Helper()
	raw, err := edgesite.Encode(site)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeObject(edgesite.Digest(raw), raw)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func lookup(index Index, port int, name string) (Digest, bool) {
	key := Key(edgesite.IndexKey(port, name))
	position, found := slices.BinarySearchFunc(index.Entries, key, func(entry Entry, key Key) int { return compareKeys(entry.Key, key) })
	if !found {
		return Digest{}, false
	}
	return index.Entries[position].Digest, true
}

func TestBuildIndexesEveryPortAndName(t *testing.T) {
	shop := object(t, testSite(1, "shop.example.test", []string{"*.shop.example.test", "www.shop.example.test"}, 80, 8080))
	api := object(t, testSite(2, "api.example.test", nil, 80))
	index, err := Build(7, []Object{shop, api})
	if err != nil {
		t.Fatal(err)
	}
	if index.Generation != 7 || !slices.Equal(index.Ports, []uint16{80, 8080}) || len(index.Entries) != 7 {
		t.Fatalf("index = gen %d ports %v entries %d", index.Generation, index.Ports, len(index.Entries))
	}
	for _, check := range []struct {
		port int
		name string
		want Object
	}{{80, "shop.example.test", shop}, {8080, "*.shop.example.test", shop}, {80, "www.shop.example.test", shop}, {80, "api.example.test", api}} {
		if got, ok := lookup(index, check.port, check.name); !ok || got != check.want.Digest {
			t.Fatalf("%d %s -> %s %v", check.port, check.name, got, ok)
		}
	}
	if _, ok := lookup(index, 8080, "api.example.test"); ok {
		t.Fatal("api is not on 8080")
	}
	if got := index.Digests(); len(got) != 2 {
		t.Fatalf("digests %v", got)
	}
}

func TestBuildRefusesConflicts(t *testing.T) {
	a := object(t, testSite(1, "a.example.test", nil, 80))
	sameName := object(t, testSite(2, "a.example.test", nil, 80))
	if _, err := Build(1, []Object{a, sameName}); err == nil {
		t.Fatal("two sites for one (port, name) must be refused")
	}
	if _, err := Build(1, []Object{a, a}); err == nil {
		t.Fatal("a site twice must be refused")
	}
	if _, err := Build(0, []Object{a}); err == nil {
		t.Fatal("generation 0 must be refused")
	}
	// Same name on another port belongs to another site legitimately.
	other := object(t, testSite(3, "a.example.test", nil, 81))
	if _, err := Build(1, []Object{a, other}); err != nil {
		t.Fatal(err)
	}
}

// HTTP/2 is per site on a shared port (native patch 27, edgesite.PortProfiles):
// one site with it and one without must index; TLS must still agree.
func TestBuildPortHTTP2PerSiteTLSShared(t *testing.T) {
	withTLS := func(site edgesite.Site, http2 bool) edgesite.Site {
		site.Listeners[0].TLS = &edgesite.TLS{}
		site.Listeners[0].HTTP2 = http2
		return site
	}
	on := withTLS(testSite(1, "on.example.test", nil, 443), true)
	off := withTLS(testSite(2, "off.example.test", nil, 443), false)
	index, err := buildSites(t, on, off)
	if err != nil {
		t.Fatalf("h2 on and off on one port must index: %v", err)
	}
	if !slices.Equal(index.Ports, []uint16{443}) || len(index.Entries) != 2 {
		t.Fatalf("index ports %v entries %d", index.Ports, len(index.Entries))
	}
	profiles, err := edgesite.PortProfiles([]edgesite.Site{on, off})
	if err != nil || len(profiles) != 1 || !profiles[0].HTTP2 {
		t.Fatalf("port profile = %+v %v, want http2 on (any site)", profiles, err)
	}
	plain := testSite(3, "plain.example.test", nil, 443)
	if _, err := buildSites(t, on, plain); err == nil {
		t.Fatal("TLS and plain on one port must be refused")
	}
}

// buildSites builds an index of sites without the digest round trip
// (the TLS stub need not encode).
func buildSites(t testing.TB, sites ...edgesite.Site) (Index, error) {
	t.Helper()
	builder := NewBuilder(1, len(sites))
	for number, site := range sites {
		var digest Digest
		digest[0] = byte(number + 1)
		if err := builder.Add(digest, site); err != nil {
			return Index{}, err
		}
	}
	return builder.Index()
}

func TestDecodeObjectChecksDigest(t *testing.T) {
	raw, err := edgesite.Encode(testSite(1, "a.example.test", nil, 80))
	if err != nil {
		t.Fatal(err)
	}
	wrong := edgesite.Digest(append(raw, ' '))
	if _, err := DecodeObject(wrong, raw); err == nil {
		t.Fatal("digest mismatch accepted")
	}
}

func randomIndex(generation uint64, count int, salt string) Index {
	index := Index{Generation: generation, Ports: []uint16{80, 443}}
	for position := range count {
		key := Key(edgesite.IndexKey(80, fmt.Sprintf("site-%d.%s.test", position, salt)))
		var digest Digest
		copy(digest[:], bytes.Repeat([]byte{byte(position), byte(position >> 8)}, 16))
		index.Entries = append(index.Entries, Entry{Key: key, Digest: digest})
	}
	sortEntries(index.Entries)
	return index
}

func TestIndexFileRoundTripAndCorruption(t *testing.T) {
	index := randomIndex(42, 1000, "x")
	raw, err := MarshalIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	if want := 8 + 8 + 4 + 2 + 4 + 1000*48 + 32; len(raw) != want {
		t.Fatalf("size %d, want %d", len(raw), want)
	}
	decoded, err := UnmarshalIndex(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Generation != 42 || !slices.Equal(decoded.Ports, index.Ports) || !slices.Equal(decoded.Entries, index.Entries) {
		t.Fatal("round trip differs")
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"flipped entry": func(b []byte) []byte { b[100] ^= 1; return b },
		"truncated":     func(b []byte) []byte { return b[:len(b)-1] },
		"magic":         func(b []byte) []byte { b[0] = 'X'; return b },
		"empty":         func([]byte) []byte { return nil },
	} {
		if _, err := UnmarshalIndex(mutate(slices.Clone(raw))); !errors.Is(err, ErrFormat) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	unsorted := randomIndex(1, 3, "y")
	unsorted.Entries[0], unsorted.Entries[1] = unsorted.Entries[1], unsorted.Entries[0]
	if _, err := MarshalIndex(unsorted); err == nil {
		t.Fatal("unsorted entries accepted")
	}
}

func TestDiffApplyAndChangeSets(t *testing.T) {
	old := randomIndex(5, 300, "a")
	next := randomIndex(0, 200, "a") // first 200 kept with the same digests
	next.Entries = append(next.Entries, randomIndex(0, 150, "b").Entries...)
	for position := range next.Entries[:20] { // and 20 changed digests
		next.Entries[position].Digest[0] ^= 0xff
	}
	sortEntries(next.Entries)
	next.Ports = []uint16{443, 8443}

	changes := Diff(old.Entries, next.Entries)
	if !slices.Equal(Apply(old.Entries, changes), next.Entries) {
		t.Fatal("apply(diff) != next")
	}
	sets, err := ChangeSets(old, next, 6, 64)
	if err != nil {
		t.Fatal(err)
	}
	if want := (len(changes) + 63) / 64; len(sets) != want {
		t.Fatalf("%d sets, want %d", len(sets), want)
	}
	entries := old.Entries
	base := uint64(5)
	for position, set := range sets {
		if set.Base != base || set.Generation != base+1 {
			t.Fatalf("set %d base %d gen %d", position, set.Base, set.Generation)
		}
		wantPorts := []uint16{80, 443, 8443}
		if position == len(sets)-1 {
			wantPorts = next.Ports
		}
		if !slices.Equal(set.Ports, wantPorts) {
			t.Fatalf("set %d ports %v", position, set.Ports)
		}
		raw, err := MarshalChangeSet(set)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := UnmarshalChangeSet(raw)
		if err != nil {
			t.Fatal(err)
		}
		entries = Apply(entries, decoded.Changes)
		base = set.Generation
	}
	if !slices.Equal(entries, next.Entries) {
		t.Fatal("applying every change set != next")
	}
	if sets, err := ChangeSets(old, old, 6, 0); err != nil || len(sets) != 1 || len(sets[0].Changes) != 0 {
		t.Fatalf("no-op change: %v %v", sets, err)
	}
	if _, err := ChangeSets(old, next, 5, 0); err == nil {
		t.Fatal("generation not after active accepted")
	}
}

func TestChangeSetRejects(t *testing.T) {
	good := ChangeSet{Generation: 2, Base: 1, Ports: []uint16{80}, Changes: []Change{{Op: OpDelete, Key: Key{1}}, {Op: OpSet, Key: Key{2}}}}
	raw, err := MarshalChangeSet(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalChangeSet(raw[:len(raw)-40]); err == nil {
		t.Fatal("truncated accepted")
	}
	for name, set := range map[string]ChangeSet{
		"base":     {Generation: 1, Base: 1, Ports: []uint16{}},
		"ports":    {Generation: 2, Base: 1, Ports: []uint16{80, 80}},
		"op":       {Generation: 2, Base: 1, Ports: []uint16{}, Changes: []Change{{Op: 3}}},
		"unsorted": {Generation: 2, Base: 1, Ports: []uint16{}, Changes: []Change{{Op: OpSet, Key: Key{2}}, {Op: OpSet, Key: Key{1}}}},
		"too many": {Generation: 2, Base: 1, Ports: []uint16{}, Changes: make([]Change, MaxChangeEntries+1)},
	} {
		if _, err := MarshalChangeSet(set); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestFilesCurrentAndRetention(t *testing.T) {
	files := Files{Root: filepath.Join(t.TempDir(), "site-index"), Access: Access{GID: -1}}
	if _, ok, err := files.Current(); ok || err != nil {
		t.Fatalf("empty: %v %v", ok, err)
	}
	for generation := uint64(1); generation <= 3; generation++ {
		if err := files.Write(randomIndex(generation, 10, "f")); err != nil {
			t.Fatal(err)
		}
	}
	if err := files.SetCurrent(3, 2); err != nil {
		t.Fatal(err)
	}
	current, ok, err := files.Current()
	if err != nil || !ok || current.Generation != 3 {
		t.Fatalf("current %d %v %v", current.Generation, ok, err)
	}
	if _, err := os.Stat(filepath.Join(files.Root, "gen-1.idx")); !os.IsNotExist(err) {
		t.Fatal("gen-1 not removed")
	}
	if _, err := files.Read(2); err != nil {
		t.Fatal("previous generation removed")
	}
	info, err := os.Stat(filepath.Join(files.Root, "gen-3.idx"))
	if err != nil || info.Mode().Perm() != 0o440 {
		t.Fatalf("mode %v %v", info.Mode(), err)
	}
	if err := files.SetCurrent(9, 0); err == nil {
		t.Fatal("current set to a missing generation")
	}
}

func TestObjectDirPutRetain(t *testing.T) {
	dir := ObjectDir{Root: filepath.Join(t.TempDir(), "site-objects"), Access: Access{GID: -1}}
	a := object(t, testSite(1, "a.example.test", nil, 80))
	b := object(t, testSite(2, "b.example.test", nil, 80))
	for _, item := range []Object{a, b, a} {
		if err := dir.Put(item.Digest.String(), item.Raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := dir.Put(a.Digest.String(), b.Raw); err == nil {
		t.Fatal("wrong content accepted")
	}
	got, err := os.ReadFile(dir.Path(a.Digest.String()))
	if err != nil || !bytes.Equal(got, a.Raw) {
		t.Fatal("object content")
	}
	info, _ := os.Stat(filepath.Dir(dir.Path(a.Digest.String())))
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("dir mode %v", info.Mode())
	}
	removed, err := dir.Retain([]string{b.Digest.String()})
	if err != nil || removed != 1 {
		t.Fatalf("retain removed %d %v", removed, err)
	}
	list, _ := dir.List()
	if !slices.Equal(list, []string{b.Digest.String()}) {
		t.Fatalf("list %v", list)
	}
}

func TestObjectDirVerifyDropsDamagedCopy(t *testing.T) {
	dir := ObjectDir{Root: filepath.Join(t.TempDir(), "site-objects"), Access: Access{GID: -1}}
	a := object(t, testSite(1, "a.example.test", nil, 80))
	digest := a.Digest.String()
	if err := dir.Put(digest, a.Raw); err != nil {
		t.Fatal(err)
	}
	if !dir.Verify(digest) {
		t.Fatal("intact object reported damaged")
	}
	damaged := slices.Clone(a.Raw)
	damaged[0] ^= 1
	path := dir.Path(digest)
	_ = os.Chmod(path, 0o644)
	if err := os.WriteFile(path, damaged, 0o644); err != nil {
		t.Fatal(err)
	}
	if dir.Verify(digest) {
		t.Fatal("damaged object reported intact")
	}
	if err := dir.Put(digest, a.Raw); err != nil || !dir.Verify(digest) {
		t.Fatalf("re-put %v", err)
	}
}
