package siteindex

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// fakeNode is the control socket of contract §5.4 reduced to what the
// Activator calls: status, stage/commit (generation moves), rebuild (from
// the current index file).
type fakeNode struct {
	mu                 sync.Mutex
	generation, maxGen uint64
	files              Files
	probes             int // /probe calls
}

func (node *fakeNode) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	node.mu.Lock()
	defer node.mu.Unlock()
	switch {
	case request.URL.Path == "/status":
		_ = json.NewEncoder(writer).Encode(map[string]any{"gen": node.generation, "max_gen": node.maxGen, "epoch_ok": node.generation != 0,
			"capacity_bytes": 1 << 20, "free_bytes": 1 << 20, "workers": map[string]uint64{"1": node.generation}})
	case request.URL.Path == "/probe":
		// answered from the current index file (the fake node's routing table)
		node.probes++
		port, _ := strconv.Atoi(request.URL.Query().Get("port"))
		index, _, _ := node.files.Current()
		host := request.URL.Query().Get("host")
		digest, ok := lookup(index, port, host)
		if _, rest, cut := strings.Cut(host, "."); !ok && cut {
			digest, ok = lookup(index, port, "*."+rest)
		}
		state := "ok"
		if !ok {
			state = "miss"
		}
		_ = json.NewEncoder(writer).Encode(Probe{State: state, Digest: digest.String(), Generation: node.generation})
	case request.URL.Path == "/stage":
		raw, _ := io.ReadAll(request.Body)
		set, err := UnmarshalChangeSet(raw)
		if err != nil || set.Base != node.generation {
			writer.WriteHeader(http.StatusConflict)
			return
		}
		node.maxGen = set.Generation
		_, _ = writer.Write([]byte("{}"))
	case request.URL.Path == "/commit":
		node.generation, _ = strconv.ParseUint(request.URL.Query().Get("gen"), 10, 64)
		_, _ = writer.Write([]byte("{}"))
	case request.URL.Path == "/rebuild":
		index, ok, err := node.files.Current()
		if err != nil || !ok {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		node.generation, node.maxGen = index.Generation, max(node.maxGen, index.Generation)
		writer.WriteHeader(http.StatusAccepted)
		_, _ = writer.Write([]byte("{}"))
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func startFakeNode(t *testing.T, root string) (*fakeNode, *Control) {
	t.Helper()
	socket := filepath.Join("/tmp", "cdnca-si-"+strconv.Itoa(os.Getpid())+".sock") // short: sun_path is 104 bytes on macOS
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	node := &fakeNode{files: Files{Root: filepath.Join(root, "index"), Access: Access{GID: -1}}}
	server := &http.Server{Handler: node}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = os.Remove(socket) })
	return node, NewControl(socket)
}

// withClientCA gives the site's TLS listener client verification against ca.
func withClientCA(site edgesite.Site, ca []byte) edgesite.Site {
	site.Listeners = []edgesite.Listener{{Port: 443, AddressFamily: edgesite.FamilyIPv4, TLS: &edgesite.TLS{
		CertificateVersionID: "0d3a0000-0000-4000-8000-0000000000c1", Protocols: []string{"TLSv1.2", "TLSv1.3"},
		ClientAuth: edgeconfig.ClientAuthRequired,
		ClientCA:   &edgesite.Ref{Kind: edgesite.RefClientCA, ID: site.SiteID, Revision: 1, SHA256: edgesite.Digest(ca)}}}}
	return site
}

// Referenced objects (client CA bundles, policies, assets) live in the same
// object directory as site objects: a cold start rebuild must keep them, and
// an incremental activation removes one only when no site of the active or
// previous generation references it any more.
func TestActivatorKeepsReferencedObjects(t *testing.T) {
	root := t.TempDir()
	node, control := startFakeNode(t, root)
	activator := &Activator{Control: control, Files: node.files, Objects: ObjectDir{Root: filepath.Join(root, "objects"), Access: Access{GID: -1}}}
	caA, caB := []byte("client CA A\n"), []byte("client CA B\n")
	digestA, digestB := edgesite.Digest(caA), edgesite.Digest(caB)
	for _, ca := range [][]byte{caA, caB} {
		if err := activator.Objects.Put(edgesite.Digest(ca), ca); err != nil {
			t.Fatal(err)
		}
	}
	// A stray object nothing references: the full sweep removes it.
	stray := []byte("stray")
	if err := activator.Objects.Put(edgesite.Digest(stray), stray); err != nil {
		t.Fatal(err)
	}
	siteA := withClientCA(testSite(1, "a.example.test", nil), caA)
	siteB := withClientCA(testSite(2, "b.example.test", nil), caB)
	plain := testSite(3, "c.example.test", nil, 80)
	generation1 := []Object{object(t, siteA), object(t, siteB), object(t, plain)}

	first, err := activator.Activate(context.Background(), generation1)
	if err != nil || !first.Rebuilt {
		t.Fatalf("cold start activation: %+v %v", first, err)
	}
	have, _ := activator.Objects.List()
	for _, digest := range []string{digestA, digestB} {
		if !slices.Contains(have, digest) {
			t.Fatalf("cold start rebuild removed referenced object %s (have %v)", digest[:8], have)
		}
	}
	if slices.Contains(have, edgesite.Digest(stray)) {
		t.Fatal("cold start rebuild kept an unreferenced object")
	}

	// Generation 2: site B now uses CA A. B's old object stays (previous
	// generation), so does CA B.
	siteB2 := withClientCA(testSite(2, "b.example.test", nil), caA)
	siteB2.Revision = 2
	generation2 := []Object{object(t, siteA), object(t, siteB2), object(t, plain)}
	if second, err := activator.Activate(context.Background(), generation2); err != nil || second.Rebuilt {
		t.Fatalf("incremental activation: %+v %v", second, err)
	}
	have, _ = activator.Objects.List()
	if !slices.Contains(have, digestB) {
		t.Fatal("CA B removed while the previous generation still references it")
	}
	// Generation 3: B's first object leaves the previous generation; CA B is
	// referenced by nothing now and goes, CA A stays.
	siteC2 := plain
	siteC2.Revision = 2
	generation3 := []Object{object(t, siteA), object(t, siteB2), object(t, siteC2)}
	if _, err := activator.Activate(context.Background(), generation3); err != nil {
		t.Fatal(err)
	}
	have, _ = activator.Objects.List()
	if slices.Contains(have, digestB) || !slices.Contains(have, digestA) {
		t.Fatalf("after B moved to CA A: CA A kept=%v, CA B kept=%v", slices.Contains(have, digestA), slices.Contains(have, digestB))
	}
	if slices.Contains(have, generation1[1].Digest.String()) {
		t.Fatal("site B's first object not released")
	}
}

// D7: a caller may hand the referenced objects with the site object
// (Object.Referenced: CC policies, HTTP policy entries, firewall actions);
// Activate writes them before the site becomes routable. A referenced object
// neither supplied nor present refuses the activation (a routable site
// whose policy object is missing would answer 503).
func TestActivatorWritesSuppliedReferencedObjects(t *testing.T) {
	root := t.TempDir()
	node, control := startFakeNode(t, root)
	activator := &Activator{Control: control, Files: node.files, Objects: ObjectDir{Root: filepath.Join(root, "objects"), Access: Access{GID: -1}}}
	policy := []byte(`{"policy":"cc"}`)
	site := testSite(4, "d.example.test", nil, 80)
	site.Security.CC = []edgesite.CCBinding{{Ports: []int{80}, SourceSHA256: edgesite.Digest([]byte("source")),
		Policy: edgesite.Ref{Kind: edgesite.RefCCPolicy, ID: site.SiteID, Revision: 1, SHA256: edgesite.Digest(policy)}}}
	missing := object(t, site)
	if _, err := activator.Activate(context.Background(), []Object{missing}); err == nil {
		t.Fatal("activated a site whose referenced object is neither supplied nor present")
	}
	if have, _ := activator.Objects.List(); slices.Contains(have, missing.Digest.String()) {
		t.Fatal("site object written before its referenced object was checked")
	}
	supplied := object(t, site)
	supplied.Referenced = map[string][]byte{edgesite.Digest(policy): policy}
	if _, err := activator.Activate(context.Background(), []Object{supplied}); err != nil {
		t.Fatal(err)
	}
	have, _ := activator.Objects.List()
	if !slices.Contains(have, edgesite.Digest(policy)) || !slices.Contains(have, supplied.Digest.String()) {
		t.Fatalf("objects %v", have)
	}
	// already present: no need to supply it again
	again := object(t, site)
	if _, err := activator.Activate(context.Background(), []Object{again}); err != nil {
		t.Fatal(err)
	}
}

// F13: on an agent node the object directory is the shared object store
// (objectstore.OpenShared). The activator reads objects in place, never
// writes or removes there (the store collects), and refuses an object the
// store does not hold.
func TestActivatorOnExternalObjectStore(t *testing.T) {
	root := t.TempDir()
	node, control := startFakeNode(t, root)
	store := ObjectDir{Root: filepath.Join(root, "objects"), Access: Access{GID: -1}}
	activator := &Activator{Control: control, Files: node.files,
		Objects: ObjectDir{Root: store.Root, Access: store.Access, External: true}}
	siteA, siteB := object(t, testSite(1, "a.example.test", nil, 80)), object(t, testSite(2, "b.example.test", nil, 80))
	if _, err := activator.Activate(context.Background(), []Object{siteA}); err == nil {
		t.Fatal("activated a site the object store does not hold")
	}
	for _, site := range []Object{siteA, siteB} {
		if err := store.Put(site.Digest.String(), site.Raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := activator.Activate(context.Background(), []Object{siteA, siteB}); err != nil {
		t.Fatal(err)
	}
	for _, generation := range [][]Object{{siteA}, {siteA}, {siteA}} {
		if _, err := activator.Activate(context.Background(), generation); err != nil {
			t.Fatal(err)
		}
	}
	if have, _ := store.List(); !slices.Contains(have, siteB.Digest.String()) {
		t.Fatal("the activator removed an object from the external object store")
	}
}

// D13d-1: the health check after an activation probes the sites the
// activation added or changed, not every site (10万站 one probe per site was
// 31.6 s per Check). Removed sites are not probed; a rebuild probes all.
func TestActivationProbesOnlyChangedSites(t *testing.T) {
	root := t.TempDir()
	node, control := startFakeNode(t, root)
	activator := &Activator{Control: control, Files: node.files, Objects: ObjectDir{Root: filepath.Join(root, "objects"), Access: Access{GID: -1}}}
	ctx := context.Background()
	a, b, c := testSite(1, "a.example.test", nil, 80), testSite(2, "*.b.example.test", nil, 80), testSite(3, "c.example.test", nil, 80)
	cold, err := activator.Activate(ctx, []Object{object(t, a), object(t, b), object(t, c)})
	if err != nil || !cold.Rebuilt {
		t.Fatalf("cold start: %+v %v", cold, err)
	}
	if len(cold.Probes) != 3 {
		t.Fatalf("rebuild probes %v, want every site", cold.Probes)
	}
	// b changes, c is removed, d is added; a is unchanged.
	b.Revision = 2
	d := testSite(4, "d.example.test", nil, 80)
	changed, added := object(t, b), object(t, d)
	next, err := activator.Activate(ctx, []Object{object(t, a), changed, added})
	if err != nil || next.Rebuilt {
		t.Fatalf("incremental: %+v %v", next, err)
	}
	want := map[ProbeKey]string{{Port: 80, Host: "probe.b.example.test"}: changed.Digest.String(), {Port: 80, Host: "d.example.test"}: added.Digest.String()}
	if len(next.Probes) != len(want) {
		t.Fatalf("probes %v, want %v", next.Probes, want)
	}
	for key, digest := range want {
		if next.Probes[key] != digest {
			t.Fatalf("probes %v, want %v", next.Probes, want)
		}
	}
	node.mu.Lock()
	node.probes = 0
	node.mu.Unlock()
	health, err := activator.WaitHealthy(ctx, next.Generation, next.Probes, time.Second)
	if err != nil || !health.Healthy {
		t.Fatalf("health %+v %v", health, err)
	}
	if node.probes != 2 {
		t.Fatalf("%d probes, want 2", node.probes)
	}
}

// A rebuild's probes run concurrently (bounded) and still report every
// mismatch.
func TestCheckProbesConcurrently(t *testing.T) {
	root := t.TempDir()
	node, control := startFakeNode(t, root)
	activator := &Activator{Control: control, Files: node.files, Objects: ObjectDir{Root: filepath.Join(root, "objects"), Access: Access{GID: -1}}}
	ctx := context.Background()
	objects := make([]Object, 200)
	for index := range objects {
		objects[index] = object(t, testSite(index+1, fmt.Sprintf("s%d.example.test", index), nil, 80))
	}
	activation, err := activator.Activate(ctx, objects)
	if err != nil {
		t.Fatal(err)
	}
	probes := maps.Clone(activation.Probes)
	probes[ProbeKey{Port: 80, Host: "missing.example.test"}] = objects[0].Digest.String()
	health, err := activator.Check(ctx, activation.Generation, probes)
	if err != nil || health.Healthy || len(health.Reasons) != 1 || !strings.Contains(health.Reasons[0], "missing.example.test") {
		t.Fatalf("health %+v %v", health, err)
	}
	if node.probes != 201 {
		t.Fatalf("%d probes, want 201", node.probes)
	}
}
