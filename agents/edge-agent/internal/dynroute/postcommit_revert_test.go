package dynroute

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

// fix-codex-a 卡 2 (DYNROUTE-POSTCOMMIT-ROLLBACK-01): a generation that was
// activated and then failed its health check is compensated (the previous
// generation runs again), and a failed compensation says so.

// revertNode is the node control socket reduced to what Apply and the
// compensation call. unhealthy decides the health of an active generation;
// refuseFrom (non-zero) refuses /rollback and /stage once the node runs
// that generation or a later one.
type revertNode struct {
	mu                       sync.Mutex
	generation, prev, maxGen uint64
	tagsGen                  uint64
	files                    siteindex.Files
	unhealthy                func(generation uint64) (probe503, lowFree bool)
	refuseFrom               uint64
	rollbacks                int
}

func (node *revertNode) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	node.mu.Lock()
	defer node.mu.Unlock()
	probe503, lowFree := node.unhealthy(node.generation)
	refused := node.refuseFrom != 0 && node.generation >= node.refuseFrom
	switch request.URL.Path {
	case "/status":
		free := int64(1 << 20)
		if lowFree {
			free = 1 << 10
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"gen": node.generation, "prev_gen": node.prev, "max_gen": node.maxGen,
			"tags_gen": node.tagsGen, "epoch_ok": true, "capacity_bytes": 1 << 20, "free_bytes": free,
			"workers": map[string]uint64{"1": node.generation}})
	case "/probe":
		if probe503 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		port, _ := strconv.Atoi(request.URL.Query().Get("port"))
		index, _, _ := node.files.Current()
		key := siteindex.Key(edgesite.IndexKey(port, request.URL.Query().Get("host")))
		probe := siteindex.Probe{State: "miss", Generation: node.generation}
		for _, entry := range index.Entries {
			if entry.Key == key {
				probe.State, probe.Digest = "ok", entry.Digest.String()
			}
		}
		_ = json.NewEncoder(writer).Encode(probe)
	case "/stage":
		raw, _ := io.ReadAll(request.Body)
		set, err := siteindex.UnmarshalChangeSet(raw)
		if refused || err != nil || set.Base != node.generation {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		node.maxGen = set.Generation
		_, _ = writer.Write([]byte("{}"))
	case "/commit":
		committed, _ := strconv.ParseUint(request.URL.Query().Get("gen"), 10, 64)
		node.prev, node.generation, node.tagsGen = node.generation, committed, committed
		_, _ = writer.Write([]byte("{}"))
	case "/rollback":
		node.rollbacks++
		if refused || node.prev == 0 {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		node.generation, node.prev, node.tagsGen = node.prev, 0, 0
		_, _ = writer.Write([]byte("{}"))
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func revertSite(origin string) edgesite.Site {
	return edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: testScopeA, TenantID: testPlatform, SiteID: testSiteA, Revision: 1,
		Hosts:     edgesite.Hosts{Primary: "www.example.test", Aliases: []string{}},
		Listeners: []edgesite.Listener{{Port: 18080, AddressFamily: edgesite.FamilyIPv4}},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "origin-0", Scheme: "http", Host: origin, Port: 80, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 10, ReadTimeoutMS: 10, TotalBudgetMS: 10}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
	}
}

func revertObject(t *testing.T, site edgesite.Site) siteindex.Object {
	t.Helper()
	raw, err := edgesite.Encode(site)
	if err != nil {
		t.Fatal(err)
	}
	object, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

// newRevertRuntime is a runtime whose generation 1 (origin 192.0.2.1) is
// active on node, with OpenResty "running" (this process) and the skeleton
// for these sites installed, so Apply of a same-port edit reaches the
// activation without OpenResty.
func newRevertRuntime(t *testing.T, node *revertNode) (*Runtime, siteindex.Object) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "rvt") // short: sun_path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	runtime, err := New(Config{StateRoot: filepath.Join(root, "node"), SharedRoot: filepath.Join(root, "shared"),
		LuaRoot: root, OpenResty: "/nonexistent/openresty", WorkerGID: -1, HealthTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	node.files = runtime.activator.Files
	socket := filepath.Join(runtime.config.StateRoot, edgeskeleton.ControlSocket)
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: node}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	old := revertObject(t, revertSite("192.0.2.1"))
	if err := runtime.activator.Objects.Put(old.Digest.String(), old.Raw); err != nil {
		t.Fatal(err)
	}
	index, err := siteindex.Build(1, []siteindex.Object{old})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.activator.Files.Write(index); err != nil {
		t.Fatal(err)
	}
	if err := runtime.activator.Files.SetCurrent(1, 0); err != nil {
		t.Fatal(err)
	}
	node.generation, node.maxGen = 1, 1
	if err := os.MkdirAll(runtime.config.SharedRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtime.config.SharedRoot, "nginx.pid"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	conf, err := runtime.render([]edgesite.Site{old.Site}, dynwaf.Result{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime.state = persisted{Generation: 1, Skeleton: skeletonDigest(conf)}
	runtime.sites = []edgesite.Site{old.Site}
	if err := runtime.saveState(); err != nil {
		t.Fatal(err)
	}
	return runtime, old
}

func TestApplyRevertsAGenerationThatFailsHealthAfterActivation(t *testing.T) {
	for _, test := range []struct {
		name     string
		probe503 bool
	}{{"probe 503", true}, {"dictionary free below 20%", false}} {
		t.Run(test.name, func(t *testing.T) {
			node := &revertNode{unhealthy: func(generation uint64) (bool, bool) {
				if generation < 2 {
					return false, false
				}
				return test.probe503, !test.probe503
			}}
			runtime, old := newRevertRuntime(t, node)
			next := revertObject(t, revertSite("192.0.2.2"))
			_, err := runtime.Apply(context.Background(), Input{Objects: []siteindex.Object{next}})
			var reverted *RevertedError
			if !errors.As(err, &reverted) || reverted.Generation != 2 || reverted.RevertedTo != 1 || !reverted.RevertedAfterActivation() {
				t.Fatalf("Apply error %v, want RevertedError 2 -> 1", err)
			}
			var failed *RollbackFailedError
			if errors.As(err, &failed) {
				t.Fatalf("reverted reported as rollback failed: %v", err)
			}
			if node.generation != 1 || node.rollbacks != 1 {
				t.Fatalf("node generation %d rollbacks %d, want 1 1", node.generation, node.rollbacks)
			}
			current, _, err := runtime.activator.Files.Current()
			if err != nil || current.Generation != 1 || current.Digests()[0] != old.Digest.String() {
				t.Fatalf("current index %+v %v", current, err)
			}
			if runtime.Generation() != 1 || len(runtime.Sites()) != 1 || runtime.Sites()[0].Origin.Pools[0].Endpoints[0].Host != "192.0.2.1" {
				t.Fatalf("runtime generation %d sites %+v", runtime.Generation(), runtime.Sites())
			}
			// the persisted state names the reverted generation (a restart recovers it)
			restarted, err := New(runtime.config)
			if err != nil || restarted.Generation() != 1 {
				t.Fatalf("restarted generation %d %v", restarted.Generation(), err)
			}
		})
	}
}

func TestApplyReportsAFailedRevertAfterActivation(t *testing.T) {
	node := &revertNode{unhealthy: func(generation uint64) (bool, bool) { return false, generation >= 2 }, refuseFrom: 2}
	runtime, _ := newRevertRuntime(t, node)
	next := revertObject(t, revertSite("192.0.2.2"))
	_, err := runtime.Apply(context.Background(), Input{Objects: []siteindex.Object{next}})
	var failed *RollbackFailedError
	if !errors.As(err, &failed) || failed.Generation != 2 || failed.Err == nil || failed.RollbackErr == nil ||
		!failed.RollbackFailedAfterActivation() {
		t.Fatalf("Apply error %v, want RollbackFailedError", err)
	}
	var reverted *RevertedError
	if errors.As(err, &reverted) {
		t.Fatalf("failed rollback reported as reverted: %v", err)
	}
	if node.generation != 2 || node.rollbacks == 0 {
		t.Fatalf("node generation %d rollbacks %d", node.generation, node.rollbacks)
	}
}
