package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldendyn"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

func siteID(number int) string { return fmt.Sprintf("0f3a0000-0000-4000-8000-%012d", 100+number) }

// baseSite: one HTTP listener on the edge port, one origin pool.
func baseSite(number int, host string) edgesite.Site {
	return edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: siteID(number), Revision: 1,
		Hosts:     edgesite.Hosts{Primary: host, Aliases: []string{}},
		Listeners: []edgesite.Listener{{Port: edge, AddressFamily: edgesite.FamilyIPv4}},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "o", Scheme: "http", Host: "127.0.0.1", Port: 19921, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 2000, ReadTimeoutMS: 5000, TotalBudgetMS: 10000}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}},
			CC: []edgesite.CCBinding{}},
		Errors: []edgesite.ErrorPage{},
	}
}

func withCache(site edgesite.Site) edgesite.Site {
	document := edgeconfig.CachePolicyDocument{Revision: 1, Mode: edgeconfig.CacheFollowOrigin, Rules: []edgeconfig.CacheRuleDocument{},
		QueryMode: edgeconfig.CacheQueryPreserve, QueryNames: []string{}, VaryHeaders: []string{}, DiskQuotaBytes: 64 << 20}
	cache := &edgesite.Cache{KeyPrefix: edgesite.CacheKeyPrefix(tenant, site.SiteID), Domain: site.Hosts.Primary, KeyByHost: true, Policy: document}
	cache.Generation, _ = edgesite.CacheGeneration(*cache)
	site.Cache = cache
	return site
}

type node struct {
	root string
	conf string
}

func (n *node) openresty(args ...string) error {
	output, err := exec.Command("openresty", append([]string{"-p", n.root + "/", "-c", "nginx.conf"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("openresty %v: %v %s", args, err, output)
	}
	return nil
}

func (n *node) stop() { _ = n.openresty("-s", "stop"); time.Sleep(300 * time.Millisecond) }

func (n *node) errorLog() string {
	raw, _ := os.ReadFile(filepath.Join(n.root, goldendyn.SharedDirectory, "error.log"))
	return string(raw)
}

// start renders the node, runs openresty and activates the sites. before
// runs after the state root exists and before openresty starts (the
// challenge installer writes there); testConf is appended to the http block.
func start(root string, sites []edgesite.Site, rum bool, challenges []edgesite.Ref, before func() error, testConf string) (*node, error) {
	n := &node{root: root}
	_ = n.openresty("-s", "stop")
	time.Sleep(200 * time.Millisecond)
	_ = os.RemoveAll(root)
	for _, dir := range []string{"logs", "run", "site-index", "site-objects", "temp", "shared/cache"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o777); err != nil {
			return nil, err
		}
	}
	_ = os.Chmod(filepath.Join(root, "shared", "cache"), 0o777)
	if before != nil {
		if err := before(); err != nil {
			return nil, err
		}
	}
	ports, err := edgesite.PortProfiles(sites)
	if err != nil {
		return nil, err
	}
	keys := 0
	for _, s := range sites {
		keys += len(s.IndexEntries())
	}
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 256 << 20})
	conf, err := goldendyn.Config(goldendyn.ConfigInput{Root: root, LuaRoot: *luaRoot, Ports: ports, IndexKeys: keys,
		Workers: *workers, Cache: pool, SiteRUM: rum, Challenges: challenges})
	if err != nil {
		return nil, err
	}
	if testConf != "" {
		end := strings.LastIndex(string(conf), "}")
		conf = []byte(string(conf[:end]) + testConf + string(conf[end:]))
	}
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), conf, 0o644); err != nil {
		return nil, err
	}
	if err := n.openresty(); err != nil {
		return nil, err
	}
	gid := -1
	if group, err := user.LookupGroup("nobody"); err == nil {
		gid, _ = strconv.Atoi(group.Gid)
	}
	control := siteindex.NewControl(filepath.Join(root, "run", "cdnca-site-admin.sock"))
	activator := &siteindex.Activator{Control: control,
		Files:   siteindex.Files{Root: filepath.Join(root, "site-index"), Access: siteindex.Access{GID: gid}},
		Objects: siteindex.ObjectDir{Root: filepath.Join(root, "site-objects"), Access: siteindex.Access{GID: gid}}}
	ctx := context.Background()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := control.Status(ctx); err == nil {
			break
		} else if time.Now().After(deadline) {
			return nil, err
		}
	}
	objects := make([]siteindex.Object, 0, len(sites))
	for _, s := range sites {
		raw, err := edgesite.Encode(s)
		if err != nil {
			return nil, err
		}
		object, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
		if err != nil {
			return nil, err
		}
		objects = append(objects, object)
	}
	activation, err := activator.Activate(ctx, objects)
	if err != nil {
		return nil, err
	}
	if err := activator.WaitGeneration(ctx, activation.Generation); err != nil {
		return nil, err
	}
	unix := dyncache.UnixControl{Socket: filepath.Join(root, "run", "cdnca-site-admin.sock")}
	generations := &dyncache.Generations{Path: filepath.Join(root, "generations.json"), Control: unix}
	if err := generations.Sync(ctx); err != nil {
		return nil, err
	}
	return n, nil
}

var _ = edgeskeleton.RUMDictionary
