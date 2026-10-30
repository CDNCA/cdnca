package goldendyn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

// Name is the renderer's name in tests/edge-golden (compare.json renderers).
const Name = "cdnca-dynroute"

func init() { edgegolden.Register(Renderer{}) }

type Renderer struct{}

func (Renderer) Name() string { return Name }

// Start converts the facts to site objects, starts one OpenResty with a
// shared server per port and activates the objects through the node index
// control socket, as the agent does (siteindex.Activator).
func (Renderer) Start(ctx context.Context, env edgegolden.Env, scenario *edgegolden.Scenario) (edgegolden.Instance, error) {
	root := filepath.Join(env.WorkDir, scenario.Name)
	_ = os.RemoveAll(root)
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, err
	}
	if streamsOf(scenario.Facts.Document) {
		// L4 forwards: the agent's dynamic routing runtime with the node's
		// L4 runtime (streams.go)
		return startStreams(ctx, env, scenario, root)
	}
	sites, referenced, err := buildSites(ctx, env, scenario, root)
	if err != nil {
		return nil, err
	}
	ports, err := edgesite.PortProfiles(sites)
	if err != nil {
		return nil, err
	}
	originCA, err := env.PKI.CA("origin")
	if err != nil {
		return nil, err
	}
	systemCA := filepath.Join(root, "system-ca.pem")
	if err := os.WriteFile(systemCA, originCA.PEM, 0o644); err != nil {
		return nil, err
	}
	var pool edgecache.Pool
	if cachingSites(sites) {
		// the golden's sites have a 64 MiB quota each; one small pool
		if pool, err = edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 256 << 20, MaxRuleTTL: maxRuleTTL(sites)}); err != nil {
			return nil, err
		}
	}
	// D11: the managed WAF of the sites (node rules, tiers, CRS text)
	waf, err := managedWAF(env, sites, root)
	if err != nil {
		return nil, err
	}
	unknown, err := unknownSitePage(scenario, root)
	if err != nil {
		return nil, err
	}
	conf, err := Config(ConfigInput{Root: root, LuaRoot: env.LuaRoot, Ports: ports, NodeRegion: scenario.Facts.Node.Region, SystemCA: systemCA,
		IndexKeys: indexKeys(sites), Cache: pool, Challenges: edgeskeleton.ChallengesFromSites(sites), HealthPort: scenario.Facts.Node.HealthPort,
		ManagedWAF: waf, Schedule302: edgeskeleton.Schedule302FromSites(sites), UnknownSite: unknown,
		SiteGzip: edgeskeleton.SiteGzipFromSites(sites), Telemetry: scenario.Facts.Telemetry != nil, Workers: scenario.Facts.Node.Workers})
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), conf, 0o640); err != nil {
		return nil, err
	}
	if err := installCertificates(env, scenario.Facts.Node.Certificates, root); err != nil {
		return nil, err
	}
	if len(scenario.Facts.Node.Schedule302Table) != 0 {
		// the node's scheduling table under the state root, as the agent's
		// sched302runtime writes it
		if err := edgegolden.InstallSchedule302Table(root, scenario.Facts.Node.Schedule302Table); err != nil {
			return nil, fmt.Errorf("schedule302 table: %w", err)
		}
	}
	instance := &instance{root: root, openresty: env.OpenResty, sites: sites, pool: pool, env: env, scenario: scenario, ports: ports,
		registry: dyntelemetry.NewRegistry(), offsets: map[string]int64{}}
	if err := instance.run(); err != nil {
		return nil, err
	}
	control := siteindex.NewControl(filepath.Join(root, "run", "cdnca-site-admin.sock"))
	if err := waitControl(ctx, control); err != nil {
		_ = instance.Stop(ctx)
		return nil, fmt.Errorf("%w\nerror.log:\n%s", err, instance.errorLog())
	}
	objects, err := siteObjects(sites, referenced)
	if err != nil {
		_ = instance.Stop(ctx)
		return nil, err
	}
	instance.activator = &siteindex.Activator{Control: control,
		Files:   siteindex.Files{Root: filepath.Join(root, "site-index"), Access: siteindex.Access{GID: -1}},
		Objects: siteindex.ObjectDir{Root: filepath.Join(root, "site-objects"), Access: siteindex.Access{GID: -1}},
		// as the agent: the generations' attribution (D12) before serving
		Prepare: func(first, last uint64) error {
			return instance.registry.Register(first, last, scopeVersions(instance.scenario, instance.sites))
		}}
	if err := instance.activate(ctx, objects); err != nil {
		_ = instance.Stop(ctx)
		return nil, fmt.Errorf("activate: %w\nerror.log:\n%s", err, instance.errorLog())
	}
	if pool.Zones > 0 {
		if err := instance.startCache(ctx); err != nil {
			_ = instance.Stop(ctx)
			return nil, fmt.Errorf("cache: %w\nerror.log:\n%s", err, instance.errorLog())
		}
	}
	return instance, nil
}

// buildSites: the scenario's site objects and the objects they reference.
func buildSites(ctx context.Context, env edgegolden.Env, scenario *edgegolden.Scenario, root string) ([]edgesite.Site, map[string][]byte, error) {
	var sites []edgesite.Site
	var referenced map[string][]byte
	var err error
	if securityScenario(scenario) {
		// D7: the scenario's signed release through the control plane's
		// own site object conversion (CC, rules, challenge, HTTP policy,
		// firewall action), its policies published where the node reads them
		if sites, referenced, err = productionSites(ctx, env, scenario, root); err != nil {
			return nil, nil, err
		}
	} else {
		values := env.PKI.Placeholders()
		raw, err := edgegolden.Expand(scenario.Facts.Document, values)
		if err != nil {
			return nil, nil, fmt.Errorf("document: %w", err)
		}
		if sites, err = Convert(raw, scenario, values); err != nil {
			return nil, nil, err
		}
	}
	// D9: the scenario's error page policy as each site's effective pages
	// (control plane siteErrorPageFacts), bodies as referenced objects
	if sites, referenced, err = withErrorPages(scenario, sites, referenced); err != nil {
		return nil, nil, err
	}
	// Origin trust CA sets are referenced objects (D5b): the golden
	// publishes origin-trust/<digest>.pem, the PEM of a run CA. The run's
	// "origin" CA stands in for the public CAs of trust "system" (as v7's
	// renderer does).
	if len(scenario.Facts.OriginTrust) != 0 && referenced == nil {
		referenced = map[string][]byte{}
	}
	for _, name := range scenario.Facts.OriginTrust {
		ca, err := env.PKI.CA(name)
		if err != nil {
			return nil, nil, err
		}
		referenced[ca.TrustDigest()] = ca.PEM
	}
	return sites, referenced, nil
}

func siteObjects(sites []edgesite.Site, referenced map[string][]byte) ([]siteindex.Object, error) {
	objects := make([]siteindex.Object, 0, len(sites))
	for _, site := range sites {
		raw, err := edgesite.Encode(site)
		if err != nil {
			return nil, err
		}
		object, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
		if err != nil {
			return nil, err
		}
		object.Referenced = referenced
		objects = append(objects, object)
	}
	return objects, nil
}

// activate activates objects as the next generation and waits until every
// worker serves it.
func (instance *instance) activate(ctx context.Context, objects []siteindex.Object) error {
	activation, err := instance.activator.Activate(ctx, objects)
	if err == nil {
		_, err = instance.activator.WaitHealthy(ctx, activation.Generation, nil, 10*time.Second)
	}
	return err
}

// Publish converts the publication's document as Start does and activates
// its site objects in place: the agent's index-only activation (no reload).
// New certificate versions go into the TLS pool beside the previous ones,
// as dyntls.Pool.Sync keeps the previous generation's. A publication that
// changes the ports' profiles would need a reload and is refused.
func (instance *instance) Publish(ctx context.Context, publication edgegolden.Publication) error {
	next := *instance.scenario
	next.Facts.Document = publication.Document
	if publication.Certificates != nil {
		next.Facts.Node.Certificates = publication.Certificates
	}
	for _, dir := range []string{"bundle", "converted"} {
		if err := os.RemoveAll(filepath.Join(instance.root, dir)); err != nil {
			return err
		}
	}
	sites, referenced, err := buildSites(ctx, instance.env, &next, instance.root)
	if err != nil {
		return err
	}
	ports, err := edgesite.PortProfiles(sites)
	if err != nil {
		return err
	}
	if !sameSkeletonPorts(ports, instance.ports) {
		return fmt.Errorf("publication changes the port profiles %v -> %v (needs a reload)", instance.ports, ports)
	}
	// only versions the pool lacks, as dyntls.Pool.Sync copies new ones
	installed, err := (dyntls.Pool{Root: filepath.Join(instance.root, edgeskeleton.TLSPoolDirectory), GID: -1}).Versions()
	if err != nil {
		return err
	}
	var added []edgegolden.Certificate
	for _, certificate := range publication.Certificates {
		if !slices.Contains(installed, certificate.VersionID) {
			added = append(added, certificate)
		}
	}
	if err := installCertificates(instance.env, added, instance.root); err != nil {
		return err
	}
	objects, err := siteObjects(sites, referenced)
	if err != nil {
		return err
	}
	instance.scenario, instance.sites = &next, sites
	if err := instance.activate(ctx, objects); err != nil {
		return fmt.Errorf("activate: %w\nerror.log:\n%s", err, instance.errorLog())
	}
	return nil
}

// sameSkeletonPorts: the skeleton renders the same servers for both (it only
// needs SiteCount to be non-zero).
func sameSkeletonPorts(left, right []edgesite.PortProfile) bool {
	return slices.EqualFunc(left, right, func(a, b edgesite.PortProfile) bool {
		a.SiteCount, b.SiteCount = min(a.SiteCount, 1), min(b.SiteCount, 1)
		return a == b
	})
}

// installCertificates puts the scenario's site certificates into the TLS
// pool (D4) as the agent's dyntls.Pool.Sync does from the certificate store.
// The golden's certificates are leaves without the CA in the chain, as
// certstore keeps what the control plane sent.
func installCertificates(env edgegolden.Env, certificates []edgegolden.Certificate, root string) error {
	if len(certificates) == 0 {
		return nil
	}
	ca, err := env.PKI.CA("site")
	if err != nil {
		return err
	}
	pool := dyntls.Pool{Root: filepath.Join(root, edgeskeleton.TLSPoolDirectory), GID: -1}
	for _, certificate := range certificates {
		chain, key, err := ca.Issue(certificate.Serial, certificate.Names...)
		if err != nil {
			return err
		}
		if err := pool.PutCertificate(certificate.VersionID, chain, key); err != nil {
			return fmt.Errorf("certificate %s: %w", certificate.VersionID, err)
		}
	}
	return nil
}

func indexKeys(sites []edgesite.Site) int {
	keys := 0
	for _, site := range sites {
		keys += len(site.IndexEntries())
	}
	return keys
}

func waitControl(ctx context.Context, control *siteindex.Control) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := control.Status(ctx)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("control socket: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type instance struct {
	root, openresty string
	sites           []edgesite.Site
	pool            edgecache.Pool
	generations     *dyncache.Generations
	prewarmer       dyncache.Prewarmer
	registry        *dyntelemetry.Registry // D12 attribution, as the agent registers it
	offsets         map[string]int64       // where Logs stopped in each node-level log
	activator       *siteindex.Activator
	env             edgegolden.Env
	scenario        *edgegolden.Scenario
	ports           []edgesite.PortProfile // what the skeleton was rendered for
}

func (instance *instance) run(args ...string) error {
	command := exec.Command(instance.openresty, append([]string{"-p", instance.root + "/", "-c", "nginx.conf"}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("openresty %v: %v: %s", args, err, output)
	}
	return nil
}

func (instance *instance) errorLog() string {
	raw, _ := os.ReadFile(filepath.Join(instance.root, SharedDirectory, "error.log"))
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-30):], "\n")
}

// Logs: the node-level access and security logs (D12) written since the
// last logs step, each line turned back into its site's v7 line by the
// agent's dyntelemetry.Normalize (what the event spool receives).
func (instance *instance) Logs(context.Context) ([]edgegolden.LogRecord, error) {
	shared := filepath.Join(instance.root, SharedDirectory)
	sites := &dyntelemetry.ObjectSites{Root: filepath.Join(instance.root, "site-objects"), Limit: 1 << 20}
	var records []edgegolden.LogRecord
	for _, stream := range []string{"access", "security"} {
		access, security := edgeconfig.DynamicRoutingTelemetryPaths(shared)
		path := access
		if stream == "security" {
			path = security
		}
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		raw = raw[min(instance.offsets[path], int64(len(raw))):]
		instance.offsets[path] += int64(len(raw))
		for _, line := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			result, err := dyntelemetry.Normalize(line, instance.registry, sites, "")
			if err != nil {
				return nil, fmt.Errorf("%s log: %w\n%s", stream, err, line)
			}
			fields := map[string]any{}
			decoder := json.NewDecoder(bytes.NewReader(result.Line))
			decoder.UseNumber()
			if err := decoder.Decode(&fields); err != nil {
				return nil, err
			}
			records = append(records, edgegolden.LogRecord{Stream: stream, Fields: fields})
		}
	}
	return records, nil
}

// scopeVersions: the config version every scope of the scenario serves (the
// release's config_version_id, as the agent registers a publication).
func scopeVersions(scenario *edgegolden.Scenario, sites []edgesite.Site) map[string]string {
	var document struct {
		ConfigVersionID string `json:"config_version_id"`
	}
	_ = json.Unmarshal(scenario.Facts.Document, &document)
	versions := map[string]string{}
	for _, site := range sites {
		if document.ConfigVersionID != "" {
			versions[site.ConfigurationScopeID] = document.ConfigVersionID
		}
	}
	return versions
}

func (instance *instance) Stop(context.Context) error {
	raw, err := os.ReadFile(filepath.Join(instance.root, SharedDirectory, "nginx.pid"))
	if err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil {
			_ = syscall.Kill(pid, syscall.SIGQUIT)
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
				if syscall.Kill(pid, 0) != nil {
					break
				}
			}
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	return os.RemoveAll(instance.root)
}

// ConfigInput is what the renderer's node configuration depends on.
type ConfigInput struct {
	Root, LuaRoot string
	Ports         []edgesite.PortProfile
	NodeRegion    string
	// Node overrides the node settings (NodeRegion is ignored when set).
	Node      *edgeskeleton.Node
	IndexKeys int
	Workers   int // 0 = auto
	// Cache is the zone pool (D8); Zones 0 = no cache module.
	Cache edgecache.Pool
	// Challenges are the JS challenge versions the master preloads (D7).
	Challenges []edgesite.Ref
	// SystemCA is the CA bundle of trust "system" HTTPS origins ("" = the
	// node default).
	SystemCA string
	// HealthPort: the loopback health server (0 = none).
	HealthPort int
	// ManagedWAF is the managed WAF (D11, internal/dynwaf); nil = none.
	ManagedWAF *edgeskeleton.ManagedWAF
	// AutoDefense renders the auto defense gate (AD-04; the adaptive WAF
	// check writes overlay values through it).
	AutoDefense bool
	// UnknownSite is the node's domain mismatch page; nil = 421.
	UnknownSite *edgeskeleton.NodePage
	// Schedule302 renders HTTP 302 scheduling (edgeskeleton.Schedule302FromSites).
	Schedule302 bool
	// RulePlanRoot holds the rule pack mount plans (edgeskeleton
	// Paths.RulePlanRoot); "" = none.
	RulePlanRoot string
	// SiteGzip renders per-site gzip (edgeskeleton.SiteGzipFromSites).
	SiteGzip bool
	// Telemetry renders the node-level access/security logs (D12).
	Telemetry bool
}

// SharedDirectory (under Root) holds the error log, pid, temp and cache
// directories (the skeleton's Paths.SharedRoot); Root is the state root
// (run/, site-objects/, site-index/, tls-pool/, challenge/).
const SharedDirectory = "shared"

// Config is the node nginx.conf of a dynamic routing node: the node skeleton
// itself (libs/edgeconfig/edgeskeleton.Render, every phase through the
// cdnca_dynroute entry), with the placeholder certificate written under
// Root. Workers > 0 pins worker_processes (the skeleton takes it from the
// system configuration, which the golden has none of).
func Config(input ConfigInput) ([]byte, error) {
	node := edgeskeleton.Node{Region: input.NodeRegion, SystemCABundle: input.SystemCA}
	if input.Node != nil {
		node = *input.Node
	}
	certificate, key := filepath.Join(input.Root, "placeholder.crt"), filepath.Join(input.Root, "placeholder.key")
	if err := dyntls.WritePlaceholder(certificate, key, -1); err != nil {
		return nil, err
	}
	// logs/: nginx opens the prefix error log before reading error_log
	for _, dir := range []string{filepath.Join(SharedDirectory, "cache"), filepath.Join(SharedDirectory, filepath.FromSlash(edgeconfig.DynamicRoutingTelemetryDir)),
		"tls-pool", "run", edgeskeleton.SecurityFlushDirectory, "site-index", "site-objects", "logs"} {
		if err := os.MkdirAll(filepath.Join(input.Root, dir), 0o755); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		if err := os.MkdirAll(filepath.Join(input.Root, SharedDirectory, name+"-temp"), 0o755); err != nil {
			return nil, err
		}
	}
	// The trust placeholder must hold no tenant CA: the placeholder
	// certificate itself (fallback.invalid) is one.
	conf, err := edgeskeleton.Render(edgeskeleton.Input{Ports: input.Ports, IndexKeys: input.IndexKeys, Node: node,
		Cache: input.Cache, Challenges: input.Challenges, HealthPort: input.HealthPort, ManagedWAF: input.ManagedWAF,
		Schedule302: input.Schedule302, UnknownSite: input.UnknownSite, AutoDefense: input.AutoDefense, SiteGzip: input.SiteGzip, Telemetry: input.Telemetry,
		// the ACME overlay as v7 renders it (no token is ever published in
		// the golden: a matching token answers 404 from the empty overlay)
		ACMEOverlayRoot: input.Root,
		Paths: edgeskeleton.Paths{SharedRoot: filepath.Join(input.Root, SharedDirectory), LuaRoot: input.LuaRoot, StateRoot: input.Root,
			RulePlanRoot: input.RulePlanRoot, PlaceholderCertificate: certificate, PlaceholderKey: key, OriginTrustPlaceholder: certificate}})
	if err != nil {
		return nil, err
	}
	if input.Workers > 0 {
		conf = bytes.Replace(conf, []byte("worker_processes auto;\n"), []byte("worker_processes "+strconv.Itoa(input.Workers)+";\n"), 1)
	}
	return conf, nil
}
