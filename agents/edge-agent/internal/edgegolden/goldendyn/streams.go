package goldendyn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// L4 forwards (gap-sweep G4): a scenario whose document carries v2 streams
// runs on the agent's own dynamic routing runtime (internal/dynroute, as the
// daemon's dynamicRoutingManager drives it) with the node's L4 runtime
// (l4runtime.Manager on a second OpenResty, cmd/edge-agent dynamicRoutingL4).
// The L4 runtime runs as root (its process identity checks, the fixed
// /var/lib/cdnca-edge dispatch and telemetry paths), so tests/edge-golden/
// run.sh runs these scenarios in a root container.

// l4DeploymentRoot is where the L4 runtime's compiled config writes its
// telemetry logs and dispatch sockets (l4runtime L4TelemetryLogPath,
// L4DispatchDirectory).
const l4DeploymentRoot = "/var/lib/cdnca-edge"

// streamsDocument is the part of the v2 document carrying L4 forwards.
type streamsDocument struct {
	ConfigurationScopeID string                    `json:"configuration_scope_id"`
	ConfigVersionID      string                    `json:"config_version_id"`
	SourceRevision       int64                     `json:"source_revision"`
	Streams              *edgeconfig.StreamRuntime `json:"streams"`
}

// streamsOf reports whether the document carries L4 forwards.
func streamsOf(raw json.RawMessage) bool {
	var document streamsDocument
	return json.Unmarshal(raw, &document) == nil && document.Streams != nil && len(document.Streams.StreamsV2) != 0
}

// l4Instance is a scenario on dynroute.Runtime + l4runtime.Manager.
type l4Instance struct {
	root      string
	runtime   *dynroute.Runtime
	manager   *l4runtime.Manager
	openresty *l4runtime.OpenResty
	l4State   string
	env       edgegolden.Env
	scenario  *edgegolden.Scenario
	certs     *goldenCertificates
}

func startStreams(ctx context.Context, env edgegolden.Env, scenario *edgegolden.Scenario, root string) (edgegolden.Instance, error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnsupported{"L4 forwards outside a root container (requires l4)"}
	}
	// root master, nobody workers (nginx's default user): the worker
	// readable files belong to the nobody group, as on a native node
	workerGID := -1
	if group, err := user.LookupGroup("nobody"); err == nil {
		workerGID, _ = strconv.Atoi(group.Gid)
	}
	// the workers traverse the run's directories to the state roots
	// (dynroute keeps those group nobody 0750)
	for _, dir := range []string{env.WorkDir, root} {
		if err := os.Chmod(dir, 0o711); err != nil {
			return nil, err
		}
	}
	instance := &l4Instance{root: root, env: env, scenario: scenario, l4State: filepath.Join(root, "l4")}
	openResty, err := l4runtime.NewOpenResty(env.OpenResty, filepath.Join(instance.l4State, "run", "nginx.pid"), 30*time.Second)
	if err != nil {
		return nil, err
	}
	instance.openresty = openResty
	if instance.manager, err = l4runtime.NewDeploymentManager(instance.l4State, openResty); err != nil {
		return nil, err
	}
	dns, err := l4runtime.NewDNSCoordinator(filepath.Join(instance.l4State, "dns"), noDNS{},
		func(context.Context, l4runtime.ListenerV2, []netip.Addr) error { return nil }, time.Now)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(l4DeploymentRoot, 0o700); err != nil {
		return nil, err
	}
	certificates := &goldenCertificates{root: filepath.Join(root, "certstore"), env: env}
	instance.certs = certificates
	instance.runtime, err = dynroute.New(dynroute.Config{StateRoot: filepath.Join(root, "node"), SharedRoot: filepath.Join(root, SharedDirectory),
		LuaRoot: env.LuaRoot, OpenResty: env.OpenResty, WorkerGID: workerGID, HealthPort: scenario.Facts.Node.HealthPort,
		Workers: max(scenario.Facts.Node.Workers, 1), Certificates: certificates, HealthTimeout: 20 * time.Second,
		L4: goldenL4{manager: instance.manager, dns: dns}, MuxRoot: filepath.Join(root, "mux")})
	if err != nil {
		return nil, err
	}
	if err := instance.Publish(ctx, edgegolden.Publication{Document: scenario.Facts.Document}); err != nil {
		_ = instance.Stop(ctx)
		return nil, err
	}
	return instance, nil
}

// Publish converts the document and applies it with its streams, as the
// daemon applies a dynamic routing release.
func (instance *l4Instance) Publish(ctx context.Context, publication edgegolden.Publication) error {
	next := *instance.scenario
	next.Facts.Document = publication.Document
	if publication.Certificates != nil {
		next.Facts.Node.Certificates = publication.Certificates
	}
	if err := instance.certs.put(next.Facts.Node.Certificates); err != nil {
		return err
	}
	values := instance.env.PKI.Placeholders()
	raw, err := edgegolden.Expand(next.Facts.Document, values)
	if err != nil {
		return fmt.Errorf("document: %w", err)
	}
	var document streamsDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return err
	}
	// the sites as the other scenarios convert them (the document without
	// its streams: Convert reads sites only)
	sites, referenced, err := buildSites(ctx, instance.env, &next, instance.root)
	if err != nil {
		return err
	}
	objects, err := siteObjects(sites, referenced)
	if err != nil {
		return err
	}
	input := dynroute.Input{Objects: objects, ScopeVersions: map[string]string{document.ConfigurationScopeID: document.ConfigVersionID}}
	if document.Streams != nil {
		input.Streams = []dynroute.ScopeStreams{{ScopeID: document.ConfigurationScopeID, ConfigVersionID: document.ConfigVersionID,
			Revision: document.SourceRevision, Runtime: *document.Streams}}
	}
	if _, err := instance.runtime.Apply(ctx, input); err != nil {
		return fmt.Errorf("dynamic routing apply: %w\nerror.log:\n%s", err, tail(filepath.Join(instance.root, SharedDirectory, "error.log")))
	}
	instance.scenario = &next
	return nil
}

func (instance *l4Instance) Logs(context.Context) ([]edgegolden.LogRecord, error) {
	return nil, ErrUnsupported{"logs in an L4 scenario"}
}

func (instance *l4Instance) CacheEntries(context.Context, string) ([]string, error) {
	return nil, ErrUnsupported{"cache in an L4 scenario"}
}

func (instance *l4Instance) Task(context.Context, edgegolden.TaskSpec) (*edgegolden.TaskResult, error) {
	return nil, ErrUnsupported{"cache tasks in an L4 scenario"}
}

func (instance *l4Instance) Stop(ctx context.Context) error {
	var errs []error
	if instance.runtime != nil {
		errs = append(errs, instance.runtime.Stop(ctx))
	}
	if instance.openresty != nil {
		errs = append(errs, instance.openresty.Stop(ctx, filepath.Join(instance.l4State, "current")))
	}
	errs = append(errs, os.RemoveAll(instance.root), os.RemoveAll(l4DeploymentRoot))
	return errors.Join(errs...)
}

func tail(path string) string {
	raw, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	return string(bytes.Join(lines[max(0, len(lines)-30):], []byte("\n")))
}

// goldenL4 is cmd/edge-agent dynamicRoutingL4 (telemetry directories
// prepared before the release).
type goldenL4 struct {
	manager *l4runtime.Manager
	dns     *l4runtime.DNSCoordinator
}

func (l4 goldenL4) Begin(ctx context.Context, versionID string) error {
	return l4.manager.BeginRelease(ctx, versionID)
}

func (l4 goldenL4) Apply(ctx context.Context, versionID string, config *l4runtime.ConfigV2) error {
	if config == nil {
		_, err := l4.manager.Apply(ctx, l4runtime.Config{SchemaVersion: l4runtime.SchemaVersionV1, VersionID: versionID,
			Listeners: []l4runtime.Listener{}, UpstreamPools: []l4runtime.UpstreamPool{}, DrainTimeoutMS: 30000})
		return err
	}
	for _, listener := range config.Listeners {
		version := listener.ConfigVersionID
		if version == "" {
			version = config.VersionID
		}
		path, err := l4runtime.L4TelemetryLogPathForConfigListener(l4DeploymentRoot, version, listener)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
	}
	_, err := l4.manager.ApplyV2(ctx, *config, l4.dns)
	return err
}

func (l4 goldenL4) Finish(ctx context.Context, versionID string, succeeded bool) error {
	return l4.manager.FinishRelease(ctx, versionID, succeeded)
}

type noDNS struct{}

func (noDNS) LookupIP(context.Context, string) (l4runtime.DNSLookupResult, error) {
	return l4runtime.DNSLookupResult{}, errors.New("the golden has no DNS")
}

// goldenCertificates is the node's certificate store for dynroute: the
// scenario's certificate versions issued by the run's site CA, resolved for
// any name of their site.
type goldenCertificates struct {
	root     string
	env      edgegolden.Env
	versions map[string]certstore.ResolvedCertificateVersion
}

func (store *goldenCertificates) put(certificates []edgegolden.Certificate) error {
	if len(certificates) == 0 {
		return nil
	}
	if store.versions == nil {
		store.versions = map[string]certstore.ResolvedCertificateVersion{}
	}
	ca, err := store.env.PKI.CA("site")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(store.root, 0o700); err != nil {
		return err
	}
	for _, certificate := range certificates {
		if _, ok := store.versions[certificate.VersionID]; ok {
			continue
		}
		chain, key, err := ca.Issue(certificate.Serial, certificate.Names...)
		if err != nil {
			return err
		}
		chainPath, keyPath := filepath.Join(store.root, certificate.VersionID+".crt"), filepath.Join(store.root, certificate.VersionID+".key")
		if err := os.WriteFile(chainPath, chain, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			return err
		}
		store.versions[certificate.VersionID] = certstore.ResolvedCertificateVersion{SiteID: certificate.SiteID,
			CertificateVersionID: certificate.VersionID, Domains: certificate.Names, CertificatePath: chainPath, PrivateKeyPath: keyPath,
			CertificateSHA256: sha256.Sum256(chain), PrivateKeySHA256: sha256.Sum256(key)}
	}
	return nil
}

func (store *goldenCertificates) ResolveCertificateVersion(_ context.Context, request certstore.CertificateResolveRequest) (certstore.ResolvedCertificateVersion, error) {
	version, ok := store.versions[request.CertificateVersionID]
	if !ok || version.SiteID != request.SiteID {
		return certstore.ResolvedCertificateVersion{}, fmt.Errorf("certificate version %s not delivered for site %s", request.CertificateVersionID, request.SiteID)
	}
	return version, nil
}

func (store *goldenCertificates) SetCertificateVersionReferences(context.Context, certstore.CertificateVersionReferences) error {
	return nil
}
