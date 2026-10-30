package siteindex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

var (
	ErrConflict = errors.New("site index: control conflict")
	ErrNoMemory = errors.New("site index: shared dictionary full")
)

// Control is the node-local control socket of the running OpenResty
// (contract §5.4).
type Control struct {
	client *http.Client
}

// NewControl dials socketPath for every request.
func NewControl(socketPath string) *Control {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	return &Control{client: &http.Client{Transport: transport, Timeout: 5 * time.Minute}}
}

// Status is GET /status.
type Status struct {
	Generation    uint64            `json:"gen"`
	Previous      uint64            `json:"prev_gen"`
	MaxGeneration uint64            `json:"max_gen"`
	Stage         uint64            `json:"stage"`
	Ports         string            `json:"ports"`
	Tags          int               `json:"tags"`
	TagsGen       uint64            `json:"tags_gen"`
	Capacity      int64             `json:"capacity_bytes"`
	Free          int64             `json:"free_bytes"`
	EpochOK       bool              `json:"epoch_ok"`
	Rebuild       *RebuildStatus    `json:"rebuild"`
	Workers       map[string]uint64 `json:"workers"`
}

type RebuildStatus struct {
	Generation uint64  `json:"gen"`
	Done       int64   `json:"done"`
	Total      int64   `json:"total"`
	Started    float64 `json:"started"`
	Finished   float64 `json:"finished"`
	Error      string  `json:"error"`
	Queued     bool    `json:"queued"`
}

// Probe is GET /probe: the request path's decision for (port, host).
type Probe struct {
	State      string `json:"state"`
	Matched    string `json:"matched"`
	Digest     string `json:"digest"`
	SiteID     string `json:"site_id"`
	Generation uint64 `json:"generation"`
}

type controlError struct {
	Error string `json:"error"`
}

func (c *Control) do(ctx context.Context, method, path string, body []byte, out any) error {
	request, err := http.NewRequestWithContext(ctx, method, "http://cdnca-site-admin"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("site index control %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode/100 != 2 {
		var detail controlError
		_ = json.Unmarshal(raw, &detail)
		message := fmt.Sprintf("site index control %s %s: %d %s", method, path, response.StatusCode, detail.Error)
		switch response.StatusCode {
		case http.StatusConflict:
			return fmt.Errorf("%w: %s", ErrConflict, message)
		case http.StatusInsufficientStorage:
			return fmt.Errorf("%w: %s", ErrNoMemory, message)
		}
		return errors.New(message)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("site index control %s %s: %w", method, path, err)
		}
	}
	return nil
}

func (c *Control) Status(ctx context.Context) (Status, error) {
	var status Status
	err := c.do(ctx, http.MethodGet, "/status", nil, &status)
	return status, err
}

func (c *Control) Stage(ctx context.Context, set ChangeSet) error {
	raw, err := MarshalChangeSet(set)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, "/stage", raw, nil)
}

func (c *Control) Commit(ctx context.Context, generation uint64) error {
	return c.do(ctx, http.MethodPost, "/commit?gen="+strconv.FormatUint(generation, 10), nil, nil)
}

func (c *Control) Abort(ctx context.Context, generation uint64) error {
	return c.do(ctx, http.MethodPost, "/abort?gen="+strconv.FormatUint(generation, 10), nil, nil)
}

func (c *Control) Rollback(ctx context.Context, generation uint64) error {
	return c.do(ctx, http.MethodPost, "/rollback?gen="+strconv.FormatUint(generation, 10), nil, nil)
}

func (c *Control) Rebuild(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/rebuild", nil, nil)
}

func (c *Control) Probe(ctx context.Context, port int, host string) (Probe, error) {
	var probe Probe
	query := url.Values{"port": {strconv.Itoa(port)}, "host": {host}}
	err := c.do(ctx, http.MethodGet, "/probe?"+query.Encode(), nil, &probe)
	return probe, err
}

// Activator moves the running node to a new index generation: it writes the
// objects and the index file first (so a cold start finds them), then
// activates through the control socket, and records the result as the
// current index file only when the node runs it.
type Activator struct {
	Control *Control
	Files   Files
	Objects ObjectDir
	// ChangeLimit splits large changes (contract §4.4); 0 = MaxChangeEntries.
	ChangeLimit int
	// Prepare, when set, runs before the node can serve any generation of
	// first..last (before the first stage or the rebuild); an error stops
	// the activation with nothing visible. Telemetry attribution
	// (dyntelemetry.Registry.Register) uses it so a log line of a new
	// generation always resolves.
	Prepare func(first, last uint64) error
	// LiveWorker, when set, tells whether a heartbeat's worker pid still
	// runs: Check ignores heartbeats of workers that exited (a reload's old
	// workers keep their key until its 10 s TTL). nil = every heartbeat
	// counts.
	LiveWorker func(pid string) bool
}

func (a *Activator) prepare(first, last uint64) error {
	if a.Prepare == nil {
		return nil
	}
	if err := a.Prepare(first, last); err != nil {
		return fmt.Errorf("prepare generations %d..%d: %w", first, last, err)
	}
	return nil
}

// Activation is what Activate did.
type Activation struct {
	Generation uint64
	Previous   uint64
	Changes    int
	ChangeSets int
	Rebuilt    bool
	Duration   time.Duration
	// Phases: build (index of the new generation, objects written), file
	// (index file written), node (stage + commit), cleanup (index files and
	// objects of dropped generations).
	Phases map[string]time.Duration
	// Probes is the health check of this activation (D13d-1): one probe per
	// site object the active generation did not have (added or changed);
	// every site on a rebuild. Removed and unchanged sites are not probed.
	Probes map[ProbeKey]string
}

// Activate makes objects the node's routing table. When the node's index is
// not the agent's last activated generation (cold start pending, dictionary
// lost, or a previous activation was interrupted) it activates by a full
// rebuild from the new index file instead of a change set.
func (a *Activator) Activate(ctx context.Context, objects []Object) (Activation, error) {
	started := time.Now()
	status, err := a.Control.Status(ctx)
	if err != nil {
		return Activation{}, err
	}
	if status.Stage != 0 {
		// An interrupted stage of ours: abort it, nothing is visible.
		if err := a.Control.Abort(ctx, status.Stage); err != nil {
			return Activation{}, err
		}
	}
	active, haveActive, err := a.Files.Current()
	if err != nil {
		haveActive = false
	}
	first := max(status.MaxGeneration, active.Generation) + 1
	next, err := Build(first, objects)
	if err != nil {
		return Activation{}, err
	}
	result := Activation{Previous: status.Generation, Phases: map[string]time.Duration{}}
	phase := time.Now()
	mark := func(name string) { result.Phases[name] = time.Since(phase); phase = time.Now() }
	consistent := haveActive && status.Generation == active.Generation && status.Generation != 0 && status.EpochOK
	// Objects of the active generation are in the directory already (kept
	// until the generation after next); only new digests are written.
	present := make(map[Digest]bool)
	if consistent {
		for _, entry := range active.Entries {
			present[entry.Digest] = true
		}
	}
	var changed []Object
	for _, object := range objects {
		if !present[object.Digest] {
			changed = append(changed, object)
		}
	}
	result.Probes = ProbesFor(changed)
	// Referenced objects (CC policies, HTTP policy entries, client CA, ...)
	// go in before any site object: a site never becomes routable before
	// what it reads. A caller that put them itself (gateway fetch) leaves
	// Object.Referenced empty; they must then be in the directory already.
	written := map[string]bool{}
	for _, object := range objects {
		for _, digest := range object.Site.ReferencedDigests() {
			if written[digest] {
				continue
			}
			if content, ok := object.Referenced[digest]; ok {
				if err := a.Objects.Put(digest, content); err != nil {
					return Activation{}, err
				}
			} else if _, err := os.Stat(a.Objects.Path(digest)); err != nil {
				return Activation{}, fmt.Errorf("%w: site %s references object %s that is neither supplied nor present", ErrFormat, object.Site.SiteID, digest)
			}
			written[digest] = true
		}
	}
	for _, object := range objects {
		if present[object.Digest] {
			continue
		}
		if err := a.Objects.Put(object.Digest.String(), object.Raw); err != nil {
			return Activation{}, err
		}
		present[object.Digest] = true
	}
	if !consistent {
		next.Generation = first
		if err := a.prepare(first, first); err != nil {
			return result, err
		}
		if err := a.rebuildTo(ctx, next); err != nil {
			return result, err
		}
		result.Generation, result.Rebuilt, result.Duration = next.Generation, true, time.Since(started)
		// Full sweep (rare: cold start, recovery): keep the site objects and
		// every object they reference (client CA, CC policies, error page
		// assets, ...), which the agent put before activating.
		keep := next.Digests()
		for digest := range referencedBy(objects) {
			keep = append(keep, digest)
		}
		_, err := a.Objects.Retain(keep)
		return result, err
	}
	sets, err := ChangeSets(active, next, first, a.ChangeLimit)
	if err != nil {
		return result, err
	}
	final := sets[len(sets)-1].Generation
	next.Generation = final
	if err := a.prepare(first, final); err != nil {
		return result, err
	}
	mark("build")
	// The index file of the final generation exists before any change, so a
	// restart in the middle rebuilds to a known whole state.
	if err := a.Files.Write(next); err != nil {
		return result, err
	}
	mark("file")
	for _, set := range sets {
		result.Changes += len(set.Changes)
		if err := a.Control.Stage(ctx, set); err != nil {
			if errors.Is(err, ErrNoMemory) {
				return result, fmt.Errorf("%w (generation %d; resize cdnca_site_index)", err, set.Generation)
			}
			return result, err
		}
		if err := a.Control.Commit(ctx, set.Generation); err != nil {
			return result, err
		}
		result.ChangeSets++
	}
	mark("node")
	dropped := a.droppedDigests(final, active.Generation)
	if err := a.Files.SetCurrent(final, active.Generation); err != nil {
		return result, err
	}
	err = a.release(dropped, next, active, objects)
	mark("cleanup")
	result.Generation, result.Duration = final, time.Since(started)
	return result, err
}

// rebuildTo writes index as the current file and has the node rebuild from
// it, waiting until it is active.
func (a *Activator) rebuildTo(ctx context.Context, index Index) error {
	if err := a.Files.Write(index); err != nil {
		return err
	}
	if err := a.Files.SetCurrent(index.Generation, 0); err != nil {
		return err
	}
	if err := a.Control.Rebuild(ctx); err != nil {
		return err
	}
	return a.WaitGeneration(ctx, index.Generation)
}

// WaitGeneration polls status until generation is active (a rebuild error
// ends the wait).
func (a *Activator) WaitGeneration(ctx context.Context, generation uint64) error {
	for {
		status, err := a.Control.Status(ctx)
		if err != nil {
			return err
		}
		if status.Generation == generation {
			return nil
		}
		if status.Rebuild != nil && status.Rebuild.Error != "" && (status.Rebuild.Generation == generation || status.Rebuild.Generation == 0) {
			return fmt.Errorf("site index rebuild: %s", status.Rebuild.Error)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// droppedDigests is the digests of the index files SetCurrent(final, keep)
// will delete: the objects only they referenced can go.
func (a *Activator) droppedDigests(final, keep uint64) map[Digest]bool {
	dropped := make(map[Digest]bool)
	for _, generation := range a.Files.generations() {
		if generation == final || generation == keep {
			continue
		}
		if index, err := a.Files.Read(generation); err == nil {
			for _, entry := range index.Entries {
				dropped[entry.Digest] = true
			}
		}
	}
	return dropped
}

// release removes the dropped site objects that neither the active nor the
// previous generation routes to, and the objects they referenced that no
// site of those two generations references any more. The referenced sets
// are cheap: the active generation's sites are in memory (objects), and the
// previous generation differs from it only by the sites this activation
// changed, read back from the object directory.
func (a *Activator) release(dropped map[Digest]bool, active, previous Index, objects []Object) error {
	for _, index := range []Index{active, previous} {
		for _, entry := range index.Entries {
			delete(dropped, entry.Digest)
		}
	}
	if len(dropped) == 0 {
		return nil
	}
	candidates := map[string]bool{}
	for digest := range dropped {
		if site, ok := a.readSite(digest); ok {
			for _, reference := range site.ReferencedDigests() {
				candidates[reference] = true
			}
		}
	}
	inUse := referencedBy(objects)
	routed := make(map[Digest]bool, len(active.Entries))
	for _, entry := range active.Entries {
		routed[entry.Digest] = true
	}
	for _, entry := range previous.Entries {
		if routed[entry.Digest] {
			continue
		}
		routed[entry.Digest] = true
		if site, ok := a.readSite(entry.Digest); ok {
			for _, reference := range site.ReferencedDigests() {
				inUse[reference] = true
			}
		}
	}
	for digest := range dropped {
		if err := a.Objects.Remove(digest.String()); err != nil {
			return err
		}
	}
	for reference := range candidates {
		if inUse[reference] {
			continue
		}
		if err := a.Objects.Remove(reference); err != nil {
			return err
		}
	}
	return nil
}

// readSite decodes a site object from the object directory.
func (a *Activator) readSite(digest Digest) (edgesite.Site, bool) {
	raw, err := os.ReadFile(a.Objects.Path(digest.String()))
	if err != nil {
		return edgesite.Site{}, false
	}
	object, err := DecodeObject(digest.String(), raw)
	if err != nil {
		return edgesite.Site{}, false
	}
	return object.Site, true
}

// referencedBy is every object digest the sites reference.
func referencedBy(objects []Object) map[string]bool {
	result := map[string]bool{}
	for _, object := range objects {
		for _, reference := range object.Site.ReferencedDigests() {
			result[reference] = true
		}
	}
	return result
}

// Rollback returns the node to the generation before the active one when the
// active one came from one change set (contract §4.3), else by rebuilding
// the previous index file.
func (a *Activator) Rollback(ctx context.Context) (uint64, error) {
	status, err := a.Control.Status(ctx)
	if err != nil {
		return 0, err
	}
	active, ok, err := a.Files.Current()
	if err != nil || !ok || active.Generation != status.Generation {
		return 0, fmt.Errorf("%w: node generation %d is not the agent's current index", ErrConflict, status.Generation)
	}
	if status.Previous != 0 && status.TagsGen == status.Generation {
		if _, err := a.Files.Read(status.Previous); err == nil {
			if err := a.Control.Rollback(ctx, status.Generation); err != nil {
				return 0, err
			}
			return status.Previous, a.Files.SetCurrent(status.Previous, active.Generation)
		}
	}
	return 0, fmt.Errorf("%w: generation %d has no single-step rollback", ErrConflict, status.Generation)
}

// RollbackTo returns the node to the routing table of index file
// generation target (kept by SetCurrent as the previous one) when no
// single-step rollback exists: it activates the difference as new
// generations (contract §4.3 item 3), without a rebuild.
func (a *Activator) RollbackTo(ctx context.Context, target uint64) (Activation, error) {
	started := time.Now()
	status, err := a.Control.Status(ctx)
	if err != nil {
		return Activation{}, err
	}
	active, ok, err := a.Files.Current()
	if err != nil || !ok || active.Generation != status.Generation || !status.EpochOK {
		return Activation{}, fmt.Errorf("%w: node generation %d is not the agent's current index", ErrConflict, status.Generation)
	}
	old, err := a.Files.Read(target)
	if err != nil {
		return Activation{}, err
	}
	first := max(status.MaxGeneration, active.Generation) + 1
	sets, err := ChangeSets(active, old, first, a.ChangeLimit)
	if err != nil {
		return Activation{}, err
	}
	final := Index{Generation: sets[len(sets)-1].Generation, Ports: old.Ports, Entries: old.Entries}
	if err := a.prepare(first, final.Generation); err != nil {
		return Activation{}, err
	}
	if err := a.Files.Write(final); err != nil {
		return Activation{}, err
	}
	result := Activation{Previous: status.Generation}
	for _, set := range sets {
		result.Changes += len(set.Changes)
		if err := a.Control.Stage(ctx, set); err != nil {
			return result, err
		}
		if err := a.Control.Commit(ctx, set.Generation); err != nil {
			return result, err
		}
		result.ChangeSets++
	}
	if err := a.Files.SetCurrent(final.Generation, active.Generation); err != nil {
		return result, err
	}
	result.Generation, result.Duration = final.Generation, time.Since(started)
	return result, nil
}

// Health is contract §5.6 for generation.
type Health struct {
	Healthy bool
	Reasons []string
	Status  Status
}

// Check reports whether generation is healthy: active, every live worker has
// seen it, no rebuild error, enough free dictionary space, and every probe
// (port, host -> want digest) selects the expected site.
func (a *Activator) Check(ctx context.Context, generation uint64, probes map[ProbeKey]string) (Health, error) {
	status, err := a.Control.Status(ctx)
	if err != nil {
		return Health{}, err
	}
	health := Health{Status: status}
	if status.Generation != generation {
		health.Reasons = append(health.Reasons, fmt.Sprintf("active generation %d, want %d", status.Generation, generation))
	}
	if len(status.Workers) == 0 {
		health.Reasons = append(health.Reasons, "no worker heartbeat")
	}
	for pid, seen := range status.Workers {
		if seen < generation && (a.LiveWorker == nil || a.LiveWorker(pid)) {
			health.Reasons = append(health.Reasons, fmt.Sprintf("worker %s at generation %d", pid, seen))
		}
	}
	if status.Rebuild != nil && status.Rebuild.Error != "" {
		health.Reasons = append(health.Reasons, "rebuild: "+status.Rebuild.Error)
	}
	if status.Capacity > 0 && status.Free*5 < status.Capacity {
		health.Reasons = append(health.Reasons, fmt.Sprintf("cdnca_site_index free %d of %d bytes", status.Free, status.Capacity))
	}
	failed, err := a.probe(ctx, probes)
	if err != nil {
		return health, err
	}
	health.Reasons = append(health.Reasons, failed...)
	health.Healthy = len(health.Reasons) == 0
	return health, nil
}

// probeConcurrency bounds the /probe requests in flight: a rebuild probes
// every site (10万站: 31.6 s one at a time).
const probeConcurrency = 16

// probe runs probes with bounded concurrency and returns the mismatches
// (sorted) or the first transport error.
func (a *Activator) probe(ctx context.Context, probes map[ProbeKey]string) ([]string, error) {
	if len(probes) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	keys := make(chan ProbeKey)
	var (
		mu       sync.Mutex
		failed   []string
		firstErr error
		wait     sync.WaitGroup
	)
	for range min(probeConcurrency, len(probes)) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for key := range keys {
				probe, err := a.Control.Probe(ctx, key.Port, key.Host)
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = err
					cancel()
				} else if err == nil && (probe.State != "ok" || probe.Digest != probes[key]) {
					failed = append(failed, fmt.Sprintf("probe %d %s: %s %s", key.Port, key.Host, probe.State, probe.Digest))
				}
				mu.Unlock()
			}
		}()
	}
send:
	for key := range probes {
		select {
		case keys <- key:
		case <-ctx.Done():
			break send
		}
	}
	close(keys)
	wait.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Strings(failed)
	return failed, nil
}

// WaitHealthy polls Check until generation is healthy or timeout passes
// (worker heartbeats are written once a second); it returns the last check.
// The probes run once the status part is healthy (or at the deadline), not
// on every poll.
func (a *Activator) WaitHealthy(ctx context.Context, generation uint64, probes map[ProbeKey]string, timeout time.Duration) (Health, error) {
	deadline := time.Now().Add(timeout)
	for {
		health, err := a.Check(ctx, generation, nil)
		if err == nil && (health.Healthy || time.Now().After(deadline)) && len(probes) > 0 {
			health, err = a.Check(ctx, generation, probes)
		}
		if err != nil || health.Healthy || time.Now().After(deadline) {
			return health, err
		}
		select {
		case <-ctx.Done():
			return health, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// ProbeKey is one (port, host) to probe.
type ProbeKey struct {
	Port int
	Host string
}

// ProbesFor is one probe per changed site: its first (port, name) with a
// wildcard replaced by a concrete label.
func ProbesFor(objects []Object) map[ProbeKey]string {
	probes := make(map[ProbeKey]string, len(objects))
	for _, object := range objects {
		entries := object.Site.IndexEntries()
		if len(entries) == 0 {
			continue
		}
		name := object.Site.Hosts.Primary
		if strings.HasPrefix(name, "*.") {
			name = "probe" + name[1:]
		}
		probes[ProbeKey{Port: object.Site.Listeners[0].Port, Host: name}] = object.Digest.String()
	}
	return probes
}

// ControlGet is a raw GET on the control socket (diagnostics and tests).
func ControlGet(ctx context.Context, socketPath, path string) ([]byte, error) {
	control := NewControl(socketPath)
	var raw json.RawMessage
	if err := control.do(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}
