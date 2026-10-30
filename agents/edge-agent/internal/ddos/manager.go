package ddos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
)

// Runner runs nft (firewall.Runner's shape): arguments only, never a shell.
type Runner interface {
	Run(context.Context, ...string) ([]byte, error)
}

var (
	ErrInvalid   = errors.New("invalid DDoS protection")
	ErrUnhealthy = errors.New("DDoS protection table does not match its spec")
)

// Manager owns inet cdnca_ddos. Apply is serialized; Ban only adds elements.
type Manager struct {
	mu      sync.Mutex
	runner  Runner
	scratch string
	// active is the spec the kernel runs (nil: no table).
	active *Spec
	// front is the NIC side filter mirroring the table (SetFront).
	front Front
	// own are the bans Ban wrote, until they end (RateBans does not report
	// them as kernel rate bans); at most MaxTrackedBans.
	own map[netip.Addr]time.Time
	// auto is the auto defense part every Apply adds (SetAutoDefense).
	auto *AutoDefense
	// siteDrop are the site drop ports (site_drop.go), outside the spec.
	siteDrop []uint16
}

// Front is the node XDP filter (xdp.Manager): it drops what it
// can of the table's spec at the NIC, before the table sees it. The table
// is always installed as well, so a front that is not running (or fails and
// falls back to nftables by itself) loses nothing.
type Front interface {
	Running() bool
	Configure(xdp.Config) error
	Ban([]netip.Addr, time.Time) error
	Unban([]netip.Addr) error
}

// SetFront mirrors the running spec (and every later Apply and Ban) to
// front.
func (manager *Manager) SetFront(front Front) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.front = front
	manager.configureFront()
}

// configureFront: errors are the front's (it falls back and reports).
func (manager *Manager) configureFront() {
	if manager.front == nil || !manager.front.Running() {
		return
	}
	if err := manager.front.Configure(manager.active.FrontConfig()); err != nil {
		slog.Warn("XDP filter not updated", "error", err)
	}
}

// FrontConfig is the part of spec the XDP filter enforces; the zero Config
// without a spec (only blocks and port bans).
func (spec *Spec) FrontConfig() xdp.Config {
	if spec == nil {
		return xdp.Config{}
	}
	ports := make([]xdp.PortRange, len(spec.Ports))
	for index, port := range spec.Ports {
		ports[index] = xdp.PortRange{First: port.First, Last: port.Last}
	}
	return xdp.ConfigOf(spec.protection(), ports, spec.Exempt)
}

const stateFile = "active.json"

// NewManager keeps its state (the applied spec) and nft batch files in
// stateRoot, a private directory. A table the previous Agent process applied
// is adopted when it still runs the recorded spec, so bans keep working
// across an Agent restart before the next release.
func NewManager(ctx context.Context, runner Runner, stateRoot string) (*Manager, error) {
	if runner == nil || !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return nil, err
	}
	manager := &Manager{runner: runner, scratch: stateRoot}
	if raw, err := os.ReadFile(filepath.Join(stateRoot, stateFile)); err == nil {
		var spec Spec
		if json.Unmarshal(raw, &spec) == nil {
			if listing, err := manager.running(ctx); err == nil && listing.digest == spec.Digest() {
				manager.active = &spec
				manager.auto = spec.Auto
			}
		}
	}
	return manager, nil
}

func (manager *Manager) saveState(spec *Spec) error {
	path := filepath.Join(manager.scratch, stateFile)
	if spec == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// Active is the spec the kernel runs, nil when none.
func (manager *Manager) Active() *Spec {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.active
}

// Apply makes the kernel run spec (nil removes the table). An unchanged spec
// whose table is intact is a no-op. A failed check leaves the running table
// as it was; nft applies a batch atomically.
func (manager *Manager) Apply(ctx context.Context, spec *Spec) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if spec != nil {
		copied := *spec
		copied.Auto = manager.auto
		spec = &copied
	}
	return manager.applyLocked(ctx, spec)
}

// applyLocked is Apply with the lock held and spec.Auto already set.
func (manager *Manager) applyLocked(ctx context.Context, spec *Spec) error {
	if spec == nil {
		batch := RemoveBatch()
		if len(manager.siteDrop) != 0 {
			// The site drop outlives the spec.
			batch = append(batch, siteDropBatch(manager.siteDrop)...)
		}
		if err := manager.runBatch(ctx, batch); err != nil {
			return err
		}
		manager.active = nil
		manager.configureFront()
		return manager.saveState(nil)
	}
	listing, err := manager.running(ctx)
	if err != nil {
		return err
	}
	if listing.digest == spec.Digest() {
		manager.active = spec
		manager.configureFront()
		return manager.saveState(spec)
	}
	if err := manager.runBatch(ctx, spec.Batch(listing.sets, listing.counterNames(), listing.chains)); err != nil {
		return err
	}
	if listing, err = manager.running(ctx); err != nil || listing.digest != spec.Digest() {
		return errors.Join(ErrUnhealthy, err)
	}
	manager.active = spec
	manager.configureFront()
	return manager.saveState(spec)
}

func (manager *Manager) runBatch(ctx context.Context, batch []byte) error {
	file, err := os.CreateTemp(manager.scratch, "ddos-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(batch); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if output, err := manager.runner.Run(ctx, "--check", "--file", file.Name()); err != nil {
		return fmt.Errorf("nft check: %w %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := manager.runner.Run(ctx, "--file", file.Name()); err != nil {
		return fmt.Errorf("nft apply: %w %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// tableListing is what running reads of the table.
type tableListing struct {
	sets   []string
	chains []string
	// autoCounters are the auto defense counter names (autodefense.go).
	autoCounters []string
	// digest names the spec the table runs ("" when absent or not ours).
	digest string
	// counters are the drop counters by kind.
	counters []DropCounter
}

func (listing tableListing) counterNames() []string {
	names := make([]string, len(listing.counters))
	for index, counter := range listing.counters {
		names[index] = dropCounterPrefix + counter.Kind
	}
	return append(names, listing.autoCounters...)
}

// DropCounter is one packet filter's drops since its counter was created
// (the class was turned on), across in-place updates.
type DropCounter struct {
	Kind    string `json:"kind"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// running lists the table (empty when absent).
func (manager *Manager) running(ctx context.Context) (tableListing, error) {
	output, err := manager.runner.Run(ctx, "--json", "list", "table", TableFamily, TableName)
	if err != nil {
		// Absent table: nft exits non-zero.
		return tableListing{}, nil
	}
	var listing struct {
		Objects []struct {
			Set *struct {
				Name string `json:"name"`
			} `json:"set,omitempty"`
			Chain *struct {
				Name string `json:"name"`
			} `json:"chain,omitempty"`
			Counter *struct {
				Name    string `json:"name"`
				Packets uint64 `json:"packets"`
				Bytes   uint64 `json:"bytes"`
			} `json:"counter,omitempty"`
			Rule *struct {
				Chain   string `json:"chain"`
				Comment string `json:"comment"`
			} `json:"rule,omitempty"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &listing); err != nil {
		return tableListing{}, fmt.Errorf("%w: %v", ErrUnhealthy, err)
	}
	var result tableListing
	for _, object := range listing.Objects {
		if object.Set != nil {
			result.sets = append(result.sets, object.Set.Name)
		}
		if object.Chain != nil {
			result.chains = append(result.chains, object.Chain.Name)
		}
		if counter := object.Counter; counter != nil && strings.HasPrefix(counter.Name, autoPrefix) {
			result.autoCounters = append(result.autoCounters, counter.Name)
		}
		if counter := object.Counter; counter != nil && strings.HasPrefix(counter.Name, dropCounterPrefix) {
			result.counters = append(result.counters, DropCounter{Kind: strings.TrimPrefix(counter.Name, dropCounterPrefix),
				Packets: counter.Packets, Bytes: counter.Bytes})
		}
		if object.Rule != nil && object.Rule.Chain == "input" && strings.HasPrefix(object.Rule.Comment, marker("")) {
			result.digest = strings.TrimPrefix(object.Rule.Comment, marker(""))
		}
	}
	sort.Slice(result.counters, func(i, j int) bool { return result.counters[i].Kind < result.counters[j].Kind })
	return result, nil
}

// DropCounters are the running table's packet filter counters, sorted by
// kind; none without a table.
func (manager *Manager) DropCounters(ctx context.Context) ([]DropCounter, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.active == nil {
		return nil, nil
	}
	listing, err := manager.running(ctx)
	if err != nil {
		return nil, err
	}
	return listing.counters, nil
}

// MaxBanSeconds bounds Ban (edgeconfig.DDoSMaxBanSeconds).
const MaxBanSeconds = 7 * 86400

// Ban adds clients to the ban sets for duration (IPv6 by /64). Exempt
// clients are skipped. Without a running table it does nothing: there is no
// set to add to and no protected port. Returns how many were banned.
func (manager *Manager) Ban(ctx context.Context, clients []netip.Addr, duration time.Duration) (int, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	seconds := int64(duration / time.Second)
	if seconds < 1 || seconds > MaxBanSeconds {
		return 0, ErrInvalid
	}
	if manager.active == nil || len(clients) == 0 {
		return 0, nil
	}
	banned, batch := manager.banBatch(clients, seconds, BanSetIPv4, BanSetIPv6)
	if batch == "" {
		return 0, nil
	}
	if err := manager.runBatch(ctx, []byte(batch)); err != nil {
		return 0, err
	}
	manager.rememberOwn(banned, time.Now().Add(duration))
	if manager.front != nil && manager.front.Running() {
		if err := manager.front.Ban(banned, time.Now().Add(duration)); err != nil {
			slog.Warn("XDP filter ban not written", "error", err)
		}
	}
	return len(banned), nil
}

// Unban deletes bans Ban wrote for clients (IPv6 by /64) from the ban sets
// and XDP (a person released them, auto defense ADR 0010 §7.4). A client
// Ban did not write (a kernel rate ban, another node source) is left alone;
// an element already gone is not an error. Returns how many were deleted.
func (manager *Manager) Unban(ctx context.Context, clients []netip.Addr) (int, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.active == nil || len(clients) == 0 {
		return 0, nil
	}
	now := time.Now()
	var removed []netip.Addr
	var failed error
	for _, client := range clients {
		client = client.Unmap()
		if !client.IsValid() {
			continue
		}
		bits, set := 32, BanSetIPv4
		if client.Is6() {
			bits, set = 64, BanSetIPv6
		}
		address := netip.PrefixFrom(client, bits).Masked().Addr()
		if end, ok := manager.own[address]; !ok || !end.After(now) {
			continue
		}
		// one batch per element: a batch is atomic and "delete element" fails
		// for an element the kernel timed out meanwhile, which must not keep
		// the others banned
		batch := fmt.Sprintf("delete element %s %s %s { %s }\n", TableFamily, TableName, set, address)
		if err := manager.runBatch(ctx, []byte(batch)); err != nil {
			failed = err
			continue
		}
		delete(manager.own, address)
		removed = append(removed, address)
	}
	if len(removed) == 0 {
		return 0, failed
	}
	if manager.front != nil && manager.front.Running() {
		if err := manager.front.Unban(removed); err != nil {
			slog.Warn("XDP filter unban not written", "error", err)
		}
	}
	return len(removed), failed
}

// BanGroup bans clients on one auto defense port group only (its ports and
// protocol; ad-16c): the group's ban sets, dropped in its counter chain. Exempt
// clients are skipped. A group the table does not run bans nothing. Not
// written to XDP (XDP has no port scope) nor reported as a rate ban.
func (manager *Manager) BanGroup(ctx context.Context, groupID string, clients []netip.Addr, duration time.Duration) (int, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	seconds := int64(duration / time.Second)
	if seconds < 1 || seconds > MaxBanSeconds {
		return 0, ErrInvalid
	}
	if manager.active == nil || manager.active.Auto == nil || len(clients) == 0 ||
		!slices.ContainsFunc(manager.active.Auto.Groups, func(group AutoGroup) bool { return group.ID == groupID }) {
		return 0, nil
	}
	token := GroupToken(groupID)
	banned, batch := manager.banBatch(clients, seconds, autoPrefix+"b4_"+token, autoPrefix+"b6_"+token)
	if batch == "" {
		return 0, nil
	}
	if err := manager.runBatch(ctx, []byte(batch)); err != nil {
		return 0, err
	}
	return len(banned), nil
}

// banBatch is the nft batch adding clients (IPv6 by /64, exempt and invalid
// ones left out) to the ban sets set4 / set6, and the banned addresses.
func (manager *Manager) banBatch(clients []netip.Addr, seconds int64, set4, set6 string) ([]netip.Addr, string) {
	var v4, v6 []string
	var banned []netip.Addr
	seen := map[netip.Prefix]bool{}
	for _, client := range clients {
		client = client.Unmap()
		if !client.IsValid() || client.IsUnspecified() || client.IsLoopback() || manager.active.exempt(client) {
			continue
		}
		bits := 32
		if client.Is6() {
			bits = 64
		}
		prefix := netip.PrefixFrom(client, bits).Masked()
		if seen[prefix] {
			continue
		}
		seen[prefix] = true
		banned = append(banned, prefix.Addr())
		element := fmt.Sprintf("%s timeout %ds", prefix.Addr(), seconds)
		if client.Is4() {
			v4 = append(v4, element)
		} else {
			v6 = append(v6, element)
		}
	}
	var batch strings.Builder
	// add element keeps an existing element's timeout; a ban that is already
	// there is not shortened (nor extended: nft cannot max two timeouts).
	if len(v4) != 0 {
		fmt.Fprintf(&batch, "add element %s %s %s { %s }\n", TableFamily, TableName, set4, strings.Join(v4, ", "))
	}
	if len(v6) != 0 {
		fmt.Fprintf(&batch, "add element %s %s %s { %s }\n", TableFamily, TableName, set6, strings.Join(v6, ", "))
	}
	return banned, batch.String()
}

func (spec *Spec) exempt(client netip.Addr) bool {
	for _, prefix := range spec.Exempt {
		if prefix.Contains(client) {
			return true
		}
	}
	return false
}
