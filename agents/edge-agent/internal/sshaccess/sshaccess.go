// Package sshaccess applies "only the controller may SSH" on a node: its own
// nft table inet cdnca_ssh_access drops new TCP connections to the sshd port
// from any source outside the controller's egress addresses and the
// operator's allowlist. It does not touch inet cdnca_firewall (host rules)
// nor fail2ban's tables, and it never filters established connections (an
// open session survives turning it on).
//
// Applying it starts a rollback timer: unless Confirm is called within the
// window (the controller reached sshd again through the new rules), the
// table is removed by itself, so a wrong egress address cannot lock the
// operator out. The pending state is persisted so a restarted agent still
// reverts on time.
package sshaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	TableFamily = "inet"
	TableName   = "cdnca_ssh_access"
	// RollbackWindow without a confirmation reverts the table.
	RollbackWindow = 5 * time.Minute

	maxCIDRs = 80
)

var (
	ErrInvalidPolicy = errors.New("invalid SSH access policy")
	ErrStaleRevision = errors.New("SSH access revision must advance")
)

// Policy is the wanted state from the controller.
type Policy struct {
	Revision uint64   `json:"revision"`
	Enabled  bool     `json:"enabled"`
	SSHPort  uint16   `json:"ssh_port"`
	CIDRs    []string `json:"cidrs"`
}

// State is what the node runs.
type State struct {
	Policy      Policy     `json:"policy"`
	Applied     bool       `json:"applied"`
	Confirmed   bool       `json:"confirmed"`
	RevertAt    *time.Time `json:"revert_at,omitempty"`
	Reverted    bool       `json:"reverted,omitempty"`
	FailureCode string     `json:"failure_code,omitempty"`
}

// Runner runs nft with arguments; stdin is the batch (nft -f -).
type Runner interface {
	Run(ctx context.Context, stdin []byte, arguments ...string) error
}

// Normalize checks a policy and canonicalizes its networks.
func Normalize(policy Policy) (Policy, error) {
	if policy.Revision == 0 || policy.SSHPort == 0 {
		return Policy{}, ErrInvalidPolicy
	}
	if !policy.Enabled {
		return Policy{Revision: policy.Revision, SSHPort: policy.SSHPort, CIDRs: []string{}}, nil
	}
	if len(policy.CIDRs) == 0 || len(policy.CIDRs) > maxCIDRs {
		return Policy{}, ErrInvalidPolicy
	}
	seen := map[string]bool{}
	cidrs := []string{}
	for _, value := range policy.CIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || prefix != prefix.Masked() ||
			prefix.Addr().Is4() && prefix.Bits() < 16 || prefix.Addr().Is6() && prefix.Bits() < 32 {
			return Policy{}, ErrInvalidPolicy
		}
		if !seen[prefix.String()] {
			seen[prefix.String()] = true
			cidrs = append(cidrs, prefix.String())
		}
	}
	sort.Strings(cidrs)
	return Policy{Revision: policy.Revision, Enabled: true, SSHPort: policy.SSHPort, CIDRs: cidrs}, nil
}

// Batch is the nft batch for an enabled policy: the table is replaced
// atomically. Loopback is always accepted; established/related packets are
// left to every other table.
func Batch(policy Policy) []byte {
	var v4, v6 []string
	for _, cidr := range policy.CIDRs {
		if netip.MustParsePrefix(cidr).Addr().Is4() {
			v4 = append(v4, cidr)
		} else {
			v6 = append(v6, cidr)
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "add table %s %s\n", TableFamily, TableName)
	fmt.Fprintf(&out, "delete table %s %s\n", TableFamily, TableName)
	fmt.Fprintf(&out, "add table %s %s { comment \"cdnca ssh-access revision=%d\"; }\n", TableFamily, TableName, policy.Revision)
	fmt.Fprintf(&out, "add set %s %s allow_v4 { type ipv4_addr; flags interval; auto-merge; }\n", TableFamily, TableName)
	fmt.Fprintf(&out, "add set %s %s allow_v6 { type ipv6_addr; flags interval; auto-merge; }\n", TableFamily, TableName)
	if len(v4) > 0 {
		fmt.Fprintf(&out, "add element %s %s allow_v4 { %s }\n", TableFamily, TableName, strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&out, "add element %s %s allow_v6 { %s }\n", TableFamily, TableName, strings.Join(v6, ", "))
	}
	// Priority -20: before cdnca_firewall (-10), so its host allow rules
	// cannot reopen sshd; a drop in any base chain is final.
	fmt.Fprintf(&out, "add chain %s %s input { type filter hook input priority -20; policy accept; }\n", TableFamily, TableName)
	fmt.Fprintf(&out, "add rule %s %s input iifname \"lo\" accept\n", TableFamily, TableName)
	fmt.Fprintf(&out, "add rule %s %s input tcp dport %d ct state established,related accept\n", TableFamily, TableName, policy.SSHPort)
	fmt.Fprintf(&out, "add rule %s %s input tcp dport %d ip saddr @allow_v4 accept\n", TableFamily, TableName, policy.SSHPort)
	fmt.Fprintf(&out, "add rule %s %s input tcp dport %d ip6 saddr @allow_v6 accept\n", TableFamily, TableName, policy.SSHPort)
	fmt.Fprintf(&out, "add rule %s %s input tcp dport %d counter drop comment \"cdnca ssh-access\"\n", TableFamily, TableName, policy.SSHPort)
	return []byte(out.String())
}

// DeleteBatch removes the table (idempotent: add then delete).
func DeleteBatch() []byte {
	return []byte(fmt.Sprintf("add table %s %s\ndelete table %s %s\n", TableFamily, TableName, TableFamily, TableName))
}

// Manager keeps the node's state and its rollback timer.
type Manager struct {
	mu     sync.Mutex
	runner Runner
	path   string
	now    func() time.Time
	state  State
	timer  *time.Timer
	window time.Duration
	// onRevert is told (outside the lock) each time the rollback timer
	// removed an unconfirmed revision.
	onRevert func(State)
}

// OnRevert registers the rollback notification (call before Resume).
func (manager *Manager) OnRevert(notify func(State)) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.onRevert = notify
}

// NewManager loads the persisted state from path (a missing file is the
// initial state). A pending unconfirmed policy whose deadline passed while
// the agent was down is reverted by Resume.
func NewManager(runner Runner, path string, now func() time.Time) (*Manager, error) {
	if runner == nil || !filepath.IsAbs(path) {
		return nil, ErrInvalidPolicy
	}
	if now == nil {
		now = time.Now
	}
	manager := &Manager{runner: runner, path: path, now: now, window: RollbackWindow}
	encoded, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(encoded, &manager.state); err != nil {
			return nil, err
		}
	}
	return manager, nil
}

// Resume re-arms (or fires) the rollback timer of a pending policy.
func (manager *Manager) Resume(ctx context.Context) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.state.Applied && !manager.state.Confirmed && manager.state.RevertAt != nil {
		manager.armLocked(ctx, *manager.state.RevertAt)
	}
}

// State returns a copy of the current state.
func (manager *Manager) State() State {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.state
}

// Apply runs a newer revision. Turning it on (or changing it) starts the
// rollback timer; turning it off removes the table at once.
func (manager *Manager) Apply(ctx context.Context, policy Policy) (State, error) {
	normalized, err := Normalize(policy)
	if err != nil {
		return State{}, err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if normalized.Revision == manager.state.Policy.Revision && manager.state.Policy.Revision != 0 {
		return manager.state, nil
	}
	if normalized.Revision < manager.state.Policy.Revision {
		return State{}, ErrStaleRevision
	}
	manager.stopLocked()
	next := State{Policy: normalized}
	if !normalized.Enabled {
		if err := manager.runner.Run(ctx, DeleteBatch(), "-f", "-"); err != nil {
			next.FailureCode = "nft_delete_failed"
			manager.state = next
			_ = manager.saveLocked()
			return next, err
		}
		next.Confirmed = true
		manager.state = next
		return next, manager.saveLocked()
	}
	batch := Batch(normalized)
	if err := manager.runner.Run(ctx, batch, "-c", "-f", "-"); err != nil {
		next.FailureCode = "nft_check_failed"
		manager.state = next
		_ = manager.saveLocked()
		return next, err
	}
	revertAt := manager.now().Add(manager.window)
	next.Applied, next.RevertAt = true, &revertAt
	// Persist the deadline before the rules take effect: a crash right
	// after applying still reverts on restart.
	manager.state = next
	if err := manager.saveLocked(); err != nil {
		return next, err
	}
	if err := manager.runner.Run(ctx, batch, "-f", "-"); err != nil {
		next.Applied, next.RevertAt, next.FailureCode = false, nil, "nft_apply_failed"
		manager.state = next
		_ = manager.saveLocked()
		return next, err
	}
	manager.armLocked(ctx, revertAt)
	return next, nil
}

// Confirm keeps revision: the controller reached sshd through the rules.
func (manager *Manager) Confirm(revision uint64) (State, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if revision != manager.state.Policy.Revision || !manager.state.Applied || manager.state.Reverted {
		return manager.state, ErrStaleRevision
	}
	manager.stopLocked()
	manager.state.Confirmed, manager.state.RevertAt = true, nil
	return manager.state, manager.saveLocked()
}

func (manager *Manager) armLocked(ctx context.Context, at time.Time) {
	revision := manager.state.Policy.Revision
	delay := at.Sub(manager.now())
	if delay < 0 {
		delay = 0
	}
	manager.timer = time.AfterFunc(delay, func() { manager.revert(context.WithoutCancel(ctx), revision) })
}

func (manager *Manager) stopLocked() {
	if manager.timer != nil {
		manager.timer.Stop()
		manager.timer = nil
	}
}

// revert removes the table of an unconfirmed revision.
func (manager *Manager) revert(ctx context.Context, revision uint64) {
	manager.mu.Lock()
	reverted, notify := manager.revertLocked(ctx, revision)
	manager.mu.Unlock()
	if reverted != nil && notify != nil {
		notify(*reverted)
	}
}

func (manager *Manager) revertLocked(ctx context.Context, revision uint64) (*State, func(State)) {
	if manager.state.Policy.Revision != revision || manager.state.Confirmed || !manager.state.Applied {
		return nil, nil
	}
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := manager.runner.Run(runCtx, DeleteBatch(), "-f", "-"); err != nil {
		// Retry shortly: leaving the rules would be the lockout this timer prevents.
		manager.timer = time.AfterFunc(10*time.Second, func() { manager.revert(ctx, revision) })
		return nil, nil
	}
	manager.state.Applied, manager.state.Reverted, manager.state.RevertAt = false, true, nil
	manager.state.FailureCode = "confirmation_timeout"
	_ = manager.saveLocked()
	state := manager.state
	return &state, manager.onRevert
}

type systemRunner struct{ binary string }

// NewSystemRunner runs the nft binary at an absolute path.
func NewSystemRunner(binary string) (Runner, error) {
	if binary == "" || !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return nil, ErrInvalidPolicy
	}
	return systemRunner{binary: binary}, nil
}

func (runner systemRunner) Run(ctx context.Context, stdin []byte, arguments ...string) error {
	command := exec.CommandContext(ctx, runner.binary, arguments...)
	command.Stdin = bytes.NewReader(stdin)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("nft %s: %w: %.256s", strings.Join(arguments, " "), err, output)
	}
	return nil
}

func (manager *Manager) saveLocked() error {
	encoded, err := json.Marshal(manager.state)
	if err != nil {
		return err
	}
	temporary := manager.path + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, manager.path)
}
