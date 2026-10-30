//go:build !linux

package xdp

import (
	"net/netip"
	"time"
)

// Options are inputs of Probe (see xdp_linux.go).
type Options struct {
	Disabled   bool
	Interfaces []string
	Modes      []Mode
	Kernel     string
}

// Manager without Linux: always nftables.
type Manager struct{ status Status }

func Probe(options Options) *Manager {
	if options.Disabled {
		return &Manager{status: Status{Mode: ModeDisabled, Reason: ReasonDisabled}}
	}
	return &Manager{status: fallback(ReasonUnsupportedOS, ErrUnsupported)}
}

func Uplinks() []string { return nil }

func (m *Manager) Status() Status {
	if m == nil {
		return Status{Mode: ModeNFTables, Reason: ReasonUnsupportedOS}
	}
	return m.status
}

func (m *Manager) Running() bool                                    { return false }
func (m *Manager) Fallback(string, error)                           {}
func (m *Manager) Reattach() error                                  { return ErrNoRetry }
func (m *Manager) Changed() <-chan struct{}                         { return nil }
func (m *Manager) Close()                                           {}
func (m *Manager) Configure(Config) error                           { return ErrNotRunning }
func (m *Manager) Verify() error                                    { return ErrNotRunning }
func (m *Manager) Ban([]netip.Addr, time.Time) error                { return ErrNotRunning }
func (m *Manager) BanPorts([]netip.Addr, []uint16, time.Time) error { return ErrNotRunning }
func (m *Manager) Block([]Block) error                              { return ErrNotRunning }
func (m *Manager) UnbanPorts(netip.Addr, []uint16) error            { return ErrNotRunning }
func (m *Manager) Unban([]netip.Addr) error                         { return ErrNotRunning }
func (m *Manager) Unblock([]netip.Prefix) error                     { return ErrNotRunning }
func (m *Manager) Sweep() (int, error)                              { return 0, ErrNotRunning }
func (m *Manager) Counters() ([]Counter, error)                     { return nil, ErrNotRunning }
func (m *Manager) SetSiteDrop(SiteDrop) error                       { return ErrNotRunning }
func (m *Manager) SiteDropCounters() (SiteDropCounters, error) {
	return SiteDropCounters{}, ErrNotRunning
}
