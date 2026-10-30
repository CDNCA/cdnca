//go:build !linux

package toa

// Manager is a no-op outside Linux; the node never declares L4_TOA there.
type Manager struct{}

// Options mirror the Linux build.
type Options struct {
	OpenRestyBinary string
	ProcCgroup      string
	CgroupRoot      string
}

// Probe always reports TOA unsupported outside Linux.
func Probe(Options) *Manager { return &Manager{} }

// Status reports the unsupported platform.
func (*Manager) Status() Status { return Status{Reason: ErrUnsupported.Error()} }

// Stats is unavailable outside Linux.
func (*Manager) Stats() (Stats, error) { return Stats{}, ErrUnsupported }

// Close is a no-op.
func (*Manager) Close() {}
