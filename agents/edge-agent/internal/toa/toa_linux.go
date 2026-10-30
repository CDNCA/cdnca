//go:build linux

package toa

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Built by bpf/build.sh; one object serves amd64 and arm64.
//
//go:embed bpf/toa.bpf.o
var bpfObject []byte

// Manager owns the loaded programs and their cgroup links. The links live as
// long as the agent process: the L4 OpenResty is its child and is stopped
// with it, so no pinning is needed.
type Manager struct {
	collection *ebpf.Collection
	links      []link.Link
	status     Status
}

// Options are inputs of Probe; empty fields use the real system.
type Options struct {
	OpenRestyBinary string
	ProcCgroup      string // default /proc/self/cgroup
	CgroupRoot      string // default /sys/fs/cgroup
}

// Probe checks the kernel and OpenResty, loads and attaches the programs, and
// runs a loopback self-test. On any failure it detaches everything and
// returns a not-ready Manager whose Status explains why.
func Probe(options Options) *Manager {
	manager := &Manager{}
	if err := manager.probe(options); err != nil {
		manager.Close()
		manager.status.Ready = false
		manager.status.Reason = err.Error()
		return manager
	}
	manager.status.Ready = true
	return manager
}

func (m *Manager) probe(options Options) error {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return fmt.Errorf("uname: %w", err)
	}
	m.status.Kernel = unix.ByteSliceToString(uname.Release[:])
	if ok, err := kernelAtLeast(m.status.Kernel, MinKernel); err != nil {
		return err
	} else if !ok {
		return ErrKernelTooOld
	}
	binary, err := os.ReadFile(options.OpenRestyBinary)
	if err != nil {
		return fmt.Errorf("read OpenResty binary: %w", err)
	}
	if !binaryHasDirective(binary) {
		return ErrNoProxyTOA
	}
	procCgroup, cgroupRoot := options.ProcCgroup, options.CgroupRoot
	if procCgroup == "" {
		procCgroup = "/proc/self/cgroup"
	}
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	content, err := os.ReadFile(procCgroup)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCgroupUnknown, err)
	}
	relative, err := cgroupV2Path(string(content))
	if err != nil {
		return err
	}
	m.status.Cgroup = filepath.Join(cgroupRoot, relative)

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return fmt.Errorf("parse TOA object: %w", err)
	}
	m.collection, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load TOA programs: %w", err)
	}
	for _, attach := range []struct {
		program string
		kind    ebpf.AttachType
	}{
		{"cdnca_toa_setsockopt", ebpf.AttachCGroupSetsockopt},
		{"cdnca_toa_sockops", ebpf.AttachCGroupSockOps},
	} {
		program := m.collection.Programs[attach.program]
		if program == nil {
			return fmt.Errorf("TOA object lacks %s", attach.program)
		}
		attached, err := link.AttachCgroup(link.CgroupOptions{Path: m.status.Cgroup, Attach: attach.kind, Program: program})
		if err != nil {
			return fmt.Errorf("attach %s to %s: %w", attach.program, m.status.Cgroup, err)
		}
		m.links = append(m.links, attached)
	}
	return m.selfTest()
}

// selfTest makes one loopback connection exactly like the patched stream
// proxy and requires the option to have been written on the handshake ACK.
// The agent runs in the attached cgroup, so the programs see this socket.
func (m *Manager) selfTest() error {
	before, err := m.Stats()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("self-test listen: %w", err)
	}
	defer listener.Close()
	go func() {
		if connection, err := listener.Accept(); err == nil {
			connection.Close()
		}
	}()
	var sockoptErr error
	dialer := net.Dialer{Timeout: 2 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
		return raw.Control(func(fd uintptr) {
			sockoptErr = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, SockoptName,
				string(EncodeSockopt(net.IPv4(192, 0, 2, 1), 65000)))
		})
	}}
	connection, err := dialer.Dial("tcp4", listener.Addr().String())
	if err != nil {
		return fmt.Errorf("self-test dial: %w", err)
	}
	connection.Close()
	if sockoptErr != nil {
		return fmt.Errorf("%w: setsockopt: %v", ErrSelfTest, sockoptErr)
	}
	after, err := m.Stats()
	if err != nil {
		return err
	}
	if after[StatStored] <= before[StatStored] || after[StatWritten] <= before[StatWritten] {
		return fmt.Errorf("%w (stored %d->%d, written %d->%d)", ErrSelfTest,
			before[StatStored], after[StatStored], before[StatWritten], after[StatWritten])
	}
	return nil
}

// Stats reads the per-CPU-free counters map.
func (m *Manager) Stats() (Stats, error) {
	var stats Stats
	if m == nil || m.collection == nil {
		return stats, errors.New("TOA programs are not loaded")
	}
	counters := m.collection.Maps["cdnca_toa_stats"]
	if counters == nil {
		return stats, errors.New("TOA object lacks cdnca_toa_stats")
	}
	for index := range stats {
		if err := counters.Lookup(uint32(index), &stats[index]); err != nil {
			return stats, fmt.Errorf("read TOA stat %d: %w", index, err)
		}
	}
	return stats, nil
}

// Status returns the probe outcome.
func (m *Manager) Status() Status {
	if m == nil {
		return Status{Reason: "TOA was not probed"}
	}
	return m.status
}

// Close detaches the programs; new upstream connections then carry no TOA
// (the patched proxy ignores the resulting ENOPROTOOPT).
func (m *Manager) Close() {
	if m == nil {
		return
	}
	for _, attached := range m.links {
		attached.Close()
	}
	m.links = nil
	if m.collection != nil {
		m.collection.Close()
		m.collection = nil
	}
}
