// Package sched302runtime installs the node's HTTP 302 scheduling table
// where the OpenResty Lua reads it:
// <deployment_root>/schedule302/table.json, replaced by rename so a worker
// always reads one whole table (edge/openresty/sched302/cdnca_sched302.lua
// re-reads it within a second). No reload: tables change with node health.
package sched302runtime

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
)

// Runtime is the installed table of this node.
type Runtime struct {
	mu       sync.Mutex
	dir      string
	nodeID   string
	revision uint64
}

// New prepares <deploymentRoot>/schedule302 (0755: OpenResty workers read
// the table; it holds site signing keys, which only this node's workers
// need, so the file is 0644 inside an agent-owned directory like the IP
// library). The installed revision is read back so a restarted agent never
// installs an older table.
func New(deploymentRoot, nodeID string) (*Runtime, error) {
	if !filepath.IsAbs(deploymentRoot) || nodeID == "" {
		return nil, errors.New("schedule302 runtime needs an absolute deployment root and the node ID")
	}
	dir := filepath.Join(deploymentRoot, sched302.TableDirectory)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	runtime := &Runtime{dir: dir, nodeID: nodeID}
	if raw, err := os.ReadFile(runtime.Path()); err == nil {
		if table, err := sched302.Decode(raw); err == nil && table.NodeID == nodeID {
			runtime.revision = table.Revision
		}
	}
	return runtime, nil
}

// Path is the installed table.
func (runtime *Runtime) Path() string { return filepath.Join(runtime.dir, sched302.TableFile) }

// Revision is the installed table's revision (0 none).
func (runtime *Runtime) Revision() uint64 {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.revision
}

// Apply installs a verified table (gatewayclient checked the signature).
// A revision not newer than the installed one is ignored.
func (runtime *Runtime) Apply(table sched302.Table, encoded []byte) error {
	if table.NodeID != runtime.nodeID {
		return fmt.Errorf("schedule302 table belongs to node %s", table.NodeID)
	}
	canonical, err := sched302.Encode(table)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return errors.New("schedule302 table is not canonical")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if table.Revision <= runtime.revision {
		return nil
	}
	temporary, err := os.CreateTemp(runtime.dir, ".table-*.json")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, runtime.Path()); err != nil {
		return err
	}
	runtime.revision = table.Revision
	return nil
}
