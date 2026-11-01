package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/sshaccess"
)

// newSSHAccessRuntime wires "only the controller may SSH" (node-ssh-tab,
// SSH_ACCESS v1): the node's own nft table inet cdnca_ssh_access, state in
// stateRoot/state.json. Resume re-arms (or fires) the rollback timer of a
// revision applied before a restart, so an unconfirmed one is still
// removed on time; its report waits for the next session.
func newSSHAccessRuntime(ctx context.Context, nodeID, stateRoot string, findBinary func(string) (string, error)) (*gatewayclient.SSHAccessRuntime, error) {
	binary, err := findBinary("nft")
	if err != nil {
		return nil, err
	}
	runner, err := sshaccess.NewSystemRunner(binary)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create SSH access state directory: %w", err)
	}
	manager, err := sshaccess.NewManager(runner, filepath.Join(stateRoot, "state.json"), time.Now)
	if err != nil {
		return nil, err
	}
	runtime, err := gatewayclient.NewSSHAccessRuntime(nodeID, manager, time.Now)
	if err != nil {
		return nil, err
	}
	manager.OnRevert(runtime.Reverted)
	manager.Resume(ctx)
	return runtime, nil
}
