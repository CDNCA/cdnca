package main

import (
	"context"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4live"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4usage"
)

// l4UsageSource is the L4 runtime the in-progress usage checkpoints read
// (L4-USAGE-01): the active configuration's TCP sockets, the kernel's
// counters and the live session registry of the L4 OpenResty.
type l4UsageSource struct {
	manager *l4runtime.Manager
}

func (source *l4UsageSource) ledger(spoolRoot, nodeID string, maxBatch int) (*l4usage.Ledger, error) {
	directory := filepath.Join(spoolRoot, "state")
	if err := ensurePrivateDirectory(spoolRoot, directory); err != nil {
		return nil, err
	}
	return l4usage.New(l4usage.Config{
		StatePath: filepath.Join(directory, "l4-usage.json"), NodeID: nodeID, Now: time.Now, MaxBatch: maxBatch,
		Kernel: l4live.LinuxKernel{}, Registry: l4live.ControlRegistry{Path: l4runtime.L4ControlSocketPath},
		Sockets: func(ctx context.Context) (map[string]l4runtime.UsageSocketV2, error) {
			config, err := source.manager.ActiveConfigV2(ctx)
			if err != nil || config == nil {
				return nil, err
			}
			return l4runtime.UsageSocketsV2(*config), nil
		},
	})
}
