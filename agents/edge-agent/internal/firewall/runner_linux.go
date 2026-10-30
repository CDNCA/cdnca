//go:build linux

package firewall

import (
	"context"
	"os/exec"
	"path/filepath"
)

type systemRunner struct {
	binary string
}

func newSystemRunner(binary string) (Runner, error) {
	if binary == "" || !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return nil, ErrInvalidPath
	}
	return &systemRunner{binary: binary}, nil
}

func (r *systemRunner) Run(ctx context.Context, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, r.binary, arguments...).Output()
}
