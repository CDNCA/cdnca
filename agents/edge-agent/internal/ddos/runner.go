package ddos

import (
	"context"
	"os/exec"
	"path/filepath"
)

type systemRunner struct{ binary string }

// NewSystemRunner runs the nft binary at an absolute path.
func NewSystemRunner(binary string) (Runner, error) {
	if binary == "" || !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return nil, ErrInvalid
	}
	return systemRunner{binary: binary}, nil
}

func (runner systemRunner) Run(ctx context.Context, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, runner.binary, arguments...).Output()
}
