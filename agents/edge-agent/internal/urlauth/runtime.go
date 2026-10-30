package urlauth

import (
	"fmt"
	"path/filepath"
)

type ArtifactRuntime struct {
	root string
}

func NewArtifactRuntime(root string) (*ArtifactRuntime, error) {
	if !cleanAbsoluteNonRoot(root) {
		return nil, invalid("URL auth runtime root must be a clean absolute non-root path")
	}
	return &ArtifactRuntime{root: root}, nil
}

func (runtime *ArtifactRuntime) InstallJSON(raw []byte, binding ArtifactBinding) (Publication, error) {
	if runtime == nil || !canonicalArtifactUUID(binding.PolicyID) {
		return Publication{}, invalid("URL auth runtime binding is invalid")
	}
	installer, err := NewArtifactInstaller(
		filepath.Join(runtime.root, "policies", binding.PolicyID),
		filepath.Join(runtime.root, "keys"),
	)
	if err != nil {
		return Publication{}, fmt.Errorf("initialize URL auth artifact installer: %w", err)
	}
	return installer.InstallJSON(raw, binding)
}
