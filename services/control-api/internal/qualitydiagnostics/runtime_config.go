package qualitydiagnostics

import (
	"bytes"
	"crypto/sha256"
	"time"
)

type RuntimeConfig struct {
	CursorKey []byte
	Now       func() time.Time
}

type RuntimeDependencies struct {
	Authority FinalizedLatestStateAuthority
}

func NewRuntimeService(config RuntimeConfig, dependencies RuntimeDependencies) (*Service, error) {
	if len(config.CursorKey) < sha256.Size || len(config.CursorKey) > 128 {
		return nil, ErrInvalidConfiguration
	}
	reader, err := NewAuthorityReaderAdapter(dependencies.Authority)
	if err != nil {
		return nil, err
	}
	return NewService(reader, Config{Now: config.Now, CursorKey: bytes.Clone(config.CursorKey)})
}
