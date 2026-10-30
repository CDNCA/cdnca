package eventspool

import (
	"context"
	"crypto/sha256"
	"encoding/json"
)

// CompleteSourceProof binds the durable tail cursor to a completely drained,
// unchanged private source. An absent source or partial line is not empty data.
func (t *Tailer) CompleteSourceProof(ctx context.Context) ([32]byte, error) {
	var zero [32]byte
	unlock, err := lockPrivateFile(ctx, t.lockPath, t.stateDevice)
	if err != nil {
		return zero, err
	}
	defer unlock()
	checkpoint, exists, err := t.loadCheckpoint()
	if err != nil {
		return zero, err
	}
	file, identity, err := openSource(t.config.SourcePath)
	if err != nil {
		return zero, err
	}
	defer file.Close()
	if !exists {
		if identity.size != 0 {
			return zero, ErrTailGap
		}
		checkpoint = tailCheckpoint{SchemaVersion: 1, SourcePath: t.config.SourcePath, Device: identity.device, Inode: identity.inode, Generation: 1}
	}
	if checkpoint.Device != identity.device || checkpoint.Inode != identity.inode || checkpoint.Offset != identity.size || !fingerprintMatches(file, checkpoint) {
		return zero, ErrTailGap
	}
	encoded, err := json.Marshal(checkpoint)
	if err != nil {
		return zero, err
	}
	return sha256.Sum256(append([]byte("cdnca.access-source.checkpoint/v1\x00"), encoded...)), nil
}

func (s *Spool) ConnectionsWatermark(ctx context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock(ctx)
	if err != nil {
		return 0, err
	}
	defer unlock()
	state, err := s.loadConnectionsStateLocked()
	if err != nil {
		return 0, err
	}
	return state.LastSourceWatermark, nil
}
