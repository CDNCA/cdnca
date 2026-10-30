package eventspool

import "context"

// ConnectionsAcknowledgedSequence is the durable queue cursor, not the source
// watermark. Pending records must replay from their first sequence after restart.
func (s *Spool) ConnectionsAcknowledgedSequence(ctx context.Context) (uint64, error) {
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
	if len(state.Entries) > 0 {
		return state.Entries[0].Sequence - 1, nil
	}
	return state.NextSequence - 1, nil
}
