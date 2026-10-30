package gateway

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
)

var ErrSessionSuperseded = errors.New("session superseded")

// SessionLease represents the process holding the current stream for a node.
// A distributed implementation can replace MemorySessionCoordinator without
// changing the stream protocol.
type SessionLease interface {
	ID() string
	Epoch() uint64
	Superseded() <-chan struct{}
	FencedSend(func() error) error
	Release()
}

type SessionCoordinator interface {
	Acquire(context.Context, string) (SessionLease, error)
}

type MemorySessionCoordinator struct {
	mu    sync.Mutex
	slots map[string]*sessionSlot
}

func NewMemorySessionCoordinator() *MemorySessionCoordinator {
	return &MemorySessionCoordinator{slots: make(map[string]*sessionSlot)}
}

func (c *MemorySessionCoordinator) Acquire(_ context.Context, nodeID string) (SessionLease, error) {
	c.mu.Lock()
	slot := c.slots[nodeID]
	if slot == nil {
		slot = &sessionSlot{}
		slot.cond = sync.NewCond(&slot.mu)
		c.slots[nodeID] = slot
	}
	c.mu.Unlock()

	slot.mu.Lock()
	if current := slot.current; current != nil {
		current.supersede()
		for current.inFlight != 0 {
			slot.cond.Wait()
		}
	}
	slot.epoch++
	lease := &memorySession{
		slot:  slot,
		id:    uuid.NewString(),
		epoch: slot.epoch,
		done:  make(chan struct{}),
	}
	slot.current = lease
	slot.mu.Unlock()
	return lease, nil
}

type sessionSlot struct {
	mu      sync.Mutex
	cond    *sync.Cond
	current *memorySession
	epoch   uint64
}

type memorySession struct {
	slot  *sessionSlot
	id    string
	epoch uint64
	done  chan struct{}
	once  sync.Once

	inFlight int
}

func (s *memorySession) ID() string                  { return s.id }
func (s *memorySession) Epoch() uint64               { return s.epoch }
func (s *memorySession) Superseded() <-chan struct{} { return s.done }
func (s *memorySession) supersede()                  { s.once.Do(func() { close(s.done) }) }

// FencedSend counts the callback as in flight without holding the slot lock
// during network I/O. Acquire fences new callbacks, then waits for callbacks
// that already started before it publishes the replacement lease.
func (s *memorySession) FencedSend(send func() error) error {
	s.slot.mu.Lock()
	if s.slot.current != s || sessionSuperseded(s) {
		s.slot.mu.Unlock()
		return ErrSessionSuperseded
	}
	s.inFlight++
	s.slot.mu.Unlock()

	err := send()

	s.slot.mu.Lock()
	s.inFlight--
	if s.inFlight == 0 {
		s.slot.cond.Broadcast()
	}
	s.slot.mu.Unlock()
	return err
}

func (s *memorySession) Release() {
	s.slot.mu.Lock()
	defer s.slot.mu.Unlock()
	if s.slot.current == s {
		s.supersede()
		s.slot.current = nil
		s.slot.cond.Broadcast()
	}
}
