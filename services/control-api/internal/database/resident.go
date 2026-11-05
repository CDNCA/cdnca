package database

import (
	"slices"
	"strings"
	"sync"
	"time"
)

// Resident connections: sessions control-api keeps for
// a long time instead of a single query — LISTEN loops and session advisory
// locks. The pool monitor (internal/poolmon) subtracts the in-pool ones from
// MaxConns to show the share left for requests. Process-wide like the pool
// itself (database.Open is called once by serve).
type Resident struct {
	Name string `json:"name"`
	// InPool: the session still counts against MaxConns. A hijacked session
	// (pgxpool.Conn.Hijack) has left the pool and only uses a PostgreSQL
	// connection slot.
	InPool bool      `json:"in_pool"`
	Since  time.Time `json:"since"`
}

var residents = struct {
	sync.Mutex
	next int
	held map[int]Resident
}{held: map[int]Resident{}}

// HoldResident records a resident connection until the returned release is
// called (idempotent).
func HoldResident(name string, inPool bool) (release func()) {
	residents.Lock()
	residents.next++
	id := residents.next
	residents.held[id] = Resident{Name: name, InPool: inPool, Since: time.Now().UTC()}
	residents.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			residents.Lock()
			delete(residents.held, id)
			residents.Unlock()
		})
	}
}

// Residents lists the resident connections held now, by name then start.
func Residents() []Resident {
	residents.Lock()
	out := make([]Resident, 0, len(residents.held))
	for _, r := range residents.held {
		out = append(out, r)
	}
	residents.Unlock()
	slices.SortFunc(out, func(a, b Resident) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return a.Since.Compare(b.Since)
	})
	return out
}
