// Package installationlock holds the process-wide installation lock (ADR 0014
// §5.2): while the license service bans this installation, or its lease is
// revoked or expired, control-api is read-only. The HTTP gate refuses writes
// and every background loop that changes state skips its round with Skip.
// It is a leaf package so any loop can check it without import cycles; the
// installationban runtime is the only writer.
package installationlock

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Reasons a control installation is locked.
const (
	ReasonBanned        = "installation_banned"
	ReasonLeaseRevoked  = "lease_revoked"
	ReasonLeaseExpired  = "lease_expired"
	ReasonTicketExpired = "service_ticket_expired"
)

// Lock is what the banner and the 423 body show. Until nil with Locked means
// permanent (or no known end for a lease reason).
type Lock struct {
	Locked     bool       `json:"locked"`
	Reason     string     `json:"reason,omitempty"`
	BanID      string     `json:"ban_id,omitempty"`
	ReasonCode string     `json:"reason_code,omitempty"`
	ReasonText string     `json:"reason_text,omitempty"`
	Until      *time.Time `json:"until,omitempty"`
	// Rebound: the license service answered master_ip_rebound — the license's
	// master IP was changed to another server, so this controller gets no new
	// lease or ticket (fix-ipswitch). Shown even before the lease runs out.
	Rebound bool `json:"rebound,omitempty"`
}

var (
	current atomic.Pointer[Lock]
	skipMu  sync.Mutex
	skipped = map[string]bool{}
)

// Set replaces the current lock (the installationban runtime).
func Set(lock Lock) {
	if !lock.Locked {
		lock = Lock{Rebound: lock.Rebound}
	}
	previous := current.Swap(&lock)
	if previous != nil && previous.Locked && !lock.Locked {
		skipMu.Lock()
		clear(skipped)
		skipMu.Unlock()
		slog.Info("installation lock lifted; background loops resume")
	}
}

// Current is the current lock (unlocked before the runtime ran once).
func Current() Lock {
	if lock := current.Load(); lock != nil {
		return *lock
	}
	return Lock{}
}

// Locked reports whether control-api is read-only now.
func Locked() bool { return Current().Locked }

// Skip is the one-line guard at the start of a background loop round that
// changes state (DNS sync, ACME, publication, billing): true while locked,
// logged once per loop per lock period. The loop keeps running, so it resumes
// by itself when the lock is lifted.
func Skip(loop string) bool {
	lock := Current()
	if !lock.Locked {
		return false
	}
	skipMu.Lock()
	first := !skipped[loop]
	skipped[loop] = true
	skipMu.Unlock()
	if first {
		slog.Warn("installation locked; background loop paused", "loop", loop, "reason", lock.Reason,
			"ban_id", lock.BanID)
	}
	return true
}
