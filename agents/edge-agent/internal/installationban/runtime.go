// Package installationban is the node side of the installation ban (ADR 0014
// §6, LIC-BAN-05). The node keeps the license service signed BanNotice and
// ServiceTicket its control plane forwarded (verified with its signer trust
// entries of usage installation-ban, never with a key the control plane
// chose). It stops serving only while a signed ban is in effect, or before the
// first ticket arrived (PF09). A ticket not renewed within the node offline
// tolerance (default 30 days, the controller's lease grace)
// freezes the node instead: existing sites keep serving, new publications,
// scaling and upgrades are refused (Frozen) and the receipt reports
// service_ticket_expired. Stopping keeps the site configuration, certificates
// and caches; resuming is one reload.
package installationban

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	transport "github.com/cdnca/cdnca/libs/edgeconfig/installationban"
	contract "github.com/cdnca/cdnca/libs/entitlement/installationban"
)

// Reasons a receipt refuses a document: the shared transport codes, which
// control-api classifies (transport.PermanentReason) to retry the same
// revision or not.
const (
	ReasonInvalid      = transport.ReasonInvalid
	ReasonUntrusted    = transport.ReasonUntrusted
	ReasonInstallation = transport.ReasonInstallation
	ReasonStale        = transport.ReasonStale
	ReasonConflict     = transport.ReasonConflict
	ReasonExpired      = transport.ReasonExpired
	ReasonPersistence  = transport.ReasonPersistence
	ReasonEnforce      = transport.ReasonEnforce
)

// Serving is what the runtime asks the node to do.
type Serving interface {
	// Stop switches every site server to the 503 page and refuses layer 4
	// (retryAfter zero = permanent); Resume restores the configuration.
	Stop(ctx context.Context, retryAfter time.Time) error
	Resume(ctx context.Context) error
}

type Config struct {
	// Dir holds state.json (0600).
	Dir            string
	InstallationID string
	// Keys are the node signer trust entries of usage installation-ban
	// (edgesignertrust.Document.InstallationBanKeys of the applied document).
	Keys    func() map[string]ed25519.PublicKey
	Serving Serving
	Now     func() time.Time
	Logger  *slog.Logger
}

type persisted struct {
	Schema string `json:"schema"`
	Notice []byte `json:"notice,omitempty"`
	Ticket []byte `json:"ticket,omitempty"`
	// HighWater is the latest wall clock the node saw (clock rollback).
	HighWater int64  `json:"high_water"`
	Stopped   bool   `json:"stopped"`
	Status    string `json:"status"`
}

const stateSchema = "cdnca.edge.installation-ban-state/v1"

type Runtime struct {
	config Config
	mu     sync.Mutex
	state  persisted
	notice *contract.BanNotice
	ticket *contract.ServiceTicket
}

func New(config Config) (*Runtime, error) {
	if !filepath.IsAbs(config.Dir) || filepath.Clean(config.Dir) != config.Dir || config.Keys == nil ||
		config.Serving == nil || config.InstallationID == "" {
		return nil, errors.New("installation ban runtime configuration is invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if err := os.MkdirAll(config.Dir, 0o700); err != nil {
		return nil, err
	}
	return &Runtime{config: config}, nil
}

func (runtime *Runtime) path() string { return filepath.Join(runtime.config.Dir, "state.json") }

// Restore loads the persisted documents (stored bytes are decoded, not
// re-verified against today's clock: they were verified when accepted) and
// enforces the resulting status, so a restart keeps the node stopped.
func (runtime *Runtime) Restore(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	content, err := os.ReadFile(runtime.path())
	switch {
	case errors.Is(err, os.ErrNotExist):
		runtime.state = persisted{Schema: stateSchema}
		if err := runtime.persist(); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		var state persisted
		if json.Unmarshal(content, &state) != nil || state.Schema != stateSchema {
			return fmt.Errorf("installation ban state %s is unreadable", runtime.path())
		}
		runtime.state = state
		if state.Notice != nil {
			signed, err := contract.DecodeNotice(state.Notice)
			if err != nil {
				return fmt.Errorf("installation ban state notice: %w", err)
			}
			runtime.notice = &signed.Body
		}
		if state.Ticket != nil {
			signed, err := contract.DecodeTicket(state.Ticket)
			if err != nil {
				return fmt.Errorf("installation ban state ticket: %w", err)
			}
			runtime.ticket = &signed.Body
		}
	}
	if runtime.state.Stopped {
		// the process restarted: the serving side forgot it is stopped (the
		// running configuration already is the maintenance one)
		runtime.state.Stopped = false
	}
	_, err = runtime.enforce(ctx)
	return err
}

// Result is one Apply's outcome (the receipt).
type Result struct {
	Applied bool
	Status  contract.Status
	Reason  string
}

// Apply verifies and keeps the delivered documents (either may be nil), then
// enforces the status. A refused document leaves the kept one in force.
func (runtime *Runtime) Apply(ctx context.Context, notice, ticket []byte) Result {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	now := runtime.config.Now()
	options := contract.VerifyOptions{Now: now, ExpectedInstallationID: runtime.config.InstallationID,
		Keys: runtime.config.Keys()}
	reason := ""
	next := runtime.state
	nextNotice, nextTicket := runtime.notice, runtime.ticket
	if notice != nil {
		body, why := accept(notice, runtime.state.Notice, func() (uint64, error) {
			verified, err := contract.VerifyNotice(notice, options)
			return verified.Revision, err
		})
		if why == "" {
			signed, _ := contract.DecodeNotice(notice)
			next.Notice, nextNotice = body, &signed.Body
		} else {
			reason = why
		}
	}
	if ticket != nil {
		body, why := accept(ticket, runtime.state.Ticket, func() (uint64, error) {
			verified, err := contract.VerifyTicket(ticket, options)
			return verified.Revision, err
		})
		if why == "" {
			signed, _ := contract.DecodeTicket(ticket)
			next.Ticket, nextTicket = body, &signed.Body
		} else if reason == "" {
			reason = why
		}
	}
	if !bytes.Equal(next.Notice, runtime.state.Notice) || !bytes.Equal(next.Ticket, runtime.state.Ticket) {
		previous := runtime.state
		runtime.state = next
		if err := runtime.persist(); err != nil {
			runtime.state = previous
			return Result{Status: runtime.status(now), Reason: ReasonPersistence}
		}
		runtime.notice, runtime.ticket = nextNotice, nextTicket
	}
	status, err := runtime.enforce(ctx)
	if err != nil && reason == "" {
		reason = ReasonEnforce
		runtime.config.Logger.Error("installation ban: could not enforce the node status", "status", status, "error", err)
	}
	return Result{Applied: reason == "", Status: status, Reason: reason}
}

// accept checks one document against the kept bytes of its kind.
func accept(encoded, kept []byte, verify func() (uint64, error)) ([]byte, string) {
	revision, err := verify()
	switch {
	case errors.Is(err, contract.ErrUntrusted):
		return nil, ReasonUntrusted
	case errors.Is(err, contract.ErrInstallationMatch):
		return nil, ReasonInstallation
	case errors.Is(err, contract.ErrTicketExpired):
		return nil, ReasonExpired
	case err != nil:
		return nil, ReasonInvalid
	}
	var keptRevision uint64
	var keptDigest [32]byte
	if kept != nil {
		keptDigest = contract.Digest(kept)
		if signed, err := contract.DecodeNotice(kept); err == nil {
			keptRevision = signed.Body.Revision
		} else if signed, err := contract.DecodeTicket(kept); err == nil {
			keptRevision = signed.Body.Revision
		}
	}
	switch contract.CheckRevision(keptRevision, keptDigest, revision, contract.Digest(encoded)) {
	case contract.ErrRevisionRollback:
		return nil, ReasonStale
	case contract.ErrRevisionConflict:
		return nil, ReasonConflict
	}
	return append([]byte(nil), encoded...), ""
}

// Tick re-evaluates the status (ticket expiry, a ban's until); the daemon
// calls it every minute.
func (runtime *Runtime) Tick(ctx context.Context) (contract.Status, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.enforce(ctx)
}

// Status is the enforced status now.
func (runtime *Runtime) Status() contract.Status {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.status(runtime.config.Now())
}

// Ticket is the kept ServiceTicket (nil before the first one); its times go
// into every receipt so the control plane shows each node's last ticket and
// the days left (PF09).
func (runtime *Runtime) Ticket() *contract.ServiceTicket {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.ticket == nil {
		return nil
	}
	ticket := *runtime.ticket
	return &ticket
}

// status: a node that never received a ticket does not serve (PF09, user
// 10-24 Q2: no install window; it opens when the first ticket arrives).
func (runtime *Runtime) status(now time.Time) contract.Status {
	highWater := time.Time{}
	if runtime.state.HighWater > 0 {
		highWater = time.Unix(runtime.state.HighWater, 0)
	}
	return contract.Evaluate(runtime.notice, runtime.ticket, now, highWater)
}

// Frozen reports whether the node refuses new publications, scaling and
// upgrades now (banned, no first ticket yet, or an expired ticket).
func (runtime *Runtime) Frozen() bool {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return contract.Frozen(runtime.status(runtime.config.Now()))
}

// enforce stops or resumes serving to match the status and keeps the clock
// high-water mark (a node clock set back cannot unfreeze its ticket). An
// expired ticket does not stop traffic.
func (runtime *Runtime) enforce(ctx context.Context) (contract.Status, error) {
	now := runtime.config.Now()
	status := runtime.status(now)
	stop := contract.StopsServing(status)
	var err error
	switch {
	case stop && !runtime.state.Stopped:
		err = runtime.config.Serving.Stop(ctx, runtime.retryAfter(status))
	case !stop && runtime.state.Stopped:
		err = runtime.config.Serving.Resume(ctx)
	}
	changed := false
	if err == nil && stop != runtime.state.Stopped {
		runtime.state.Stopped, changed = stop, true
		runtime.config.Logger.Warn("installation ban: node serving changed", "stopped", stop, "status", status)
	}
	if string(status) != runtime.state.Status {
		runtime.state.Status, changed = string(status), true
	}
	if now.Unix() > runtime.state.HighWater+int64(time.Minute/time.Second) {
		runtime.state.HighWater, changed = now.Unix(), true
	}
	if changed {
		if persistErr := runtime.persist(); persistErr != nil {
			err = errors.Join(err, persistErr)
		}
	}
	return status, err
}

func (runtime *Runtime) retryAfter(status contract.Status) time.Time {
	if status == contract.StatusBanned && runtime.notice != nil && runtime.notice.Until != nil {
		return time.Unix(*runtime.notice.Until, 0).UTC()
	}
	return time.Time{}
}

// RetryAfterHeader formats retryAfter as an HTTP date ("" when zero).
func RetryAfterHeader(retryAfter time.Time) string {
	if retryAfter.IsZero() {
		return ""
	}
	return retryAfter.UTC().Format(http.TimeFormat)
}

func (runtime *Runtime) persist() error {
	encoded, err := json.Marshal(runtime.state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(runtime.config.Dir, ".state-*.json")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, runtime.path())
}
