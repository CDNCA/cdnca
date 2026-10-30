package nodesshinstall

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// progressPrefix marks install-node.sh's own log lines; nothing else of the
// remote output is kept (it could echo anything the shell printed).
const progressPrefix = "[cdnca-edge] "

// installStatePrefix / installerFirstTicketExitCode: install-node.sh
// wait_first_ticket ("[cdnca-edge] install-state: <state>", exit 3).
const (
	installStatePrefix           = progressPrefix + "install-state: "
	installerFirstTicketExitCode = 3
)

// Run claims pending jobs until ctx ends, at most `concurrency` at once.
func (service *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var running sync.WaitGroup
	defer running.Wait()
	slots := make(chan struct{}, concurrency)
	for {
		service.dispatch(ctx, slots, &running)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// dispatch starts jobs while a slot is free and a job is pending.
func (service *Service) dispatch(ctx context.Context, slots chan struct{}, running *sync.WaitGroup) {
	for {
		select {
		case slots <- struct{}{}:
		default:
			return
		}
		job, ok, err := service.claim(ctx)
		if err != nil || !ok {
			<-slots
			if err != nil && ctx.Err() == nil {
				service.logger.Warn("node SSH install claim failed", "error", err)
			}
			return
		}
		running.Add(1)
		go func(job claimed) {
			defer running.Done()
			defer func() { <-slots }()
			service.execute(ctx, job)
		}(job)
	}
}

// RunOnce claims and runs every pending job (tests).
func (service *Service) RunOnce(ctx context.Context) error {
	for {
		job, ok, err := service.claim(ctx)
		if err != nil || !ok {
			return err
		}
		service.execute(ctx, job)
	}
}

type claimed struct {
	id, scopeID, createdBy         uuid.UUID
	host, username, authKind, name string
	controlPlane, hostKey, keyID   string
	port, attempts                 int
	ciphertext                     []byte
	batchID                        uuid.UUID
}

func (service *Service) claim(ctx context.Context) (claimed, bool, error) {
	var job claimed
	now := service.now().UTC()
	err := service.pool.QueryRow(ctx, `UPDATE node_ssh_install_jobs SET state='running',lease_owner=$1,lease_until=$2,
			attempts=attempts+1,started_at=COALESCE(started_at,$3),updated_at=$3
		WHERE id=(SELECT id FROM node_ssh_install_jobs
			WHERE (state='pending' OR state='running' AND lease_until<$3) AND attempts<$4
			ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING id,scope_id,batch_id,created_by_user_id,host,port,username,auth_kind,node_name,
			control_plane,host_key_sha256,credential_key_id,credential_ciphertext,attempts`,
		service.worker, now.Add(leaseDuration), now, maxAttempts).Scan(&job.id, &job.scopeID, &job.batchID, &job.createdBy,
		&job.host, &job.port, &job.username, &job.authKind, &job.name, &job.controlPlane, &job.hostKey,
		&job.keyID, &job.ciphertext, &job.attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		// Jobs that ran out of attempts while running are failed.
		_, err = service.pool.Exec(ctx, `UPDATE node_ssh_install_jobs SET state='failed',failure_code='install_timeout',
			credential_key_id='',credential_ciphertext=NULL,finished_at=$1,lease_owner='',lease_until=NULL,updated_at=$1
			WHERE state='running' AND lease_until<$1 AND attempts>=$2`, now, maxAttempts)
		return claimed{}, false, err
	}
	return job, err == nil, err
}

func (service *Service) execute(ctx context.Context, job claimed) {
	defer clear(job.ciphertext)
	fail := func(code string) { service.finish(ctx, job, StateFailed, code) }
	credential, err := service.open(job.id, job.username, job.keyID, job.ciphertext)
	if err != nil {
		fail(FailCredential)
		return
	}
	defer clear([]byte(credential.Password))
	registration, err := service.registration.RegistrationCredential(ctx, node.Actor{UserID: job.createdBy, ScopeID: job.scopeID},
		"node-ssh-install/"+job.id.String())
	if err != nil {
		fail(FailRegistration)
		return
	}
	root := job.username == "root"
	command, err := InstallCommand(job.controlPlane, registration.Credential, job.host, job.name, root,
		!root && credential.Password != "")
	if err != nil {
		fail(FailInstall)
		return
	}
	sudoPassword := ""
	if !root {
		sudoPassword = credential.Password
	}
	stdin := InstallInput(registration.Credential, sudoPassword)
	defer clear(stdin)
	var mu sync.Mutex
	var lines []string
	installState := ""
	flush := func() {
		mu.Lock()
		pending := lines
		lines = nil
		mu.Unlock()
		if len(pending) > 0 {
			service.appendProgress(ctx, job.id, pending)
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, installTimeout)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	stopped := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				flush()
				if service.cancelled(ctx, job.id) {
					cancel()
				}
			case <-stopped:
				return
			}
		}
	}()
	err = service.dialer.Run(runCtx, job.host, job.port, credential, job.hostKey, command, stdin, func(line string) {
		line = strings.TrimSpace(line)
		// Keep only the installer's own lines; never echo a secret.
		if !strings.HasPrefix(line, progressPrefix) || strings.Contains(line, registration.Credential) ||
			credential.Password != "" && strings.Contains(line, credential.Password) {
			return
		}
		if len(line) > maxProgressBytes {
			line = line[:maxProgressBytes]
		}
		mu.Lock()
		lines = append(lines, line)
		if state, ok := strings.CutPrefix(line, installStatePrefix); ok {
			installState = strings.TrimSpace(state)
		}
		mu.Unlock()
	})
	ticker.Stop()
	close(stopped)
	flush()
	if service.cancelled(ctx, job.id) {
		return
	}
	mu.Lock()
	finalState := installState
	mu.Unlock()
	switch {
	case err == nil:
		service.finish(ctx, job, StateSucceeded, "")
	case installedNotServing(err, finalState) != "":
		// Installed, enrolled and connected, but not serving yet: not
		// initialized, waiting for the first license ticket, installation
		// banned, or ticket expired.
		// The node serves once the cause is fixed (not a failure).
		service.finish(ctx, job, StateSucceeded, installedNotServing(err, finalState))
	case errors.Is(err, errHostKeyMismatch):
		fail(FailHostKeyMismatch)
	case isAuthFailure(err):
		fail(FailAuth)
	case errors.Is(err, context.DeadlineExceeded):
		fail(FailTimeout)
	case isNetwork(err):
		if job.attempts < maxAttempts {
			service.retry(ctx, job)
			return
		}
		fail(FailUnreachable)
	default:
		fail(FailInstall)
	}
}

// installedNotServing: install-node.sh exits with FIRST_TICKET_EXIT_CODE and
// prints "install-state: <state>" as its last state line when the Agent runs
// but the node does not serve: installed_pending_initialization (registered as
// pending, not initialized yet), installed_pending_ticket (no first
// ServiceTicket yet), installed_banned, installed_ticket_expired,
// installed_resume_failed (ticket valid, resuming the servers failed). It returns
// that state as the job's result code, or "" for any other outcome.
func installedNotServing(err error, installState string) string {
	var exit interface{ ExitStatus() int }
	if !errors.As(err, &exit) || exit.ExitStatus() != installerFirstTicketExitCode {
		return ""
	}
	switch installState {
	case ResultPendingInitialization, ResultPendingTicket, ResultBanned, ResultTicketExpired, ResultResumeFailed:
		return installState
	}
	return ""
}

func isAuthFailure(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unable to authenticate")
}

func isNetwork(err error) bool {
	var netErr net.Error
	var opErr *net.OpError
	return errors.As(err, &netErr) || errors.As(err, &opErr) || errors.Is(err, errBlockedAddress)
}

func (service *Service) cancelled(ctx context.Context, jobID uuid.UUID) bool {
	var state string
	if err := service.pool.QueryRow(ctx, `SELECT state FROM node_ssh_install_jobs WHERE id=$1`, jobID).Scan(&state); err != nil {
		return false
	}
	return state == StateCancelled
}

func (service *Service) appendProgress(ctx context.Context, jobID uuid.UUID, lines []string) {
	_, _ = service.pool.Exec(ctx, `UPDATE node_ssh_install_jobs SET progress=(
			SELECT COALESCE(array_agg(line ORDER BY position),'{}') FROM (
				SELECT line,position FROM unnest(progress || $2::text[]) WITH ORDINALITY AS item(line,position)
				ORDER BY position DESC LIMIT $3) newest),
		updated_at=$4 WHERE id=$1 AND state='running'`, jobID, lines, MaxProgressLines, service.now().UTC())
}

func (service *Service) retry(ctx context.Context, job claimed) {
	_, _ = service.pool.Exec(ctx, `UPDATE node_ssh_install_jobs SET state='pending',lease_owner='',lease_until=NULL,updated_at=$2
		WHERE id=$1 AND state='running'`, job.id, service.now().UTC())
}

// finish ends a job, wipes its secret, links the node the install
// registered (by the target IP) and audits the outcome.
func (service *Service) finish(ctx context.Context, job claimed, state, code string) {
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		now := service.now().UTC()
		command, err := tx.Exec(ctx, `UPDATE node_ssh_install_jobs SET state=$2,failure_code=$3,credential_key_id='',
			credential_ciphertext=NULL,finished_at=$4,lease_owner='',lease_until=NULL,updated_at=$4,
			node_id=CASE WHEN $2='succeeded' THEN (SELECT node.id FROM nodes node WHERE node.scope_id=$5
				AND (host(node.ipv4)=$6 OR host(node.ipv6)=$6) ORDER BY node.created_at DESC LIMIT 1) END
			WHERE id=$1 AND state='running'`, job.id, state, code, now, job.scopeID, job.host)
		if err != nil || command.RowsAffected() != 1 {
			return err
		}
		result := "success"
		if state == StateFailed {
			result = "failure"
		}
		extra := map[string]any{"attempts": job.attempts}
		if state == StateSucceeded && code != "" {
			extra["install_state"] = code
		}
		view := Job{ID: job.id, BatchID: job.batchID, Host: job.host, Port: job.port, Username: job.username}
		reason := code
		if state == StateSucceeded {
			reason = ""
		}
		return service.audit(ctx, tx, Actor{ScopeID: job.scopeID}, "node.ssh_install."+state, view, result, reason, extra)
	})
	if err != nil && ctx.Err() == nil {
		service.logger.Warn("node SSH install finish failed", "job_id", job.id, "error", err)
	}
}
