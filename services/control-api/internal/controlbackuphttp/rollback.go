package controlbackuphttp

// fix-migrollback: stop a running migration, roll back to this host, and the
// "is the new master already serving?" check that guards a rollback against
// two control planes writing at once.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nativebackup"
)

// NewMaster is what the console shows before a rollback.
type NewMaster struct {
	// Host is the target of the latest migration ("" = none recorded).
	Host  string `json:"host"`
	RunID string `json:"run_id,omitempty"`
	// Phase is the phase the migration reached; restored means the target may
	// hold data and run services.
	Phase    string `json:"phase,omitempty"`
	State    string `json:"state,omitempty"`
	Restored bool   `json:"restored"`
	// Reachable: the target answers as a control plane right now.
	Reachable bool `json:"reachable"`
	// DNSPointsToNew: the control domain resolves to the target.
	DNSPointsToNew bool `json:"dns_points_to_new"`
	// Serving = restored and (reachable or DNS points there); a rollback then
	// requires confirm_new_master_stopped.
	Serving         bool   `json:"serving"`
	ControlDomain   string `json:"control_domain,omitempty"`
	GatewayEndpoint string `json:"gateway_endpoint,omitempty"`
	// CleanCommand removes the restore from the target (run there as root).
	CleanCommand string `json:"clean_command,omitempty"`
	// Held: this host is under a migration hold (rollback available).
	Held bool `json:"held"`
}

func latestMigration(layout nativebackup.Layout) (nativebackup.Run, bool) {
	runs, _ := nativebackup.ListRuns(layout, 30)
	for _, run := range runs {
		if run.Kind == nativebackup.RequestMigrate {
			return run, true
		}
	}
	return nativebackup.Run{}, false
}

func (handler *Handler) newMaster(ctx context.Context) NewMaster {
	layout := handler.dependencies.Layout
	facts := handler.dependencies.Facts(ctx)
	view := NewMaster{ControlDomain: facts.ControlDomain, GatewayEndpoint: facts.GatewayEndpoint}
	if current, _ := (nativebackup.Freezer{Layout: layout}).Current(); current != nil && current.Mode == nativebackup.FreezeHold {
		view.Held = true
	}
	run, found := latestMigration(layout)
	if !found {
		return view
	}
	view.Host, view.RunID, view.Phase, view.State = run.Target, run.ID, run.Phase, string(run.State)
	// A finished migration (succeeded) passed restore even if an older agent
	// recorded no phase.
	view.Restored = nativebackup.PhaseReachedTarget(run.Phase) || run.State == nativebackup.RunSucceeded
	if view.Restored && run.BackupID != "" {
		if keys, err := nativebackup.LoadKeys(layout); err == nil {
			view.CleanCommand = nativebackup.TargetCleanCommand(run.BackupID, keys.Fingerprint())
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		view.Reachable = handler.dependencies.ProbeNewMaster(probeCtx, run.Target, facts.ControlDomain) == nil
	}()
	go func() {
		defer wait.Done()
		view.DNSPointsToNew = handler.dnsPointsTo(probeCtx, facts.ControlDomain, run.Target)
	}()
	wait.Wait()
	view.Serving = view.Restored && (view.Reachable || view.DNSPointsToNew)
	return view
}

// dnsPointsTo: the control domain resolves to the target (its address, or
// the addresses the target name resolves to).
func (handler *Handler) dnsPointsTo(ctx context.Context, domain, target string) bool {
	if domain == "" || target == "" {
		return false
	}
	domainAddresses, err := handler.dependencies.LookupHost(ctx, domain)
	if err != nil {
		return false
	}
	targetAddresses := []string{strings.Trim(target, "[]")}
	if net.ParseIP(targetAddresses[0]) == nil {
		if resolved, err := handler.dependencies.LookupHost(ctx, target); err == nil {
			targetAddresses = resolved
		}
	}
	for _, address := range domainAddresses {
		if slices.Contains(targetAddresses, address) {
			return true
		}
	}
	return false
}

// probeNewMaster asks the target's nginx for /health/ready with the control
// domain as SNI/Host. Any 2xx means a control plane is serving there. The
// certificate is not checked: this is a liveness signal, not trust.
func probeNewMaster(ctx context.Context, host, controlDomain string) error {
	if host == "" {
		return errors.New("no target")
	}
	serverName := controlDomain
	if serverName == "" {
		serverName = host
	}
	client := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: serverName, InsecureSkipVerify: true}, //nolint:gosec // liveness probe only
		Proxy:           nil,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(strings.Trim(host, "[]"), "443")+"/health/ready", nil)
	if err != nil {
		return err
	}
	request.Host = serverName
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return errors.New("target is not ready")
	}
	return nil
}

func (handler *Handler) stop(response http.ResponseWriter, request *http.Request, session identity.AuthenticatedSession, requestID, runID string) error {
	if err := handler.requireManage(session); err != nil {
		return err
	}
	run, err := nativebackup.ReadRun(handler.dependencies.Layout, runID)
	if err != nil {
		return fail(http.StatusNotFound, "control_backup_run_not_found")
	}
	if run.Kind != nativebackup.RequestMigrate || run.State != nativebackup.RunRunning {
		return fail(http.StatusConflict, "control_backup_not_stoppable")
	}
	// Stopping after the restore started aborts it: the target needs cleaning.
	abort := nativebackup.PhaseReachedTarget(run.Phase)
	if err := handler.dependencies.Audit(request.Context(), session, "control_backup.migrate_stop", runID, requestID, map[string]any{
		"target_host": run.Target, "phase": run.Phase, "abort": abort,
	}); err != nil {
		return err
	}
	if err := nativebackup.RequestStop(handler.dependencies.Layout, runID); err != nil {
		if errors.Is(err, nativebackup.ErrNotStoppable) {
			return fail(http.StatusConflict, "control_backup_not_stoppable")
		}
		return err
	}
	writeJSON(response, http.StatusAccepted, map[string]any{"data": map[string]any{"run_id": runID, "phase": run.Phase, "abort": abort}})
	return nil
}

func (handler *Handler) rollback(response http.ResponseWriter, request *http.Request, session identity.AuthenticatedSession, requestID string) error {
	if err := handler.requireManage(session); err != nil {
		return err
	}
	var body struct {
		Password                string `json:"password"`
		Confirm                 string `json:"confirm"`
		ConfirmNewMasterStopped bool   `json:"confirm_new_master_stopped"`
	}
	if err := decode(request, &body); err != nil {
		return fail(http.StatusBadRequest, "control_backup_invalid_request")
	}
	defer func() { body.Password = "" }()
	if body.Confirm != "rollback" {
		return fail(http.StatusBadRequest, "confirmation_mismatch")
	}
	if current, _ := (nativebackup.Freezer{Layout: handler.dependencies.Layout}).Current(); current == nil || current.Mode != nativebackup.FreezeHold {
		return fail(http.StatusConflict, "control_backup_not_held")
	}
	if handler.dependencies.VerifyPassword == nil {
		return fail(http.StatusServiceUnavailable, "control_backup_unavailable")
	}
	if !handler.passwordLimiter.allow(session.Principal.Username, handler.dependencies.Now()) {
		return fail(http.StatusTooManyRequests, "control_backup_rollback_rate_limited")
	}
	verified, err := handler.dependencies.VerifyPassword(request.Context(), session.Principal.Username, body.Password, audit.SourceIPFrom(request.Context()))
	if err != nil || verified.UserID != session.Principal.UserID {
		_ = handler.dependencies.Audit(request.Context(), session, "control_backup.rollback_request", "rollback", requestID,
			map[string]any{"result": "denied", "reason_code": "invalid_password"})
		return fail(http.StatusForbidden, "control_backup_password_invalid")
	}
	handler.passwordLimiter.reset(session.Principal.Username)
	master := handler.newMaster(request.Context())
	if master.Serving && !body.ConfirmNewMasterStopped {
		writeJSON(response, http.StatusConflict, map[string]any{"error": map[string]any{"code": "control_backup_new_master_serving",
			"request_id": requestID}, "data": master})
		return nil
	}
	return handler.submit(response, request, session, requestID, nativebackup.Request{Kind: nativebackup.RequestRollback}, map[string]any{
		"target_host": master.Host, "new_master_serving": master.Serving, "new_master_reachable": master.Reachable,
		"dns_points_to_new": master.DNSPointsToNew, "confirm_new_master_stopped": body.ConfirmNewMasterStopped,
	})
}

// passwordLimiter caps rollback password attempts per user in memory: the
// frozen console must not write a throttle row to the held database.
type passwordLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

const (
	rollbackAttempts = 5
	rollbackWindow   = 15 * time.Minute
)

func (limiter *passwordLimiter) allow(user string, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.failures == nil {
		limiter.failures = map[string][]time.Time{}
	}
	recent := limiter.failures[user][:0]
	for _, at := range limiter.failures[user] {
		if now.Sub(at) < rollbackWindow {
			recent = append(recent, at)
		}
	}
	if len(recent) >= rollbackAttempts {
		limiter.failures[user] = recent
		return false
	}
	limiter.failures[user] = append(recent, now)
	return true
}

func (limiter *passwordLimiter) reset(user string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	delete(limiter.failures, user)
}
