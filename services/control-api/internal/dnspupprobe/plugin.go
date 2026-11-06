package dnspupprobe

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PermissionPluginRequest lets a plugin's API key run probes with the
// platform's dnspup quota (migration 638; granted to tenant_owner).
const PermissionPluginRequest = "probes.dnspup.request"

const (
	pluginRequestTTL  = 24 * time.Hour
	pluginPollEvery   = 2 * time.Second
	checkpointsMaxAge = 5 * time.Minute
	maxExpect         = 20
	// DiagnosePoints bounds an mtr diagnosis (mtr is 100 packets per point).
	DiagnosePoints = 2
)

// Plugin API errors (handler: pluginError).
var (
	ErrPluginIdentity    = errors.New("dnspup plugin API requires an API key bound to an enabled plugin installation")
	ErrNotInstalled      = errors.New("module.probe.dnspup is not active on this platform")
	ErrNotConfigured     = errors.New("dnspup probe plugin is not enabled or has no key pair")
	ErrPaused            = errors.New("dnspup probe source is paused")
	ErrPluginRateLimited = errors.New("dnspup plugin probe rate limit reached")
	ErrPluginQuota       = errors.New("dnspup plugin probe quota used")
	ErrTargetRestricted  = errors.New("dnspup refused the probe target")
	ErrRequestNotFound   = errors.New("dnspup probe request not found")
)

// Availability reasons (GET /v1/probe-dnspup/plugin/status).
const (
	ReasonNotInstalled  = "probe_dnspup_not_installed"
	ReasonNotConfigured = "probe_dnspup_not_configured"
	ReasonPaused        = "probe_dnspup_paused"
)

// PluginStatus answers whether probes can run now (not metered).
type PluginStatus struct {
	Available   bool       `json:"available"`
	Reason      string     `json:"reason,omitempty"`
	PausedUntil *time.Time `json:"paused_until,omitempty"`
	// PerMinute and TenantMonthly are the limits this installation runs under.
	PerMinute     int   `json:"per_minute"`
	TenantMonthly int64 `json:"tenant_monthly"`
	UsedThisMonth int64 `json:"used_this_month"`
}

// ProbeInput is POST /v1/probe-dnspup/plugin/requests.
type ProbeInput struct {
	Type      string    `json:"type"` // tcping / ping / http / https / dns
	Target    string    `json:"target"`
	Port      int       `json:"port,omitempty"`
	Method    string    `json:"method,omitempty"`
	Record    string    `json:"record,omitempty"`
	Expect    []string  `json:"expect,omitempty"`
	IPVersion string    `json:"ip_version,omitempty"`
	Selection Selection `json:"selection"`
}

// DiagnoseInput is POST /v1/admin/probe-dnspup/diagnoses (mtr).
type DiagnoseInput struct {
	Target      string     `json:"target"`
	NodeID      *uuid.UUID `json:"node_id,omitempty"`
	Checkpoints []string   `json:"checkpoints"`
}

// ProbeRequestView is a request and, once done, its checkpoints.
type ProbeRequestView struct {
	ID         uuid.UUID        `json:"id"`
	Status     string           `json:"status"` // pending / completed / failed
	Type       string           `json:"type"`
	Target     string           `json:"target"`
	ErrorCode  string           `json:"error_code,omitempty"`
	CreatedAt  time.Time        `json:"created_at"`
	Results    []CheckpointView `json:"results"`
	Traces     json.RawMessage  `json:"traces,omitempty"`
	RetryAfter time.Duration    `json:"-"`
}

// PluginActor is an authenticated plugin API key.
type PluginActor struct {
	ScopeID, UserID, KeyID uuid.UUID
	Permissions            []string
}

type pluginIdentity struct {
	installationID uuid.UUID
	perMinute      int
	tenantMonthly  int64
}

func validHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return address.IsGlobalUnicast() && !address.IsPrivate()
	}
	return len(host) <= 253 && strings.Contains(host, ".") && strings.IndexFunc(host, func(r rune) bool {
		return !(r == '.' || r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) < 0
}

// dnspupRequest validates input and builds the dnspup body (https is http
// with an https:// URL).
func (input ProbeInput) dnspupRequest() (ProbeRequest, error) {
	request := ProbeRequest{Type: input.Type, Target: strings.TrimSpace(input.Target), IPVersion: input.IPVersion}
	if request.IPVersion == "" {
		request.IPVersion = "4"
	}
	if input.Selection.PointsPerGroup == 0 {
		input.Selection.PointsPerGroup = 3
	}
	if request.IPVersion != "4" && request.IPVersion != "6" || input.Selection.Validate() != nil || len(input.Expect) > maxExpect {
		return request, ErrInvalidInput
	}
	switch input.Type {
	case "tcping":
		if !validHost(request.Target) || input.Port < 1 || input.Port > 65535 {
			return request, ErrInvalidInput
		}
		request.Port, request.Count = input.Port, 4
	case "ping":
		if !validHost(request.Target) {
			return request, ErrInvalidInput
		}
		request.Count = 4
	case "http", "https":
		parsed, err := url.Parse(request.Target)
		method := strings.ToUpper(input.Method)
		if method == "" {
			method = "GET"
		}
		if err != nil || parsed.Scheme != input.Type || parsed.User != nil || !validHost(parsed.Hostname()) ||
			len(request.Target) > 2048 || method != "GET" && method != "HEAD" {
			return request, ErrInvalidInput
		}
		request.Type, request.Method = "http", method
	case "dns":
		record := strings.ToUpper(input.Record)
		if record == "" {
			record = "A"
		}
		if !validHost(request.Target) || net.ParseIP(request.Target) != nil ||
			!slices.Contains([]string{"A", "AAAA", "CNAME", "MX", "NS", "TXT"}, record) {
			return request, ErrInvalidInput
		}
		request.Record, request.IPVersion = record, ""
	default:
		return request, ErrInvalidInput
	}
	return request, nil
}

// availability reads whether dnspup can run now and the purposes' gates.
func (service *Service) availability(ctx context.Context, tx pgx.Tx) (stored, PurposesView, string, *time.Time, error) {
	value, err := readSettings(ctx, tx, false)
	if err != nil {
		return value, PurposesView{}, "", nil, err
	}
	var paused *time.Time
	if err := tx.QueryRow(ctx, `SELECT paused_until FROM probe_dnspup_state WHERE singleton`).Scan(&paused); err != nil {
		return value, PurposesView{}, "", nil, err
	}
	licensed, err := service.licensed(ctx, tx)
	switch {
	case err != nil:
		return value, PurposesView{}, "", nil, err
	case !licensed:
		return value, PurposesView{}, ReasonNotInstalled, nil, nil
	case !value.Enabled || value.Ciphertext == nil || value.KeyID == nil:
		return value, PurposesView{}, ReasonNotConfigured, nil, nil
	case paused != nil && paused.After(service.now()):
		return value, PurposesView{}, ReasonPaused, paused, nil
	}
	purposes, err := readPurposes(ctx, tx, service.now())
	return value, purposes, "", nil, err
}

func reasonError(reason string) error {
	switch reason {
	case ReasonNotInstalled:
		return ErrNotInstalled
	case ReasonNotConfigured:
		return ErrNotConfigured
	case ReasonPaused:
		return ErrPaused
	}
	return nil
}

// pluginOf checks the key's probe permission and its enabled installation.
func pluginOf(ctx context.Context, tx pgx.Tx, actor PluginActor) (pluginIdentity, error) {
	if actor.ScopeID == uuid.Nil || actor.KeyID == uuid.Nil {
		return pluginIdentity{}, ErrUnauthenticated
	}
	if !slices.Contains(actor.Permissions, PermissionPluginRequest) {
		return pluginIdentity{}, ErrPermissionDenied
	}
	var identity pluginIdentity
	var installation *uuid.UUID
	var status *string
	err := tx.QueryRow(ctx, `SELECT key.plugin_installation_id,head.status,settings.plugin_per_minute,settings.plugin_tenant_monthly
		FROM api_keys key
		LEFT JOIN plugin_installation_heads head ON head.tenant_scope_id=key.scope_id
		 AND head.authorization_id=key.plugin_installation_authorization_id
		CROSS JOIN probe_dnspup_settings settings
		WHERE key.id=$1 AND key.scope_id=$2 AND settings.singleton`, actor.KeyID, actor.ScopeID).Scan(
		&installation, &status, &identity.perMinute, &identity.tenantMonthly)
	if errors.Is(err, pgx.ErrNoRows) {
		return pluginIdentity{}, ErrUnauthenticated
	}
	if err != nil {
		return pluginIdentity{}, err
	}
	if installation == nil || status == nil || *status != "enabled" {
		return pluginIdentity{}, ErrPluginIdentity
	}
	identity.installationID = *installation
	return identity, nil
}

// PluginStatus serves GET /v1/probe-dnspup/plugin/status.
func (service *Service) PluginStatus(ctx context.Context, actor PluginActor) (PluginStatus, error) {
	var status PluginStatus
	err := pgx.BeginTxFunc(ctx, service.config.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		identity, err := pluginOf(ctx, tx, actor)
		if err != nil {
			return err
		}
		status.PerMinute, status.TenantMonthly = identity.perMinute, identity.tenantMonthly
		if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(requests),0) FROM probe_dnspup_plugin_usage
			WHERE month=$1 AND tenant_scope_id=$2`, monthOf(service.now()), actor.ScopeID).Scan(&status.UsedThisMonth); err != nil {
			return err
		}
		_, purposes, reason, until, err := service.availability(ctx, tx)
		if err != nil {
			return err
		}
		if reason == "" && purposeStopped(purposes, PurposePlugin) {
			reason = "probe_dnspup_quota_exceeded"
		}
		status.Available, status.Reason, status.PausedUntil = reason == "", reason, until
		return nil
	})
	return status, err
}

func purposeStopped(view PurposesView, purpose string) bool {
	for _, item := range view.Purposes {
		if item.Purpose == purpose {
			return item.Gate.Stopped
		}
	}
	return false
}

type pendingRequest struct {
	id      uuid.UUID
	kind    string
	request ProbeRequest
	pick    Selection
	ids     []string
	value   stored
	created time.Time
}

// CreatePluginRequest serves POST /v1/probe-dnspup/plugin/requests: limits
// are checked and counted in one transaction, then the dnspup job is
// created (Idempotency-Key per installation; the same key and body answers
// the existing request).
func (service *Service) CreatePluginRequest(ctx context.Context, actor PluginActor, key string, input ProbeInput) (ProbeRequestView, error) {
	if !validKey(key) {
		return ProbeRequestView{}, ErrInvalidInput
	}
	request, err := input.dnspupRequest()
	if err != nil {
		return ProbeRequestView{}, err
	}
	if input.Selection.PointsPerGroup == 0 {
		input.Selection.PointsPerGroup = 3
	}
	digest := requestDigest("plugin_probe", input)
	now := service.now()
	pending := pendingRequest{id: uuid.New(), kind: input.Type, request: request, pick: input.Selection, created: now}
	var existing *uuid.UUID
	err = pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		identity, err := pluginOf(ctx, tx, actor)
		if err != nil {
			return err
		}
		var storedID uuid.UUID
		var storedDigest []byte
		err = tx.QueryRow(ctx, `SELECT id,request_digest_sha256 FROM probe_dnspup_plugin_requests
			WHERE origin='plugin' AND installation_id=$1 AND idempotency_key=$2`, identity.installationID, key).Scan(&storedID, &storedDigest)
		switch {
		case err == nil && string(storedDigest) != string(digest[:]):
			return ErrIdempotency
		case err == nil:
			existing = &storedID
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		value, purposes, reason, _, err := service.availability(ctx, tx)
		if err != nil {
			return err
		}
		if reason != "" {
			return reasonError(reason)
		}
		if purposeStopped(purposes, PurposePlugin) {
			return ErrPluginQuota
		}
		pending.value = value
		// Serialise one installation's admissions so the per-minute count holds.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,638))`, identity.installationID); err != nil {
			return err
		}
		var recent int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM probe_dnspup_plugin_requests WHERE installation_id=$1
			AND created_at>$2`, identity.installationID, now.Add(-time.Minute)).Scan(&recent); err != nil {
			return err
		}
		if recent >= identity.perMinute {
			return ErrPluginRateLimited
		}
		var used int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(requests),0) FROM probe_dnspup_plugin_usage
			WHERE month=$1 AND tenant_scope_id=$2`, monthOf(now), actor.ScopeID).Scan(&used); err != nil {
			return err
		}
		if identity.tenantMonthly > 0 && used >= identity.tenantMonthly {
			return ErrPluginQuota
		}
		if _, err := tx.Exec(ctx, `INSERT INTO probe_dnspup_plugin_usage(month,tenant_scope_id,installation_id,requests)
			VALUES($1,$2,$3,1) ON CONFLICT (month,tenant_scope_id,installation_id) DO UPDATE
			SET requests=probe_dnspup_plugin_usage.requests+1`, monthOf(now), actor.ScopeID, identity.installationID); err != nil {
			return err
		}
		raw, _ := json.Marshal(input)
		_, err = tx.Exec(ctx, `INSERT INTO probe_dnspup_plugin_requests(id,origin,tenant_scope_id,installation_id,api_key_id,
			idempotency_key,request_digest_sha256,request,status,created_at,expires_at)
			VALUES($1,'plugin',$2,$3,$4,$5,$6,$7,'pending',$8,$9)`, pending.id, actor.ScopeID, identity.installationID, actor.KeyID,
			key, digest[:], raw, now, now.Add(pluginRequestTTL))
		return err
	})
	if err != nil {
		return ProbeRequestView{}, err
	}
	if existing != nil {
		return service.GetPluginRequest(ctx, actor, *existing)
	}
	return service.launch(ctx, pending, ConsumerPlugin)
}

// checkpointsFor lists the key's checkpoints, cached for checkpointsMaxAge
// (GET /v1/nodes shares the per-key read limit with job polling).
func (service *Service) checkpointsFor(ctx context.Context, prober *Prober) ([]Checkpoint, error) {
	service.mu.Lock()
	if service.checkpoints != nil && service.now().Sub(service.checkpointsAt) < checkpointsMaxAge &&
		service.checkpointsRevision == service.loaded {
		cached := service.checkpoints
		service.mu.Unlock()
		return cached, nil
	}
	service.mu.Unlock()
	checkpoints, err := prober.client.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	service.mu.Lock()
	service.checkpoints, service.checkpointsAt, service.checkpointsRevision = checkpoints, service.now(), service.loaded
	service.mu.Unlock()
	return checkpoints, nil
}

// launch creates the dnspup job of a stored pending request and records its
// id (or the failure).
func (service *Service) launch(ctx context.Context, pending pendingRequest, consumer string) (ProbeRequestView, error) {
	ctx = context.WithoutCancel(ctx)
	view := ProbeRequestView{ID: pending.id, Status: "pending", Type: pending.kind, Target: pending.request.Target,
		CreatedAt: pending.created, Results: []CheckpointView{}, RetryAfter: pluginPollEvery}
	prober, err := service.proberFor(pending.value)
	if err != nil {
		return service.failRequest(ctx, view, "credential_unavailable", ErrSecretUnavailable)
	}
	ids := pending.ids
	if ids == nil {
		checkpoints, err := service.checkpointsFor(ctx, prober)
		if err != nil {
			return service.failRequest(ctx, view, "checkpoints_unavailable", prober.fail("", 0, err))
		}
		for _, picked := range Select(checkpoints, pending.pick, 0) {
			ids = append(ids, picked.ID)
		}
		if len(ids) == 0 {
			return service.failRequest(ctx, view, "no_checkpoint", nil)
		}
	}
	pending.request.NodeIDs = ids
	job, err := prober.client.CreateProbe(ctx, "cdnca-req-"+pending.id.String(), pending.request)
	if err != nil {
		var apiErr *APIError
		code := "transport_error"
		if errors.As(err, &apiErr) {
			code = apiErr.Code
		}
		failure := prober.fail("", 0, err)
		if errors.Is(failure, ErrRefused) && code == "target_restricted" {
			failure = ErrTargetRestricted
		}
		return service.failRequest(ctx, view, code, failure)
	}
	if job.Created {
		service.meter(consumer)
	}
	if _, err := service.config.Pool.Exec(ctx, `UPDATE probe_dnspup_plugin_requests SET dnspup_request_id=$2,polled_at=$3
		WHERE id=$1`, pending.id, job.RequestID, service.now()); err != nil {
		return view, err
	}
	return view, nil
}

// failRequest marks a request failed. Refusals the caller must see
// (restricted target, missing secret, dnspup quota / rate limit) are
// errors; anything else answers the failed request with its error_code.
func (service *Service) failRequest(ctx context.Context, view ProbeRequestView, code string, cause error) (ProbeRequestView, error) {
	view.Status, view.ErrorCode, view.RetryAfter = "failed", token(code), 0
	if _, err := service.config.Pool.Exec(ctx, `UPDATE probe_dnspup_plugin_requests SET status='failed',error_code=$2
		WHERE id=$1`, view.ID, view.ErrorCode); err != nil {
		return view, err
	}
	switch {
	case errors.Is(cause, ErrTargetRestricted), errors.Is(cause, ErrSecretUnavailable):
		return view, cause
	}
	var apiErr *APIError
	if errors.As(cause, &apiErr) && (apiErr.Code == "quota_exceeded" || apiErr.Status == 429) {
		return view, ErrPaused
	}
	return view, nil
}

// GetPluginRequest serves GET /v1/probe-dnspup/plugin/requests/{id}: only
// the installation that created it reads it (anything else: not found).
func (service *Service) GetPluginRequest(ctx context.Context, actor PluginActor, id uuid.UUID) (ProbeRequestView, error) {
	var installation uuid.UUID
	err := pgx.BeginTxFunc(ctx, service.config.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		identity, err := pluginOf(ctx, tx, actor)
		installation = identity.installationID
		return err
	})
	if err != nil {
		return ProbeRequestView{}, err
	}
	return service.readRequest(ctx, id, `origin='plugin' AND installation_id=$2 AND tenant_scope_id=$3`, installation, actor.ScopeID)
}

// readRequest loads a request (filter on $2.. args), refreshes a pending one
// from dnspup at most every pluginPollEvery, and answers its view.
func (service *Service) readRequest(ctx context.Context, id uuid.UUID, filter string, args ...any) (ProbeRequestView, error) {
	now := service.now()
	var view ProbeRequestView
	var raw []byte
	var result []byte
	var dnspupID string
	var polled *time.Time
	var expires time.Time
	err := service.config.Pool.QueryRow(ctx, `SELECT request,status,result,error_code,created_at,dnspup_request_id,polled_at,expires_at
		FROM probe_dnspup_plugin_requests WHERE id=$1 AND `+filter, append([]any{id}, args...)...).Scan(&raw, &view.Status,
		&result, &view.ErrorCode, &view.CreatedAt, &dnspupID, &polled, &expires)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !expires.After(now) {
		return ProbeRequestView{}, ErrRequestNotFound
	}
	if err != nil {
		return ProbeRequestView{}, err
	}
	var input ProbeInput
	var diagnose DiagnoseInput
	_ = json.Unmarshal(raw, &input)
	if input.Type == "" {
		_ = json.Unmarshal(raw, &diagnose)
		input.Type, input.Target = "mtr", diagnose.Target
	}
	view.ID, view.Type, view.Target, view.Results = id, input.Type, input.Target, []CheckpointView{}
	if result != nil {
		var stored ProbeRequestView
		if json.Unmarshal(result, &stored) == nil {
			view.Results, view.Traces = stored.Results, stored.Traces
		}
	}
	if view.Status != "pending" {
		return view, nil
	}
	view.RetryAfter = pluginPollEvery
	if dnspupID == "" || polled != nil && now.Sub(*polled) < pluginPollEvery {
		return view, nil
	}
	return service.poll(ctx, view, input, dnspupID)
}

func (service *Service) poll(ctx context.Context, view ProbeRequestView, input ProbeInput, dnspupID string) (ProbeRequestView, error) {
	ctx = context.WithoutCancel(ctx)
	now := service.now()
	if _, err := service.config.Pool.Exec(ctx, `UPDATE probe_dnspup_plugin_requests SET polled_at=$2 WHERE id=$1`,
		view.ID, now); err != nil {
		return view, err
	}
	var value stored
	err := pgx.BeginTxFunc(ctx, service.config.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		value, err = readSettings(ctx, tx, false)
		return err
	})
	if err != nil {
		return view, err
	}
	prober, err := service.proberFor(value)
	if err != nil {
		return view, nil // still pending; the key was changed or removed meanwhile
	}
	job, err := prober.client.GetProbe(ctx, dnspupID)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.Code == "task_not_found" || apiErr.Code == "result_expired") {
			view.Status, view.ErrorCode = "failed", apiErr.Code
			_, err = service.config.Pool.Exec(ctx, `UPDATE probe_dnspup_plugin_requests SET status='failed',error_code=$2
				WHERE id=$1`, view.ID, apiErr.Code)
			return view, err
		}
		_ = prober.fail("", 0, err)
		return view, nil
	}
	if job.Pending() {
		view.RetryAfter = max(job.RetryAfter, pluginPollEvery)
		return view, nil
	}
	kind := input.Type
	view.Status, view.RetryAfter = "completed", 0
	if kind == "mtr" {
		view.Traces = job.Traces()
	} else {
		view.Results, _ = ViewsOf(kind, job.Results(), input.Expect)
		if view.Results == nil {
			view.Results = []CheckpointView{}
		}
	}
	if job.Status == "failed" {
		view.Status, view.ErrorCode = "failed", "job_failed"
	}
	encoded, err := json.Marshal(struct {
		Results []CheckpointView `json:"results"`
		Traces  json.RawMessage  `json:"traces,omitempty"`
	}{view.Results, view.Traces})
	if err != nil {
		return view, err
	}
	_, err = service.config.Pool.Exec(ctx, `UPDATE probe_dnspup_plugin_requests SET status=$2,result=$3,error_code=$4
		WHERE id=$1`, view.ID, view.Status, encoded, view.ErrorCode)
	return view, err
}

// CreateDiagnose runs one mtr diagnosis (admin; the line alert path calls
// Diagnose directly) from at most DiagnosePoints checkpoints, metered under
// the diagnose purpose.
func (service *Service) CreateDiagnose(ctx context.Context, actor Actor, key string, input DiagnoseInput) (ProbeRequestView, error) {
	if !validKey(key) {
		return ProbeRequestView{}, ErrInvalidInput
	}
	var replayID *uuid.UUID
	digest := requestDigest("diagnose", input)
	err := pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, service.now()); err != nil {
			return err
		}
		body, found, err := replay(ctx, tx, actor, key, digest)
		if err != nil || !found {
			return err
		}
		var stored struct {
			ID uuid.UUID `json:"id"`
		}
		if err := json.Unmarshal(body, &stored); err != nil {
			return err
		}
		replayID = &stored.ID
		return nil
	})
	if err != nil {
		return ProbeRequestView{}, err
	}
	if replayID != nil {
		return service.readRequest(ctx, *replayID, `origin<>'plugin'`)
	}
	view, err := service.Diagnose(ctx, "admin", input)
	if err != nil {
		return view, err
	}
	body, _ := json.Marshal(map[string]uuid.UUID{"id": view.ID})
	err = pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		if err := service.appendAudit(ctx, tx, &actor, ActionDiagnose, "success", map[string]any{"request_id": view.ID.String(),
			"target": input.Target, "checkpoints": input.Checkpoints}); err != nil {
			return err
		}
		return recordWrite(ctx, tx, actor, key, "diagnose", digest, body, service.now())
	})
	return view, err
}

// ActionDiagnose audits an admin mtr diagnosis.
const ActionDiagnose = "system.probe_dnspup.diagnose"

// Diagnose stores and launches an mtr request (origin admin / alert).
func (service *Service) Diagnose(ctx context.Context, origin string, input DiagnoseInput) (ProbeRequestView, error) {
	input.Target = strings.TrimSpace(input.Target)
	if !validHost(input.Target) || len(input.Checkpoints) == 0 || len(input.Checkpoints) > DiagnosePoints ||
		!uniqueIn(input.Checkpoints, nil, checkpointToken, DiagnosePoints) || origin != "admin" && origin != "alert" {
		return ProbeRequestView{}, ErrInvalidInput
	}
	now := service.now()
	pending := pendingRequest{id: uuid.New(), kind: "mtr", ids: input.Checkpoints, created: now,
		request: ProbeRequest{Type: "mtr", Target: input.Target, Count: 100}}
	err := pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		value, purposes, reason, _, err := service.availability(ctx, tx)
		if err != nil {
			return err
		}
		if reason != "" {
			return reasonError(reason)
		}
		if purposeStopped(purposes, PurposeDiagnose) {
			return ErrPluginQuota
		}
		pending.value = value
		raw, _ := json.Marshal(input)
		digest := requestDigest("diagnose_row", pending.id)
		_, err = tx.Exec(ctx, `INSERT INTO probe_dnspup_plugin_requests(id,origin,node_id,idempotency_key,request_digest_sha256,
			request,status,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,'pending',$7,$8)`, pending.id, origin, input.NodeID,
			pending.id.String(), digest[:], raw, now, now.Add(pluginRequestTTL))
		return err
	})
	if err != nil {
		return ProbeRequestView{}, err
	}
	return service.launch(ctx, pending, ConsumerDiagnose)
}

// GetDiagnose reads an admin / alert diagnosis.
func (service *Service) GetDiagnose(ctx context.Context, actor Actor, id uuid.UUID) (ProbeRequestView, error) {
	err := pgx.BeginTxFunc(ctx, service.config.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		return authenticate(ctx, tx, actor, service.now())
	})
	if err != nil {
		return ProbeRequestView{}, err
	}
	return service.readRequest(ctx, id, `origin<>'plugin'`)
}
