// Package controlbackuphttp is the console API for native backups, restore
// commands and the migration wizard. It never stops services itself: jobs are
// queued for the root backup agent (cdnca-control-backup.service), because a
// backup stops this very process.
package controlbackuphttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nativebackup"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

const (
	Prefix           = "/v1/admin/control-backup"
	readPermission   = "control.upgrades.read"
	managePermission = "control.upgrades.manage"
)

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

// Auditor records one console action. Payloads never contain secrets.
type Auditor func(ctx context.Context, session identity.AuthenticatedSession, action, resourceID, requestID string, payload map[string]any) error

type Dependencies struct {
	Layout       nativebackup.Layout
	Authenticate AuthenticateSessionFunc
	Audit        Auditor
	Now          func() time.Time
	// Probe and HostKey reach external hosts; tests replace them.
	Probe   func(context.Context, nativebackup.Target) error
	HostKey func(context.Context, string, int) (string, error)
	// VerifyPassword re-checks the caller's password before a rollback. It
	// must not write (the frozen console runs on a held host).
	VerifyPassword func(ctx context.Context, username, password, sourceIP string) (identity.Principal, error)
	// ProbeNewMaster reports whether the migration target answers as a
	// control plane; LookupHost resolves the control domain. Tests replace both.
	ProbeNewMaster func(ctx context.Context, host, controlDomain string) error
	LookupHost     func(ctx context.Context, host string) ([]string, error)
	// Facts names the control and Gateway domains for the DNS hint.
	Facts func(context.Context) nativebackup.ControlFacts
}

type Handler struct {
	dependencies    Dependencies
	passwordLimiter passwordLimiter
}

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if dependencies.Authenticate == nil || dependencies.Audit == nil {
		return nil, errors.New("control backup handler is not configured")
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	if dependencies.Probe == nil {
		dependencies.Probe = func(ctx context.Context, target nativebackup.Target) error {
			storage, err := nativebackup.OpenStorage(target)
			if err != nil {
				return err
			}
			defer storage.Close()
			return storage.Probe(ctx)
		}
	}
	if dependencies.HostKey == nil {
		dependencies.HostKey = nativebackup.FetchHostKey
	}
	if dependencies.ProbeNewMaster == nil {
		dependencies.ProbeNewMaster = probeNewMaster
	}
	if dependencies.LookupHost == nil {
		dependencies.LookupHost = net.DefaultResolver.LookupHost
	}
	if dependencies.Facts == nil {
		layout := dependencies.Layout
		dependencies.Facts = func(ctx context.Context) nativebackup.ControlFacts {
			facts, _ := nativebackup.NativeFacts(ctx, &nativebackup.Host{Layout: layout})
			return facts
		}
	}
	return &Handler{dependencies: dependencies}, nil
}

var (
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	backupPath       = regexp.MustCompile(`^` + Prefix + `/backups/([0-9]{8}T[0-9]{6}Z-[a-z0-9]{8})(/restore-commands)?$`)
	runPath          = regexp.MustCompile(`^` + Prefix + `/runs/([0-9]{8}T[0-9]{6}Z-[0-9a-f]{12})(/stop)?$`)
)

type apiError struct {
	status int
	code   string
}

func (failure apiError) Error() string { return failure.code }

func fail(status int, code string) error { return apiError{status: status, code: code} }

// targetError is a refused target field: details name the target and the
// request JSON key so the console marks that field.
type targetError struct {
	code, target, field string
}

func (failure targetError) Error() string { return failure.code }

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := request.Header.Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	response.Header().Set("X-Request-ID", requestID)
	session, err := handler.authenticate(request)
	if err == nil {
		err = handler.route(response, request, session, requestID)
	}
	if err != nil {
		var refused targetError
		if errors.As(err, &refused) {
			writeJSON(response, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": refused.code, "request_id": requestID,
				"details": map[string]string{"target": refused.target, "field": refused.field}}})
			return
		}
		var failure apiError
		if !errors.As(err, &failure) {
			failure = apiError{status: http.StatusServiceUnavailable, code: "control_backup_unavailable"}
		}
		writeJSON(response, failure.status, map[string]any{"error": map[string]string{"code": failure.code, "request_id": requestID}})
	}
}

func (handler *Handler) authenticate(request *http.Request) (identity.AuthenticatedSession, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || len(values[0]) > 8192 {
		return identity.AuthenticatedSession{}, fail(http.StatusUnauthorized, "authentication_required")
	}
	session, err := handler.dependencies.Authenticate(request.Context(), strings.TrimPrefix(values[0], "Bearer "))
	if err != nil || session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil {
		return identity.AuthenticatedSession{}, fail(http.StatusUnauthorized, "authentication_required")
	}
	if session.Principal.ScopeKind != "platform" || identity.Authorize(session.Principal, readPermission) != nil {
		return identity.AuthenticatedSession{}, fail(http.StatusForbidden, "permission_denied")
	}
	return session, nil
}

func (handler *Handler) requireManage(session identity.AuthenticatedSession) error {
	if identity.Authorize(session.Principal, managePermission) != nil {
		return fail(http.StatusForbidden, "permission_denied")
	}
	return nil
}

func (handler *Handler) route(response http.ResponseWriter, request *http.Request, session identity.AuthenticatedSession, requestID string) error {
	path := request.URL.Path
	switch {
	case path == Prefix && request.Method == http.MethodGet:
		return handler.status(response)
	case path == Prefix+"/settings" && request.Method == http.MethodPut:
		return handler.updateSettings(response, request, session, requestID)
	case path == Prefix+"/backups" && request.Method == http.MethodPost:
		return handler.submit(response, request, session, requestID, nativebackup.Request{Kind: nativebackup.RequestBackup})
	case path == Prefix+"/host-key" && request.Method == http.MethodPost:
		return handler.hostKey(response, request, session)
	case path == Prefix+"/migrations" && request.Method == http.MethodPost:
		return handler.migrate(response, request, session, requestID)
	case path == Prefix+"/recovery-kit" && request.Method == http.MethodPost:
		return handler.recoveryKit(response, request, session, requestID)
	case path == Prefix+"/targets/probe" && request.Method == http.MethodPost:
		return handler.probe(response, request, session)
	case path == Prefix+"/new-master" && request.Method == http.MethodGet:
		writeJSON(response, http.StatusOK, map[string]any{"data": handler.newMaster(request.Context())})
		return nil
	case path == Prefix+"/rollback" && request.Method == http.MethodPost:
		return handler.rollback(response, request, session, requestID)
	}
	if match := backupPath.FindStringSubmatch(path); match != nil {
		switch {
		case match[2] != "" && request.Method == http.MethodGet:
			return handler.restoreCommands(response, match[1])
		case match[2] == "" && request.Method == http.MethodDelete:
			var body struct {
				Confirm string `json:"confirm"`
			}
			if err := decode(request, &body); err != nil || body.Confirm != match[1] {
				return fail(http.StatusBadRequest, "confirmation_mismatch")
			}
			return handler.submit(response, request, session, requestID, nativebackup.Request{Kind: nativebackup.RequestDelete, BackupID: match[1]})
		}
	}
	if match := runPath.FindStringSubmatch(path); match != nil && match[2] != "" && request.Method == http.MethodPost {
		return handler.stop(response, request, session, requestID, match[1])
	}
	if match := runPath.FindStringSubmatch(path); match != nil && match[2] == "" && request.Method == http.MethodGet {
		run, err := nativebackup.ReadRun(handler.dependencies.Layout, match[1])
		if err != nil {
			return fail(http.StatusNotFound, "control_backup_run_not_found")
		}
		writeJSON(response, http.StatusOK, map[string]any{"data": run})
		return nil
	}
	return fail(http.StatusNotFound, "control_backup_not_found")
}

func (handler *Handler) status(response http.ResponseWriter) error {
	layout := handler.dependencies.Layout
	keys, err := nativebackup.LoadKeys(layout)
	keysReady := err == nil
	fingerprint, recipient := "", ""
	if keysReady {
		fingerprint, recipient = keys.Fingerprint(), keys.Recipient()
	}
	bundles, err := nativebackup.ListBundles(layout.Path(nativebackup.BackupRoot), fingerprint)
	if err != nil {
		return err
	}
	runs, err := nativebackup.ListRuns(layout, 30)
	if err != nil {
		return err
	}
	settings, err := nativebackup.LoadSettings(layout)
	if err != nil {
		return err
	}
	freeze, _ := (nativebackup.Freezer{Layout: layout}).Current()
	targets := make([]map[string]any, 0, len(settings.Targets))
	for _, target := range settings.Targets {
		targets = append(targets, target.Redacted())
	}
	_, agentErr := os.Stat(layout.Path("/etc/systemd/system/cdnca-control-backup.path"))
	_, dependenciesErr := os.Stat(layout.Path(nativebackup.DependenciesScript))
	if bundles == nil {
		bundles = []nativebackup.BundleSummary{}
	}
	if runs == nil {
		runs = []nativebackup.Run{}
	}
	// next_run_at: the next scheduled backup; null when the schedule is off.
	var nextRun *time.Time
	if slot, ok := nativebackup.NextSlot(settings, handler.dependencies.Now()); ok {
		utc := slot.UTC()
		nextRun = &utc
	}
	writeJSON(response, http.StatusOK, map[string]any{"data": map[string]any{
		"keys_ready": keysReady, "signer_fingerprint": fingerprint, "recipient": recipient,
		"agent_installed": agentErr == nil, "migration_ready": agentErr == nil && dependenciesErr == nil,
		"freeze": freeze, "bundles": bundles, "runs": runs, "next_run_at": nextRun,
		"settings": map[string]any{"schedule": settings.Schedule, "keep_local": settings.KeepLocal, "keep_remote": settings.KeepRemote, "targets": targets,
			"revision": settingsRevision(settings)},
	}})
	return nil
}

func decode(request *http.Request, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(request.Body, 256<<10))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

// settingsRevision identifies the stored settings (secrets included, so a
// credential change is a new revision). It is a digest, never the content.
func settingsRevision(settings nativebackup.Settings) string {
	encoded, _ := json.Marshal(settings)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:12])
}

// targetInput is one target as the console sends it. StoredName is the saved
// target it edits ("" for a new one, which never inherits stored secrets; it
// may differ from Name on a rename). Secrets: empty keeps the stored value of
// StoredName, for SFTP only while the auth stays the same.
type targetInput struct {
	nativebackup.Target
	StoredName string `json:"stored_name,omitempty"`
	Auth       string `json:"auth,omitempty"` // sftp: password | private_key
}

type settingsInput struct {
	ExpectedRevision string                `json:"expected_revision"`
	Schedule         nativebackup.Schedule `json:"schedule"`
	KeepLocal        int                   `json:"keep_local"`
	KeepRemote       int                   `json:"keep_remote"`
	Targets          []targetInput         `json:"targets"`
}

func storedAuth(target nativebackup.Target) string {
	if target.PrivateKey != "" {
		return "private_key"
	}
	return "password"
}

// mergeTarget applies one console target onto the stored settings: the rule
// saving and 测试连接 share. A changed SFTP auth needs a new credential of that
// type; the stored secret of the other type is never reused.
func mergeTarget(item targetInput, stored map[string]nativebackup.Target) (nativebackup.Target, error) {
	target := item.Target
	previous, found := stored[item.StoredName]
	if item.StoredName != "" && (!found || previous.Kind != target.Kind) {
		return nativebackup.Target{}, fail(http.StatusConflict, "control_backup_revision_conflict")
	}
	found = item.StoredName != ""
	if target.Kind == "s3" {
		if found {
			if target.AccessKey == "" {
				target.AccessKey = previous.AccessKey
			}
			if target.SecretKey == "" {
				target.SecretKey = previous.SecretKey
			}
			if target.CACertificate == "" {
				target.CACertificate = previous.CACertificate
			}
		}
		return target, nil
	}
	if target.Kind != "sftp" {
		return target, nil
	}
	auth := item.Auth
	switch {
	case auth == "" && target.PrivateKey != "":
		auth = "private_key"
	case auth == "" && target.Password != "":
		auth = "password"
	case auth == "" && found:
		auth = storedAuth(previous)
	case auth == "":
		auth = "password"
	}
	if auth != "password" && auth != "private_key" {
		return nativebackup.Target{}, targetError{code: "control_backup_invalid_settings", target: target.Name, field: "auth"}
	}
	field := auth // the console field holding this auth's credential
	switch {
	case auth == "private_key" && target.Password != "", auth == "password" && target.PrivateKey != "":
		return nativebackup.Target{}, targetError{code: "control_backup_invalid_settings", target: target.Name, field: field}
	case target.Password == "" && target.PrivateKey == "":
		if found && storedAuth(previous) != auth {
			return nativebackup.Target{}, targetError{code: "control_backup_auth_changed", target: target.Name, field: field}
		}
		if found {
			target.Password, target.PrivateKey = previous.Password, previous.PrivateKey
		}
	case auth == "private_key":
		if _, err := ssh.ParsePrivateKey([]byte(target.PrivateKey)); err != nil {
			return nativebackup.Target{}, targetError{code: "control_backup_invalid_private_key", target: target.Name, field: field}
		}
	case strings.Contains(target.Password, "PRIVATE KEY-----"):
		return nativebackup.Target{}, targetError{code: "control_backup_invalid_password", target: target.Name, field: field}
	}
	return target, nil
}

// fieldRefusal names the console field of a target error it can pin (X08).
func fieldRefusal(target nativebackup.Target) error {
	if errors.Is(target.Validate(), nativebackup.ErrInvalidEndpoint) {
		return targetError{code: "control_backup_invalid_endpoint", target: target.Name, field: "endpoint"}
	}
	return nil
}

// loadForEdit reads the stored settings and checks the console's revision.
func (handler *Handler) loadForEdit(expected string) (nativebackup.Settings, map[string]nativebackup.Target, error) {
	current, err := nativebackup.LoadSettings(handler.dependencies.Layout)
	if err != nil {
		return nativebackup.Settings{}, nil, err
	}
	if expected != settingsRevision(current) {
		return nativebackup.Settings{}, nil, fail(http.StatusConflict, "control_backup_revision_conflict")
	}
	stored := map[string]nativebackup.Target{}
	for _, target := range current.Targets {
		stored[target.Name] = target
	}
	return current, stored, nil
}

func (handler *Handler) updateSettings(response http.ResponseWriter, request *http.Request, session identity.AuthenticatedSession, requestID string) error {
	if err := handler.requireManage(session); err != nil {
		return err
	}
	var input settingsInput
	if err := decode(request, &input); err != nil {
		return fail(http.StatusBadRequest, "control_backup_invalid_settings")
	}
	_, stored, err := handler.loadForEdit(input.ExpectedRevision)
	if err != nil {
		return err
	}
	next := nativebackup.Settings{Schedule: input.Schedule, KeepLocal: input.KeepLocal, KeepRemote: input.KeepRemote}
	for _, item := range input.Targets {
		target, err := mergeTarget(item, stored)
		if err != nil {
			return err
		}
		if err := fieldRefusal(target); err != nil {
			return err
		}
		next.Targets = append(next.Targets, target)
	}
	if err := next.Validate(); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "control_backup_invalid_settings",
			"message": nativebackup.Redact(err.Error()), "request_id": requestID}})
		return nil
	}
	names := make([]string, 0, len(next.Targets))
	for _, target := range next.Targets {
		names = append(names, target.Kind+":"+target.Name)
	}
	if err := handler.dependencies.Audit(request.Context(), session, "control_backup.settings_update", "settings", requestID,
		map[string]any{"schedule_enabled": next.Schedule.Enabled, "keep_local": next.KeepLocal, "keep_remote": next.KeepRemote, "targets": names}); err != nil {
		return err
	}
	if err := nativebackup.SaveSettings(handler.dependencies.Layout, next); err != nil {
		return err
	}
	return handler.status(response)
}

func (handler *Handler) submit(response http.ResponseWriter, request *http.Request, session identity.AuthenticatedSession, requestID string, job nativebackup.Request, extra ...map[string]any) error {
	if err := handler.requireManage(session); err != nil {
		return err
	}
	if _, err := os.Stat(handler.dependencies.Layout.Path("/etc/systemd/system/cdnca-control-backup.path")); err != nil {
		return fail(http.StatusConflict, "control_backup_agent_not_installed")
	}
	if current, _ := (nativebackup.Freezer{Layout: handler.dependencies.Layout}).Current(); current != nil && current.Mode == nativebackup.FreezeHold &&
		job.Kind != nativebackup.RequestRollback {
		return fail(http.StatusConflict, "control_backup_host_held")
	}
	job.RequestedBy = session.Principal.Username
	payload := map[string]any{"kind": string(job.Kind)}
	for _, values := range extra {
		for key, value := range values {
			payload[key] = value
		}
	}
	if job.BackupID != "" {
		payload["backup_id"] = job.BackupID
	}
	if job.Migration != nil {
		payload["target_host"], payload["target_port"], payload["target_user"] = job.Migration.Host, job.Migration.Port, job.Migration.User
		payload["host_key_sha256"] = job.Migration.HostKeySHA256
		payload["target_env"] = job.Migration.Env
		if payload["target_env"] == "" {
			payload["target_env"] = "auto"
		}
	}
	if err := handler.dependencies.Audit(request.Context(), session, "control_backup."+string(job.Kind)+"_request", string(job.Kind), requestID, payload); err != nil {
		return err
	}
	run, err := nativebackup.SubmitRequest(handler.dependencies.Layout, job, handler.dependencies.Now())
	if errors.Is(err, nativebackup.ErrBusy) {
		return fail(http.StatusConflict, "control_backup_busy")
	}
	if err != nil {
		return fail(http.StatusBadRequest, "control_backup_invalid_request")
	}
	writeJSON(response, http.StatusAccepted, map[string]any{"data": run})
	return nil
}

func (handler *Handler) hostKey(response http.ResponseWriter, request *http.Request, session identity.AuthenticatedSession) error {
	if err := handler.requireManage(session); err != nil {
		return err
	}
	var body struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := decode(request, &body); err != nil {
		return fail(http.StatusBadRequest, "control_backup_invalid_request")
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	fingerprint, err := handler.dependencies.HostKey(ctx, body.Host, body.Port)
	if err != nil {
		return fail(http.StatusBadGateway, "control_backup_host_unreachable")
	}
	writeJSON(response, http.StatusOK, map[string]any{"data": map[string]string{"host_key_sha256": fingerprint}})
	return nil
}

func (handler *Handler) migrate(response http.ResponseWriter, request *http.Request, session identity.AuthenticatedSession, requestID string) error {
	var body struct {
		nativebackup.MigrationTarget
		Confirm string `json:"confirm"`
	}
	if err := decode(request, &body); err != nil {
		return fail(http.StatusBadRequest, "control_backup_invalid_request")
	}
	if body.Confirm != body.Host {
		return fail(http.StatusBadRequest, "confirmation_mismatch")
	}
	if body.MigrationTarget.Validate() != nil {
		return fail(http.StatusBadRequest, "control_backup_invalid_request")
	}
	if _, err := os.Stat(handler.dependencies.Layout.Path(nativebackup.DependenciesScript)); err != nil {
		return fail(http.StatusConflict, "control_backup_migration_dependencies_missing")
	}
	target := body.MigrationTarget
	return handler.submit(response, request, session, requestID, nativebackup.Request{Kind: nativebackup.RequestMigrate, Migration: &target})
}

// probe tests the target as it is on screen: a new one as given, an edited
// one (stored_name) merged over the stored settings at expected_revision.
// It writes, reads back and deletes a probe object; nothing is saved.
func (handler *Handler) probe(response http.ResponseWriter, request *http.Request, session identity.AuthenticatedSession) error {
	if err := handler.requireManage(session); err != nil {
		return err
	}
	var input struct {
		ExpectedRevision string      `json:"expected_revision"`
		Target           targetInput `json:"target"`
	}
	if err := decode(request, &input); err != nil {
		return fail(http.StatusBadRequest, "control_backup_invalid_settings")
	}
	_, stored, err := handler.loadForEdit(input.ExpectedRevision)
	if err != nil {
		return err
	}
	target, err := mergeTarget(input.Target, stored)
	if err != nil {
		return err
	}
	if err := fieldRefusal(target); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "control_backup_invalid_settings",
			"message": nativebackup.Redact(err.Error()), "request_id": requestIDOf(response)}})
		return nil
	}
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()
	result := map[string]any{"ok": true}
	if err := handler.dependencies.Probe(ctx, target); err != nil {
		result = map[string]any{"ok": false, "message": nativebackup.Redact(err.Error())}
	}
	writeJSON(response, http.StatusOK, map[string]any{"data": result})
	return nil
}

func requestIDOf(response http.ResponseWriter) string { return response.Header().Get("X-Request-ID") }

// restoreCommands only renders text. Restoring always targets an empty host
// and is run there by root, never by this process.
func (handler *Handler) restoreCommands(response http.ResponseWriter, backupID string) error {
	directory := handler.dependencies.Layout.Path(nativebackup.BackupRoot) + "/" + backupID
	signed, err := nativebackup.ReadSignedManifest(directory)
	if err != nil {
		return fail(http.StatusNotFound, "control_backup_not_found")
	}
	manifest, err := nativebackup.ReadUnverifiedManifest(signed)
	if err != nil {
		return fail(http.StatusNotFound, "control_backup_not_found")
	}
	binary := nativebackup.NativeRoot + "/current/bin/control-api"
	commands := []string{
		"# 1. 在全新服务器上（同为 " + manifest.Control.Version + "）安装依赖：bash install-ubuntu-dependencies.sh install（来自本机 " + nativebackup.DependenciesScript + "）",
		fmt.Sprintf("# 2. 把整个备份目录复制到新服务器：scp -r root@本机:%s/%s /var/lib/cdnca-control-backup/bundles/", nativebackup.BackupRoot, backupID),
		"# 3. 把本机 " + binary + " 复制到新服务器 /root/control-api（版本必须一致）",
		"# 4. 在新服务器执行（恢复口令包由“导出恢复密钥”下载；签名指纹见下）：",
		fmt.Sprintf("/root/control-api native-backup restore --bundle /var/lib/cdnca-control-backup/bundles/%s --recovery-kit /root/cdnca-recovery-kit.json --signer %s", backupID, manifest.SignerKeyHint),
		fmt.Sprintf("%s native-backup verify-migration --bundle /var/lib/cdnca-control-backup/bundles/%s --wait-nodes 10m", binary, backupID),
		"# 5. 把管理端与 Gateway 域名的 DNS 改到新服务器；旧服务器仍在运行时先停掉：" + binary + " native-backup create --reason migration --hold 或直接关机",
		"# 本机仍可用时更简单：在新服务器执行 install-control.sh migrate-from root@本机，或使用下方“迁移主控”。",
	}
	writeJSON(response, http.StatusOK, map[string]any{"data": map[string]any{"backup_id": backupID, "signer_fingerprint": manifest.SignerKeyHint,
		"version": manifest.Control.Version, "schema_version": manifest.Control.SchemaVersion, "commands": commands}})
	return nil
}

func (handler *Handler) recoveryKit(response http.ResponseWriter, request *http.Request, session identity.AuthenticatedSession, requestID string) error {
	if err := handler.requireManage(session); err != nil {
		return err
	}
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decode(request, &body); err != nil {
		return fail(http.StatusBadRequest, "control_backup_invalid_request")
	}
	defer func() { body.Passphrase = "" }()
	keys, err := nativebackup.LoadKeys(handler.dependencies.Layout)
	if err != nil {
		return fail(http.StatusConflict, "control_backup_keys_unavailable")
	}
	facts, _ := nativebackup.NativeFacts(request.Context(), &nativebackup.Host{Layout: handler.dependencies.Layout})
	kit, err := nativebackup.ExportRecoveryKit(keys, facts.InstallationID, body.Passphrase, handler.dependencies.Now())
	if errors.Is(err, nativebackup.ErrWeakPassphrase) {
		return fail(http.StatusBadRequest, "control_backup_weak_passphrase")
	}
	if err != nil {
		return err
	}
	if err := handler.dependencies.Audit(request.Context(), session, "control_backup.recovery_kit_export", "recovery-kit", requestID,
		map[string]any{"signer_fingerprint": kit.SignerFinger}); err != nil {
		return err
	}
	response.Header().Set("Content-Disposition", `attachment; filename="cdnca-recovery-kit.json"`)
	writeJSON(response, http.StatusOK, kit)
	return nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
