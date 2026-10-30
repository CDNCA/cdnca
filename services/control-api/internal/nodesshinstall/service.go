package nodesshinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CredentialCipher is the control-api credential keyring
// (dnsacme.AESGCMCredentialCipher).
type CredentialCipher interface {
	EncryptCredential(dnsacme.CredentialBinding, []byte) (keyID string, ciphertext []byte, err error)
	DecryptCredential(dnsacme.CredentialBinding, string, []byte) ([]byte, error)
}

// RegistrationKeys hands out the scope's reusable node registration key
// (node.Service.RegistrationCredential, the one the console command shows).
type RegistrationKeys interface {
	RegistrationCredential(context.Context, node.Actor, string) (node.RegistrationCredential, error)
}

// credentialDomain separates SSH secrets from every other envelope under the
// same keyring, on top of the AAD binding to the job row.
const credentialDomain = "cdnca-node-ssh-credential/v1\x00"

const (
	installTimeout = 20 * time.Minute
	leaseDuration  = installTimeout + 2*time.Minute
	concurrency    = 4
)

type Service struct {
	pool         *pgxpool.Pool
	cipher       CredentialCipher
	registration RegistrationKeys
	dialer       *Dialer
	auditor      *audit.Log
	now          func() time.Time
	logger       *slog.Logger
	worker       string
}

type Config struct {
	Pool         *pgxpool.Pool
	Cipher       CredentialCipher
	Registration RegistrationKeys
	Dialer       *Dialer
	Now          func() time.Time
	Logger       *slog.Logger
}

func New(config Config) (*Service, error) {
	if config.Pool == nil || config.Cipher == nil || config.Registration == nil {
		return nil, ErrInvalidInput
	}
	if config.Dialer == nil {
		config.Dialer = NewDialer(nil)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Service{pool: config.Pool, cipher: config.Cipher, registration: config.Registration, dialer: config.Dialer,
		auditor: audit.NewWithClock(config.Pool, func() time.Time { return config.Now().UTC() }), now: config.Now,
		logger: config.Logger, worker: "nodesshinstall-" + uuid.NewString()}, nil
}

func binding(jobID uuid.UUID) dnsacme.CredentialBinding {
	return dnsacme.CredentialBinding{TenantID: jobID, ScopeID: jobID, ProviderID: jobID}
}

type sealedCredential struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

func (service *Service) seal(jobID uuid.UUID, credential Credential) (string, []byte, error) {
	encoded, err := json.Marshal(sealedCredential{Password: credential.Password, PrivateKey: credential.PrivateKey})
	if err != nil {
		return "", nil, ErrInvalidInput
	}
	plaintext := append([]byte(credentialDomain+jobID.String()+"\x00"), encoded...)
	defer clear(plaintext)
	clear(encoded)
	return service.cipher.EncryptCredential(binding(jobID), plaintext)
}

func (service *Service) open(jobID uuid.UUID, username, keyID string, ciphertext []byte) (Credential, error) {
	plaintext, err := service.cipher.DecryptCredential(binding(jobID), keyID, ciphertext)
	if err != nil {
		return Credential{}, err
	}
	defer clear(plaintext)
	prefix := []byte(credentialDomain + jobID.String() + "\x00")
	if !bytes.HasPrefix(plaintext, prefix) {
		return Credential{}, ErrInvalidInput
	}
	var sealed sealedCredential
	if err := json.Unmarshal(plaintext[len(prefix):], &sealed); err != nil {
		return Credential{}, ErrInvalidInput
	}
	return Credential{Username: username, Password: sealed.Password, PrivateKey: sealed.PrivateKey}, nil
}

func validHost(host string, blocked func(netip.Addr) bool) bool {
	host = strings.Trim(host, "[]")
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == "" && !blocked(address)
	}
	if host == "" || len(host) > 253 || strings.ToLower(host) != host || host == "localhost" ||
		strings.HasSuffix(host, ".localhost") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

// ValidControlPlane accepts an https origin (no path, query, fragment or
// credentials).
func ValidControlPlane(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Path == "" && parsed.RawQuery == "" &&
		parsed.Fragment == "" && parsed.User == nil && parsed.Opaque == "" && !strings.ContainsAny(value, " \t\r\n'\"")
}

func normalizeCreate(request *CreateRequest, blocked func(netip.Addr) bool) error {
	credential := &request.Credential
	credential.Username = strings.TrimSpace(credential.Username)
	if len(request.Targets) < 1 || len(request.Targets) > MaxBatch ||
		!usernamePattern.MatchString(credential.Username) || !ValidControlPlane(request.ControlPlane) ||
		(credential.Password == "") == (credential.PrivateKey == "") || len(credential.Password) > 1024 ||
		strings.ContainsAny(credential.Password, "\r\n") ||
		len(credential.PrivateKey) > 16<<10 {
		return ErrInvalidInput
	}
	if credential.PrivateKey != "" {
		if _, err := authMethods(*credential); err != nil {
			return ErrInvalidInput
		}
	}
	seen := map[string]bool{}
	for index := range request.Targets {
		target := &request.Targets[index]
		target.Host = strings.ToLower(strings.Trim(strings.TrimSpace(target.Host), "[]"))
		if address, err := netip.ParseAddr(target.Host); err == nil {
			target.Host = address.String()
		}
		target.Name = strings.TrimSpace(target.Name)
		if target.Port == 0 {
			target.Port = 22
		}
		key := target.Host + "|" + strconv.Itoa(target.Port)
		if !validHost(target.Host, blocked) || target.Port < 1 || target.Port > 65535 || seen[key] ||
			utf8.RuneCountInString(target.Name) > 128 || strings.ContainsAny(target.Name, "\x00\r\n'") {
			return ErrInvalidInput
		}
		seen[key] = true
	}
	return nil
}

func (service *Service) requirePlatform(ctx context.Context, querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, actor Actor) error {
	var kind string
	var tenant *uuid.UUID
	if err := querier.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1`, actor.ScopeID).
		Scan(&kind, &tenant); err != nil || kind != "platform" || tenant != nil {
		return ErrPermission
	}
	return nil
}

func (service *Service) audit(ctx context.Context, tx pgx.Tx, actor Actor, action string, job Job, result, reason string,
	extra map[string]any) error {
	payload := map[string]any{"host": job.Host, "port": job.Port, "username": job.Username, "batch_id": job.BatchID.String()}
	for key, value := range extra {
		payload[key] = value
	}
	event := audit.Event{ScopeID: actor.ScopeID, Action: action, ResourceType: "node_ssh_install",
		ResourceID: job.ID.String(), RequestID: actor.RequestID, Result: result, ReasonCode: reason,
		SourceIP: actor.IP, Payload: payload}
	if actor.UserID != uuid.Nil {
		event.ActorUserID = &actor.UserID
	} else {
		event.ActorKind, event.ActorRef = audit.ActorSystem, "job:node_ssh_install"
	}
	if event.RequestID == "" {
		event.RequestID = "node-ssh-install/" + uuid.NewString()
	}
	return service.auditor.Append(ctx, tx, event)
}

// Create records one job per target and fetches each host key. A job waits
// in awaiting_host_key until the operator confirms the fingerprint (or
// fails when the host cannot be reached).
func (service *Service) Create(ctx context.Context, actor Actor, request CreateRequest) ([]Job, error) {
	if err := normalizeCreate(&request, service.dialer.blocked); err != nil {
		return nil, err
	}
	defer clear([]byte(request.Credential.Password))
	batchID := uuid.New()
	authKind := AuthPassword
	if request.Credential.PrivateKey != "" {
		authKind = AuthPrivateKey
	}
	// Host keys are fetched before the transaction (network I/O).
	type fetched struct {
		key string
		err error
	}
	keys := make([]fetched, len(request.Targets))
	var wait sync.WaitGroup
	slots := make(chan struct{}, 16)
	for index, target := range request.Targets {
		wait.Add(1)
		slots <- struct{}{}
		go func(index int, target Target) {
			defer wait.Done()
			defer func() { <-slots }()
			fetchCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			key, err := service.dialer.FetchHostKey(fetchCtx, target.Host, target.Port)
			keys[index] = fetched{key: key, err: err}
		}(index, target)
	}
	wait.Wait()
	var jobs []Job
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if err := service.requirePlatform(ctx, tx, actor); err != nil {
			return err
		}
		now := service.now().UTC()
		for index, target := range request.Targets {
			job := Job{ID: uuid.New(), BatchID: batchID, Host: target.Host, Port: target.Port,
				Username: request.Credential.Username, AuthKind: authKind, NodeName: target.Name,
				State: StateAwaitingHostKey, Progress: []string{}, CreatedAt: now}
			var keyID string
			var ciphertext []byte
			if keys[index].err != nil || !hostKeyPattern.MatchString(keys[index].key) {
				job.State, job.FailureCode = StateFailed, FailUnreachable
				finished := now
				job.FinishedAt = &finished
			} else {
				job.HostKeySHA256 = keys[index].key
				var err error
				if keyID, ciphertext, err = service.seal(job.ID, request.Credential); err != nil {
					return ErrInvalidInput
				}
			}
			_, err := tx.Exec(ctx, `INSERT INTO node_ssh_install_jobs(id,scope_id,batch_id,host,port,username,auth_kind,
				node_name,control_plane,host_key_sha256,credential_key_id,credential_ciphertext,state,
				failure_code,created_by_user_id,created_at,finished_at,updated_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$16)`,
				job.ID, actor.ScopeID, batchID, job.Host, job.Port, job.Username, authKind, job.NodeName,
				request.ControlPlane, job.HostKeySHA256, keyID, ciphertext, job.State, job.FailureCode, actor.UserID,
				now, job.FinishedAt)
			clear(ciphertext)
			if err != nil {
				if isUnique(err) {
					return ErrDuplicate
				}
				return err
			}
			result, reason := "success", ""
			if job.State == StateFailed {
				result, reason = "failure", job.FailureCode
			}
			if err := service.audit(ctx, tx, actor, "node.ssh_install.create", job, result, reason,
				map[string]any{"auth_kind": authKind, "host_key_sha256": job.HostKeySHA256}); err != nil {
				return err
			}
			jobs = append(jobs, job)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return jobs, nil
}

// ConfirmHostKey starts a job: the fingerprint the operator compared out of
// band must equal the one fetched.
func (service *Service) ConfirmHostKey(ctx context.Context, actor Actor, jobID uuid.UUID, fingerprint string) (Job, error) {
	if !hostKeyPattern.MatchString(fingerprint) {
		return Job{}, ErrInvalidInput
	}
	return service.transition(ctx, actor, jobID, "node.ssh_install.host_key.confirm", func(job Job) (string, string, error) {
		if job.State != StateAwaitingHostKey {
			return "", "", ErrConflict
		}
		if job.HostKeySHA256 != fingerprint {
			return "", "", ErrConflict
		}
		return StatePending, "", nil
	})
}

// Cancel stops a job that has not finished; a running install is abandoned
// on the controller side (the remote script may still complete; the node
// then registers as pending as usual).
func (service *Service) Cancel(ctx context.Context, actor Actor, jobID uuid.UUID) (Job, error) {
	return service.transition(ctx, actor, jobID, "node.ssh_install.cancel", func(job Job) (string, string, error) {
		switch job.State {
		case StateAwaitingHostKey, StatePending, StateRunning:
			return StateCancelled, "", nil
		}
		return "", "", ErrConflict
	})
}

func (service *Service) transition(ctx context.Context, actor Actor, jobID uuid.UUID, action string,
	next func(Job) (string, string, error)) (Job, error) {
	var result Job
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if err := service.requirePlatform(ctx, tx, actor); err != nil {
			return err
		}
		job, err := scanJob(tx.QueryRow(ctx, selectJob+` WHERE scope_id=$1 AND id=$2 FOR UPDATE`, actor.ScopeID, jobID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		state, code, err := next(job)
		if err != nil {
			return err
		}
		now := service.now().UTC()
		terminal := state == StateCancelled || state == StateFailed || state == StateSucceeded
		if _, err := tx.Exec(ctx, `UPDATE node_ssh_install_jobs SET state=$3,failure_code=$4,
			host_key_confirmed=host_key_confirmed OR $3='pending',
			credential_key_id=CASE WHEN $5 THEN '' ELSE credential_key_id END,
			credential_ciphertext=CASE WHEN $5 THEN NULL ELSE credential_ciphertext END,
			finished_at=CASE WHEN $5 THEN $6 ELSE finished_at END,lease_owner='',lease_until=NULL,updated_at=$6
			WHERE scope_id=$1 AND id=$2`, actor.ScopeID, jobID, state, code, terminal, now); err != nil {
			return err
		}
		job.State, job.FailureCode = state, code
		job.HostKeyConfirmed = job.HostKeyConfirmed || state == StatePending
		if terminal {
			job.FinishedAt = &now
		}
		if err := service.audit(ctx, tx, actor, action, job, "success", "", nil); err != nil {
			return err
		}
		result = job
		return nil
	})
	return result, err
}

const selectJob = `SELECT id,batch_id,host,port,username,auth_kind,node_name,host_key_sha256,
	host_key_confirmed,state,failure_code,progress,node_id,attempts,created_at,started_at,finished_at
	FROM node_ssh_install_jobs`

func scanJob(row pgx.Row) (Job, error) {
	var job Job
	err := row.Scan(&job.ID, &job.BatchID, &job.Host, &job.Port, &job.Username, &job.AuthKind, &job.NodeName,
		&job.HostKeySHA256, &job.HostKeyConfirmed, &job.State, &job.FailureCode, &job.Progress,
		&job.NodeID, &job.Attempts, &job.CreatedAt, &job.StartedAt, &job.FinishedAt)
	if job.Progress == nil {
		job.Progress = []string{}
	}
	return job, err
}

// List returns the newest jobs (optionally one batch).
func (service *Service) List(ctx context.Context, actor Actor, batchID uuid.UUID, limit int) ([]Job, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	if err := service.requirePlatform(ctx, service.pool, actor); err != nil {
		return nil, err
	}
	rows, err := service.pool.Query(ctx, selectJob+` WHERE scope_id=$1 AND ($2::uuid IS NULL OR batch_id=$2)
		ORDER BY created_at DESC, id LIMIT $3`, actor.ScopeID, nullableUUID(batchID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []Job{}
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// Get returns one job.
func (service *Service) Get(ctx context.Context, actor Actor, jobID uuid.UUID) (Job, error) {
	if err := service.requirePlatform(ctx, service.pool, actor); err != nil {
		return Job{}, err
	}
	job, err := scanJob(service.pool.QueryRow(ctx, selectJob+` WHERE scope_id=$1 AND id=$2`, actor.ScopeID, jobID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	return job, err
}

func nullableUUID(value uuid.UUID) any {
	if value == uuid.Nil {
		return nil
	}
	return value
}

func isUnique(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
