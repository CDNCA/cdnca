package nodesshinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The console SSH terminal (node management "SSH" tab): a platform
// administrator opens an interactive shell on a node from the browser. The
// controller dials the node's address with the host key already known for it
// (the one pinned with a remembered login, or the one an SSH install
// confirmed), trusting the presented key on first use, so the
// browser never talks SSH and the node never sees the browser.

// PermissionSSH: only holders of platform.admin pass identity.Authorize; no
// role is granted it (migration 608).
const PermissionSSH = "nodes.ssh"

const (
	// TerminalIdleTimeout ends a session without keyboard input.
	TerminalIdleTimeout = 15 * time.Minute
	// TerminalMaxDuration ends any session.
	TerminalMaxDuration = 2 * time.Hour
	// maxTerminals open at once on one controller process.
	maxTerminals = 16
)

// terminalCredentialDomain separates remembered terminal logins from the
// install job envelopes under the same keyring.
const terminalCredentialDomain = "cdnca-node-ssh-terminal-credential/v1\x00"

var (
	ErrNoAddress     = errors.New("the node has no address to SSH to")
	ErrTerminalsBusy = errors.New("too many SSH terminals are open")
)

// NodeEndpoint is where a node's sshd is reached, and its remembered login
// (without the secret).
type NodeEndpoint struct {
	NodeID   uuid.UUID        `json:"node_id"`
	NodeName string           `json:"node_name"`
	Host     string           `json:"host"`
	Saved    *SavedCredential `json:"saved"`
}

// SavedCredential is a remembered terminal login (never the secret).
type SavedCredential struct {
	Port          int       `json:"port"`
	Username      string    `json:"username"`
	AuthKind      string    `json:"auth_kind"`
	HostKeySHA256 string    `json:"host_key_sha256"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TerminalRequest opens a terminal. With UseSaved the remembered login and
// its pinned host key are used (Credential and HostKeySHA256 are ignored);
// otherwise Credential is the login and HostKeySHA256 an optional expected
// fingerprint: without it the controller uses the key already known for the
// node (remembered login, else a confirmed SSH install), or trusts the key
// presented on first use. Remember stores the login after it succeeded and
// pins the key the connection was made with; a later change is refused.
type TerminalRequest struct {
	NodeID        uuid.UUID
	Port          int
	Credential    Credential
	HostKeySHA256 string
	UseSaved      bool
	Remember      bool
	Cols, Rows    int
}

// Terminal is an open session; End must be called once.
type Terminal struct {
	*Shell
	service  *Service
	actor    Actor
	endpoint NodeEndpoint
	port     int
	username string
	id       uuid.UUID
	started  time.Time
	// Remembered: the login was saved (Remember) for the next connection.
	Remembered bool
}

func terminalBinding(nodeID uuid.UUID) dnsacme.CredentialBinding {
	return dnsacme.CredentialBinding{TenantID: nodeID, ScopeID: nodeID, ProviderID: nodeID}
}

// Endpoint returns the node's SSH address of the actor's (platform) scope.
func (service *Service) Endpoint(ctx context.Context, actor Actor, nodeID uuid.UUID) (NodeEndpoint, error) {
	if err := service.requirePlatform(ctx, service.pool, actor); err != nil {
		return NodeEndpoint{}, err
	}
	endpoint := NodeEndpoint{NodeID: nodeID}
	var saved SavedCredential
	var savedPort *int
	err := service.pool.QueryRow(ctx, `SELECT node.name, COALESCE(host(node.ipv4), host(node.ipv6), ''),
			credential.port, COALESCE(credential.username,''), COALESCE(credential.auth_kind,''),
			COALESCE(credential.host_key_sha256,''), COALESCE(credential.updated_at, node.updated_at)
		FROM nodes node LEFT JOIN node_ssh_credentials credential ON credential.node_id = node.id
		WHERE node.scope_id=$1 AND node.id=$2 AND node.admin_state <> 'retired'`, actor.ScopeID, nodeID).
		Scan(&endpoint.NodeName, &endpoint.Host, &savedPort, &saved.Username, &saved.AuthKind, &saved.HostKeySHA256, &saved.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return NodeEndpoint{}, ErrNotFound
	}
	if err != nil {
		return NodeEndpoint{}, err
	}
	if endpoint.Host == "" {
		return NodeEndpoint{}, ErrNoAddress
	}
	if savedPort != nil {
		saved.Port = *savedPort
		endpoint.Saved = &saved
	}
	return endpoint, nil
}

// NodeHostKey fetches the node's current host key on port (for the
// operator to compare before sending a login).
func (service *Service) NodeHostKey(ctx context.Context, actor Actor, nodeID uuid.UUID, port int) (NodeEndpoint, string, error) {
	if port < 1 || port > 65535 {
		return NodeEndpoint{}, "", ErrInvalidInput
	}
	endpoint, err := service.Endpoint(ctx, actor, nodeID)
	if err != nil {
		return NodeEndpoint{}, "", err
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	key, err := service.dialer.FetchHostKey(fetchCtx, endpoint.Host, port)
	if err != nil || !hostKeyPattern.MatchString(key) {
		return endpoint, "", ErrUnreachable
	}
	return endpoint, key, nil
}

// ErrUnreachable: the node's sshd did not answer.
var ErrUnreachable = errors.New("SSH destination is unreachable")

// ErrAuthFailed: the login was refused.
var ErrAuthFailed = errors.New("SSH login was refused")

// ErrHostKeyChanged: the node presented another host key than the pinned one.
var ErrHostKeyChanged = errors.New("SSH host key does not match")

func (service *Service) sealTerminal(nodeID uuid.UUID, credential Credential) (string, []byte, error) {
	encoded, err := json.Marshal(sealedCredential{Password: credential.Password, PrivateKey: credential.PrivateKey})
	if err != nil {
		return "", nil, ErrInvalidInput
	}
	plaintext := append([]byte(terminalCredentialDomain+nodeID.String()+"\x00"), encoded...)
	defer clear(plaintext)
	clear(encoded)
	return service.cipher.EncryptCredential(terminalBinding(nodeID), plaintext)
}

func (service *Service) openTerminalCredential(nodeID uuid.UUID, username, keyID string, ciphertext []byte) (Credential, error) {
	plaintext, err := service.cipher.DecryptCredential(terminalBinding(nodeID), keyID, ciphertext)
	if err != nil {
		return Credential{}, err
	}
	defer clear(plaintext)
	prefix := []byte(terminalCredentialDomain + nodeID.String() + "\x00")
	if !bytes.HasPrefix(plaintext, prefix) {
		return Credential{}, ErrInvalidInput
	}
	var sealed sealedCredential
	if err := json.Unmarshal(plaintext[len(prefix):], &sealed); err != nil {
		return Credential{}, ErrInvalidInput
	}
	return Credential{Username: username, Password: sealed.Password, PrivateKey: sealed.PrivateKey}, nil
}

func (service *Service) terminalAudit(ctx context.Context, actor Actor, action, nodeID, result, reason string,
	payload map[string]any) error {
	return pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if err := service.requirePlatform(ctx, tx, actor); err != nil {
			return err
		}
		return service.auditTx(ctx, tx, actor, action, "node", nodeID, result, reason, payload)
	})
}

func (service *Service) auditTx(ctx context.Context, tx pgx.Tx, actor Actor, action, resourceType, resourceID, result,
	reason string, payload map[string]any) error {
	var actorID *uuid.UUID
	if actor.UserID != uuid.Nil {
		actorID = &actor.UserID
	}
	requestID := actor.RequestID
	if requestID == "" {
		requestID = "node-ssh/" + uuid.NewString()
	}
	return service.auditor.Append(ctx, tx, auditEvent(actor.ScopeID, actorID, action, resourceType, resourceID,
		requestID, result, reason, actor.IP, payload))
}

// OpenTerminal logs in to the node and starts a shell; output receives the
// shell's output. The start (or the refusal) is audited; the login secret
// never is.
func (service *Service) OpenTerminal(ctx context.Context, actor Actor, request TerminalRequest,
	output func([]byte)) (*Terminal, error) {
	endpoint, err := service.Endpoint(ctx, actor, request.NodeID)
	if err != nil {
		return nil, err
	}
	credential, pinned, port, err := service.terminalLogin(ctx, actor, request)
	if err != nil {
		return nil, err
	}
	defer clear([]byte(credential.Password))
	payload := map[string]any{"host": endpoint.Host, "port": port, "username": credential.Username,
		"use_saved": request.UseSaved, "host_key_sha256": pinned}
	select {
	case service.terminals <- struct{}{}:
	default:
		_ = service.terminalAudit(ctx, actor, "node.ssh.session.start", request.NodeID.String(), "failure", "terminals_busy", payload)
		return nil, ErrTerminalsBusy
	}
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	shell, err := service.dialer.OpenShell(dialCtx, endpoint.Host, port, credential, pinned, request.Cols, request.Rows,
		writerFunc(output))
	if err != nil {
		<-service.terminals
		reason := FailUnreachable
		switch {
		case errors.Is(err, errHostKeyMismatch):
			reason, err = FailHostKeyMismatch, ErrHostKeyChanged
		case isAuthFailure(err):
			reason, err = FailAuth, ErrAuthFailed
		case errors.Is(err, ErrInvalidInput):
			reason = "invalid_credential"
		default:
			err = ErrUnreachable
		}
		_ = service.terminalAudit(ctx, actor, "node.ssh.session.start", request.NodeID.String(), "failure", reason, payload)
		return nil, err
	}
	// First use: the key this connection was made with is the one pinned from now on.
	pinned = shell.HostKeySHA256
	terminal := &Terminal{Shell: shell, service: service, actor: actor, endpoint: endpoint, port: port,
		username: credential.Username, id: uuid.New(), started: service.now().UTC()}
	payload["session_id"] = terminal.id.String()
	payload["host_key_sha256"] = pinned
	if err := service.terminalAudit(ctx, actor, "node.ssh.session.start", request.NodeID.String(), "success", "", payload); err != nil {
		// An unaudited session is not allowed.
		_ = shell.Close()
		<-service.terminals
		return nil, err
	}
	if request.Remember && !request.UseSaved {
		if err := service.rememberCredential(ctx, actor, request.NodeID, port, credential, pinned); err != nil {
			service.logger.Warn("remember SSH terminal credential failed", "node_id", request.NodeID, "error", err)
		} else {
			terminal.Remembered = true
		}
	}
	return terminal, nil
}

// terminalLogin resolves the login, the pinned host key and the port. A
// typed login without a fingerprint uses the key already known for the node
// on that port (the remembered login's pin, else the one a successful SSH
// install confirmed); none known: "" (trust on first use, see OpenShell).
func (service *Service) terminalLogin(ctx context.Context, actor Actor, request TerminalRequest) (Credential, string, int, error) {
	if request.Cols < 1 || request.Cols > 1000 || request.Rows < 1 || request.Rows > 500 {
		return Credential{}, "", 0, ErrInvalidInput
	}
	if !request.UseSaved {
		credential := request.Credential
		if request.Port < 1 || request.Port > 65535 || normalizeCredential(&credential) != nil {
			return Credential{}, "", 0, ErrInvalidInput
		}
		if request.HostKeySHA256 != "" {
			if !hostKeyPattern.MatchString(request.HostKeySHA256) {
				return Credential{}, "", 0, ErrInvalidInput
			}
			return credential, request.HostKeySHA256, request.Port, nil
		}
		pinned, err := service.knownHostKey(ctx, actor, request.NodeID, request.Port)
		if err != nil {
			return Credential{}, "", 0, err
		}
		return credential, pinned, request.Port, nil
	}
	var port int
	var username, hostKey, keyID string
	var ciphertext []byte
	err := service.pool.QueryRow(ctx, `SELECT port,username,host_key_sha256,credential_key_id,credential_ciphertext
		FROM node_ssh_credentials WHERE scope_id=$1 AND node_id=$2`, actor.ScopeID, request.NodeID).
		Scan(&port, &username, &hostKey, &keyID, &ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, "", 0, ErrNotFound
	}
	if err != nil {
		return Credential{}, "", 0, err
	}
	defer clear(ciphertext)
	credential, err := service.openTerminalCredential(request.NodeID, username, keyID, ciphertext)
	if err != nil {
		return Credential{}, "", 0, ErrInvalidInput
	}
	return credential, hostKey, port, nil
}

// knownHostKey is the host key already trusted for the node's sshd on port:
// the remembered login's pin, else the newest one an SSH install of this
// node confirmed; "" when none is known.
func (service *Service) knownHostKey(ctx context.Context, actor Actor, nodeID uuid.UUID, port int) (string, error) {
	var key string
	err := service.pool.QueryRow(ctx, `SELECT host_key_sha256 FROM (
			SELECT host_key_sha256, 0 AS rank, updated_at FROM node_ssh_credentials
			WHERE scope_id=$1 AND node_id=$2 AND port=$3
			UNION ALL
			SELECT host_key_sha256, 1, finished_at FROM node_ssh_install_jobs
			WHERE scope_id=$1 AND node_id=$2 AND port=$3 AND state='succeeded' AND host_key_confirmed
				AND host_key_sha256 <> '') known
		ORDER BY rank, updated_at DESC LIMIT 1`, actor.ScopeID, nodeID, port).Scan(&key)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !hostKeyPattern.MatchString(key) {
		return "", ErrInvalidInput
	}
	return key, nil
}

func (service *Service) rememberCredential(ctx context.Context, actor Actor, nodeID uuid.UUID, port int,
	credential Credential, hostKey string) error {
	keyID, ciphertext, err := service.sealTerminal(nodeID, credential)
	if err != nil {
		return err
	}
	defer clear(ciphertext)
	authKind := AuthPassword
	if credential.PrivateKey != "" {
		authKind = AuthPrivateKey
	}
	return pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if err := service.requirePlatform(ctx, tx, actor); err != nil {
			return err
		}
		now := service.now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO node_ssh_credentials(node_id,scope_id,port,username,auth_kind,host_key_sha256,
				credential_key_id,credential_ciphertext,saved_by_user_id,created_at,updated_at)
			SELECT id,scope_id,$3,$4,$5,$6,$7,$8,$9,$10,$10 FROM nodes WHERE scope_id=$1 AND id=$2
			ON CONFLICT (node_id) DO UPDATE SET port=EXCLUDED.port,username=EXCLUDED.username,auth_kind=EXCLUDED.auth_kind,
				host_key_sha256=EXCLUDED.host_key_sha256,credential_key_id=EXCLUDED.credential_key_id,
				credential_ciphertext=EXCLUDED.credential_ciphertext,saved_by_user_id=EXCLUDED.saved_by_user_id,
				updated_at=EXCLUDED.updated_at`,
			actor.ScopeID, nodeID, port, credential.Username, authKind, hostKey, keyID, ciphertext, actor.UserID, now); err != nil {
			return err
		}
		return service.auditTx(ctx, tx, actor, "node.ssh.credential.save", "node", nodeID.String(), "success", "",
			map[string]any{"port": port, "username": credential.Username, "auth_kind": authKind, "host_key_sha256": hostKey})
	})
}

// ForgetCredential deletes the node's remembered terminal login.
func (service *Service) ForgetCredential(ctx context.Context, actor Actor, nodeID uuid.UUID) error {
	return pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if err := service.requirePlatform(ctx, tx, actor); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `DELETE FROM node_ssh_credentials WHERE scope_id=$1 AND node_id=$2`, actor.ScopeID, nodeID)
		if err != nil {
			return err
		}
		if command.RowsAffected() == 0 {
			return ErrNotFound
		}
		return service.auditTx(ctx, tx, actor, "node.ssh.credential.delete", "node", nodeID.String(), "success", "", nil)
	})
}

// End closes the session and audits who, which node and how long (never
// what was typed).
func (terminal *Terminal) End(reason string, bytesIn, bytesOut int64) {
	_ = terminal.Shell.Close()
	<-terminal.service.terminals
	duration := terminal.service.now().UTC().Sub(terminal.started)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := terminal.service.terminalAudit(ctx, terminal.actor, "node.ssh.session.end", terminal.endpoint.NodeID.String(),
		"success", "", map[string]any{"session_id": terminal.id.String(), "host": terminal.endpoint.Host, "port": terminal.port,
			"username": terminal.username, "duration_seconds": int64(duration / time.Second), "end_reason": reason,
			"bytes_in": bytesIn, "bytes_out": bytesOut}); err != nil {
		terminal.service.logger.Warn("audit SSH terminal end failed", "session_id", terminal.id, "error", err)
	}
}

type writerFunc func([]byte)

func (write writerFunc) Write(payload []byte) (int, error) {
	write(payload)
	return len(payload), nil
}
