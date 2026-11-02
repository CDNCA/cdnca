//go:build integration

package nodesshinstall

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
)

// TestTerminalRememberAndAccessAgainstPostgres: a typed login
// without a fingerprint trusts the key on first use; "remember" stores the
// login with that key pinned, so the next connection (use_saved) needs no
// password; a changed host key is refused; forgetting removes it. "Only the
// controller may SSH" turns on with an allowlist alone when no egress is
// configured or detected, and still refuses an empty one.
func TestTerminalRememberAndAccessAgainstPostgres(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	server := startTestSSHD(t)
	host, port := splitHostPort(t, server.address)
	scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ssh-terminal','SSH terminal','unused')`, []any{userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4)
			VALUES($1,$2,'edge-terminal','active',$3,(SELECT COALESCE(max(display_id),0)+1 FROM nodes),$4)`,
			[]any{nodeID, scopeID, userID, host}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("ssh-test-key", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{Pool: pool, Cipher: cipher, Registration: fixedRegistration{}, Dialer: NewDialer(allowLoopback)})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, RequestID: "ssh-terminal-test", IP: "198.51.100.1"}
	open := func(request TerminalRequest) (*Terminal, error) {
		request.NodeID, request.Cols, request.Rows = nodeID, 80, 24
		return service.OpenTerminal(ctx, actor, request, func([]byte) {})
	}

	// First use: no fingerprint sent; remembered with the presented key pinned.
	terminal, err := open(TerminalRequest{Port: port, Credential: Credential{Username: "root", Password: "test-password"}, Remember: true})
	if err != nil {
		t.Fatal(err)
	}
	if !terminal.Remembered || terminal.HostKeySHA256 != server.fingerprint {
		t.Fatalf("remembered=%v key=%q", terminal.Remembered, terminal.HostKeySHA256)
	}
	terminal.End("client_closed", 0, 0)
	endpoint, err := service.Endpoint(ctx, actor, nodeID)
	if err != nil || endpoint.Saved == nil || endpoint.Saved.Port != port || endpoint.Saved.Username != "root" ||
		endpoint.Saved.HostKeySHA256 != server.fingerprint || endpoint.Saved.AuthKind != AuthPassword {
		t.Fatalf("saved = %+v, %v", endpoint.Saved, err)
	}

	// Next time: the remembered login, no password.
	terminal, err = open(TerminalRequest{UseSaved: true})
	if err != nil {
		t.Fatalf("saved login: %v", err)
	}
	terminal.End("client_closed", 0, 0)

	// A typed login on the same port uses the pinned key: a changed host key is refused.
	if _, err := service.pool.Exec(ctx, `UPDATE node_ssh_credentials SET host_key_sha256=$2 WHERE node_id=$1`, nodeID,
		"SHA256:"+string(bytes.Repeat([]byte{'D'}, 43))); err != nil {
		t.Fatal(err)
	}
	if _, err := open(TerminalRequest{Port: port, Credential: Credential{Username: "root", Password: "test-password"}}); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("changed key (typed): %v", err)
	}
	if _, err := open(TerminalRequest{UseSaved: true}); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("changed key (saved): %v", err)
	}

	// Forget: the next saved login is gone.
	if err := service.ForgetCredential(ctx, actor, nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := open(TerminalRequest{UseSaved: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("forgotten login: %v", err)
	}
	if endpoint, _ := service.Endpoint(ctx, actor, nodeID); endpoint.Saved != nil {
		t.Fatalf("still saved: %+v", endpoint.Saved)
	}

	// No egress configured or detected: the allowlist alone enables it ...
	if _, err := service.SetAccess(ctx, actor, nodeID, AccessChange{Enabled: true}); !errors.Is(err, ErrControllerEgressUnknown) {
		t.Fatalf("empty allowlist: %v", err)
	}
	set, err := service.SetAccess(ctx, actor, nodeID, AccessChange{Enabled: true, AllowCIDRs: []string{"203.0.113.9"}})
	if err != nil || !set.Enabled || set.State != AccessPending || len(set.ControllerCIDRs) != 1 ||
		set.ControllerCIDRs[0] != "203.0.113.9/32" || len(set.AllowCIDRs) != 1 {
		t.Fatalf("allowlist only = %+v, %v", set, err)
	}
	// ... and a detected egress is used as the controller's addresses.
	service.UseEgressDetector(func(context.Context) []string { return []string{"198.51.100.77"} })
	set, err = service.SetAccess(ctx, actor, nodeID, AccessChange{Enabled: true})
	if err != nil || len(set.ControllerCIDRs) != 1 || set.ControllerCIDRs[0] != "198.51.100.77/32" || set.Revision != 2 {
		t.Fatalf("detected = %+v, %v", set, err)
	}
	if controller, source := service.ControllerEgress(ctx); len(controller) != 1 || source != EgressDetected {
		t.Fatalf("egress = %v %s", controller, source)
	}

	// SSH install with restrict_ssh: without an egress it needs the allowlist (409 otherwise) ...
	service.UseEgressDetector(nil)
	install := func(allow []string) ([]Job, error) {
		return service.Create(ctx, actor, CreateRequest{Targets: []Target{{Host: host, Port: port}},
			Credential: Credential{Username: "root", Password: "test-password"}, ControlPlane: "https://console.example.com",
			RestrictSSH: true, AllowCIDRs: allow})
	}
	if _, err := install(nil); !errors.Is(err, ErrControllerEgressUnknown) {
		t.Fatalf("install without egress or allowlist: %v", err)
	}
	if _, err := service.Create(ctx, actor, CreateRequest{Targets: []Target{{Host: host, Port: port}},
		Credential: Credential{Username: "root", Password: "test-password"}, ControlPlane: "https://console.example.com",
		AllowCIDRs: []string{"203.0.113.9"}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("allowlist without restrict_ssh: %v", err)
	}
	jobs, err := install([]string{"203.0.113.9"})
	if err != nil || len(jobs) != 1 || jobs[0].State != StateAwaitingHostKey || !jobs[0].RestrictSSH {
		t.Fatalf("install with allowlist = %+v, %v", jobs, err)
	}
	// ... and the node it registers gets the restriction with that allowlist when it finishes.
	if _, err := pool.Exec(ctx, `UPDATE node_ssh_install_jobs SET state='running',host_key_confirmed=true WHERE id=$1`, jobs[0].ID); err != nil {
		t.Fatal(err)
	}
	service.finish(ctx, claimed{id: jobs[0].ID, scopeID: scopeID, host: host, port: port, username: "root", batchID: jobs[0].BatchID},
		StateSucceeded, "")
	got, err := service.GetAccess(ctx, actor, nodeID)
	if err != nil || !got.Enabled || got.SSHPort != port || got.Revision != 3 || len(got.ControllerCIDRs) != 1 ||
		got.ControllerCIDRs[0] != "203.0.113.9/32" || len(got.AllowCIDRs) != 1 || got.AllowCIDRs[0] != "203.0.113.9/32" {
		t.Fatalf("restriction after install = %+v, %v", got, err)
	}
}
