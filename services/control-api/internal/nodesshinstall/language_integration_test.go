//go:build integration

package nodesshinstall

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
)

// node-cmd-lang2 (migration 610): Create stores the request language on the
// job row and the worker's claim reads it back for InstallCommand.
func TestSSHInstallLanguageStoredAndClaimed(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	scopeID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ssh-lang','SSH lang','unused')`,
		userID); err != nil {
		t.Fatal(err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("ssh-test-key", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	// A closed loopback port: the host key fetch fails at once and the job is stored as failed.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	dialer := NewDialer(func(address netip.Addr) bool { return !address.IsLoopback() && defaultBlocked(address) })
	service, err := New(Config{Pool: pool, Cipher: cipher, Registration: fixedRegistration{}, Dialer: dialer})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, RequestID: "ssh-lang-test", IP: "198.51.100.1"}
	for _, language := range []string{"", "zh", "en"} {
		jobs, err := service.Create(ctx, actor, CreateRequest{Targets: []Target{{Host: "127.0.0.1", Port: closedPort}},
			Credential: Credential{Username: "root", Password: "x"}, ControlPlane: "https://console.example.com", Language: language})
		if err != nil || len(jobs) != 1 {
			t.Fatalf("create %q: %+v %v", language, jobs, err)
		}
		var stored string
		if err := pool.QueryRow(ctx, `SELECT language FROM node_ssh_install_jobs WHERE id=$1`, jobs[0].ID).Scan(&stored); err != nil ||
			stored != language {
			t.Fatalf("stored language %q %v, want %q", stored, err, language)
		}
	}
	// A due job: claim hands the language to the worker.
	jobID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO node_ssh_install_jobs(id,scope_id,batch_id,host,port,username,auth_kind,
		control_plane,host_key_sha256,host_key_confirmed,credential_key_id,credential_ciphertext,state,created_by_user_id,
		created_at,updated_at,language) VALUES($1,$2,$1,'203.0.113.7',22,'root','password','https://console.example.com',
		'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',true,'k','\x01','pending',$3,now(),now(),'zh')`,
		jobID, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	job, ok, err := service.claim(ctx)
	if err != nil || !ok || job.id != jobID || job.language != "zh" {
		t.Fatalf("claim: id=%v language=%q ok=%v err=%v", job.id, job.language, ok, err)
	}
}
