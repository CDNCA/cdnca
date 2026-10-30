//go:build integration

package nodesshinstall

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"
)

// The SSH target is a throwaway local container (testdata/sshd, docker run
// --rm); no real server is ever contacted. Build the image first:
//
//	docker build -t cdnca-test-sshd:ge-nodes internal/nodesshinstall/testdata/sshd
const sshdImage = "cdnca-test-sshd:ge-nodes"

const testRegistrationKey = "nrk1.0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type fixedRegistration struct{}

func (fixedRegistration) RegistrationCredential(context.Context, node.Actor, string) (node.RegistrationCredential, error) {
	return node.RegistrationCredential{KeyID: uuid.New(), Credential: testRegistrationKey, IssuedAt: time.Now()}, nil
}

type sshdContainer struct {
	name string
	port int
}

func startSSHD(t *testing.T, authorizedKey string) sshdContainer {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	if err := exec.Command("docker", "image", "inspect", sshdImage).Run(); err != nil {
		t.Skipf("image %s is not built", sshdImage)
	}
	name := "cdnca-ge-nodes-sshd-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	output, err := exec.Command("docker", "run", "--rm", "-d", "--name", name, "-p", "127.0.0.1::22",
		"-e", "ROOT_PASSWORD=root-test-password", "-e", "DEPLOY_PASSWORD=deploy-test-password",
		"-e", "AUTHORIZED_KEY="+authorizedKey, sshdImage).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	mapped, err := exec.Command("docker", "port", name, "22/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, portText, _ := strings.Cut(strings.TrimSpace(strings.Split(string(mapped), "\n")[0]), ":")
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("docker port %q", mapped)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", portText), time.Second); err == nil {
			buffer := make([]byte, 4)
			_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ := connection.Read(buffer)
			_ = connection.Close()
			if n == 4 && string(buffer) == "SSH-" {
				return sshdContainer{name: name, port: port}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("sshd did not start")
	return sshdContainer{}
}

func (container sshdContainer) read(t *testing.T, path string) string {
	t.Helper()
	output, err := exec.Command("docker", "exec", container.name, "cat", path).Output()
	if err != nil {
		return ""
	}
	return string(output)
}

func (container sshdContainer) exec(t *testing.T, arguments ...string) {
	t.Helper()
	if output, err := exec.Command("docker", append([]string{"exec", container.name}, arguments...)...).CombinedOutput(); err != nil {
		t.Fatalf("docker exec %v: %v %s", arguments, err, output)
	}
}

// assertKeyOnStdinOnly: the real install-node.sh (copied to /opt) read the
// registration key from stdin, and no process command line on the host
// (snapshot taken by the fake installer while it ran) nor the installer's
// arguments carried it.
func (container sshdContainer) assertKeyOnStdinOnly(t *testing.T) {
	t.Helper()
	if key := strings.TrimSpace(container.read(t, "/tmp/install-key")); key != testRegistrationKey {
		t.Fatalf("installer read key %q from stdin", key)
	}
	processes := container.read(t, "/tmp/install-ps")
	if !strings.Contains(processes, "/install-node.sh --control-plane") {
		t.Fatalf("process snapshot misses the installer:\n%s", processes)
	}
	if strings.Contains(processes, testRegistrationKey) || strings.Contains(container.read(t, "/tmp/install-args"), testRegistrationKey) {
		t.Fatalf("registration key visible in process arguments:\n%s", processes)
	}
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "node_ssh_install_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := databasetest.CleanupContext()
		defer done()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE")
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}

// TestSSHInstallAgainstRealSSHD: host key fetched and confirmed before any
// login; root with a password and with a private key, and a sudo user whose
// password reaches sudo on stdin, run the console's install command; only
// the installer's own lines are kept; the secret is wiped; a wrong host key,
// a wrong password and a failing installer end the job with a code.
func TestSSHInstallAgainstRealSSHD(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := string(pem.EncodeToMemory(block))
	container := startSSHD(t, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic))))
	if output, err := exec.Command("docker", "cp", "../../../../scripts/install-node.sh", container.name+":/opt/install-node.sh").
		CombinedOutput(); err != nil {
		t.Fatalf("docker cp install-node.sh: %v %s", err, output)
	}
	// The stand-in curl comes from this checkout, not from whenever the image
	// was last built: a stale image prints another progress prefix.
	if output, err := exec.Command("docker", "cp", "testdata/sshd/curl", container.name+":/usr/local/bin/curl").
		CombinedOutput(); err != nil {
		t.Fatalf("docker cp curl: %v %s", err, output)
	}
	if output, err := exec.Command("docker", "exec", container.name, "chmod", "0755", "/usr/local/bin/curl").
		CombinedOutput(); err != nil {
		t.Fatalf("chmod curl: %v %s", err, output)
	}
	pool := testPool(t)
	ctx := t.Context()
	scopeID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ssh-install','SSH install','unused')`,
		userID); err != nil {
		t.Fatal(err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("ssh-test-key", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	// The container listens on loopback: allow it in this test only.
	dialer := NewDialer(func(address netip.Addr) bool { return !address.IsLoopback() && defaultBlocked(address) })
	service, err := New(Config{Pool: pool, Cipher: cipher, Registration: fixedRegistration{}, Dialer: dialer})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, RequestID: "ssh-install-test", IP: "198.51.100.1"}
	create := func(credential Credential) Job {
		t.Helper()
		jobs, err := service.Create(ctx, actor, CreateRequest{Targets: []Target{{Host: "127.0.0.1", Port: container.port, Name: "edge-1"}},
			Credential: credential, ControlPlane: "https://console.example.com"})
		if err != nil || len(jobs) != 1 {
			t.Fatalf("create: %+v %v", jobs, err)
		}
		return jobs[0]
	}
	run := func(job Job, fingerprint string) Job {
		t.Helper()
		if _, err := service.ConfirmHostKey(ctx, actor, job.ID, fingerprint); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		if err := service.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		done, err := service.Get(ctx, actor, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		return done
	}
	secretStored := func(jobID uuid.UUID) bool {
		var stored bool
		if err := pool.QueryRow(ctx, `SELECT credential_ciphertext IS NOT NULL FROM node_ssh_install_jobs WHERE id=$1`,
			jobID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		return stored
	}

	// 1. root + password.
	job := create(Credential{Username: "root", Password: "root-test-password"})
	if job.State != StateAwaitingHostKey || !hostKeyPattern.MatchString(job.HostKeySHA256) || !secretStored(job.ID) {
		t.Fatalf("created = %+v", job)
	}
	var plain bool
	if err := pool.QueryRow(ctx, `SELECT position('root-test-password'::bytea in credential_ciphertext)>0
		FROM node_ssh_install_jobs WHERE id=$1`, job.ID).Scan(&plain); err != nil || plain {
		t.Fatalf("password stored in clear: %v %v", plain, err)
	}
	if _, err := service.ConfirmHostKey(ctx, actor, job.ID, "SHA256:"+strings.Repeat("A", 43)); err == nil {
		t.Fatal("a different fingerprint was confirmed")
	}
	done := run(job, job.HostKeySHA256)
	if done.State != StateSucceeded || secretStored(job.ID) {
		t.Fatalf("root password job = %+v", done)
	}
	if strings.Join(done.Progress, "|") != "[cdnca-edge] preflight passed|[cdnca-edge] edge-agent installed and enrolled" {
		t.Fatalf("progress = %q", done.Progress)
	}
	args := container.read(t, "/tmp/install-args")
	for _, want := range []string{"--control-plane\nhttps://console.example.com\n", "--registration-key-stdin\n",
		"--public-ip\n127.0.0.1\n", "--node-name\nedge-1\n", "-y\n"} {
		if !strings.Contains(args, want) {
			t.Errorf("installer args missing %q:\n%s", want, args)
		}
	}
	container.assertKeyOnStdinOnly(t)
	if url := strings.TrimSpace(container.read(t, "/tmp/curl-url")); url != "https://console.example.com/downloads/install-node.sh" {
		t.Fatalf("download url = %q", url)
	}
	if uid := strings.TrimSpace(container.read(t, "/tmp/install-uid")); uid != "0" {
		t.Fatalf("installer uid = %q", uid)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action IN
		('node.ssh_install.create','node.ssh_install.host_key.confirm','node.ssh_install.succeeded')`, job.ID.String()).
		Scan(&audits); err != nil || audits != 3 {
		t.Fatalf("audits = %d (%v)", audits, err)
	}
	var leaked int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE payload::text LIKE '%root-test-password%'
		OR payload::text LIKE '%`+testRegistrationKey+`%'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("secret in audit payload: %d (%v)", leaked, err)
	}

	// 2. root + private key.
	container.exec(t, "rm", "-f", "/tmp/install-args")
	job = create(Credential{Username: "root", PrivateKey: privatePEM})
	if done = run(job, job.HostKeySHA256); done.State != StateSucceeded || container.read(t, "/tmp/install-args") == "" {
		t.Fatalf("private key job = %+v", done)
	}

	// 3. sudo user + password (sudo reads it on stdin).
	container.exec(t, "rm", "-f", "/tmp/install-args", "/tmp/install-uid", "/tmp/install-ps", "/tmp/install-key")
	job = create(Credential{Username: "deploy", Password: "deploy-test-password"})
	if done = run(job, job.HostKeySHA256); done.State != StateSucceeded {
		t.Fatalf("sudo job = %+v", done)
	}
	if uid := strings.TrimSpace(container.read(t, "/tmp/install-uid")); uid != "0" {
		t.Fatalf("sudo installer uid = %q", uid)
	}
	container.assertKeyOnStdinOnly(t)

	// 4. wrong password.
	job = create(Credential{Username: "root", Password: "wrong-password"})
	if done = run(job, job.HostKeySHA256); done.State != StateFailed || done.FailureCode != FailAuth || secretStored(job.ID) {
		t.Fatalf("wrong password job = %+v", done)
	}

	// 5. the installer fails.
	container.exec(t, "touch", "/tmp/install-fail")
	job = create(Credential{Username: "root", Password: "root-test-password"})
	if done = run(job, job.HostKeySHA256); done.State != StateFailed || done.FailureCode != FailInstall ||
		!strings.Contains(strings.Join(done.Progress, "|"), "simulated failure") {
		t.Fatalf("failing installer job = %+v", done)
	}
	container.exec(t, "rm", "-f", "/tmp/install-fail")

	// 6. the host key changed after confirmation (MITM): refused before login.
	job = create(Credential{Username: "root", Password: "root-test-password"})
	if _, err := pool.Exec(ctx, `UPDATE node_ssh_install_jobs SET host_key_sha256=$2 WHERE id=$1`, job.ID,
		"SHA256:"+strings.Repeat("B", 43)); err != nil {
		t.Fatal(err)
	}
	if done = run(job, "SHA256:"+strings.Repeat("B", 43)); done.State != StateFailed || done.FailureCode != FailHostKeyMismatch {
		t.Fatalf("host key mismatch job = %+v", done)
	}

	// 7. one live job per host; cancel frees it.
	job = create(Credential{Username: "root", Password: "root-test-password"})
	if _, err := service.Create(ctx, actor, CreateRequest{Targets: []Target{{Host: "127.0.0.1", Port: container.port}},
		Credential: Credential{Username: "root", Password: "x"}, ControlPlane: "https://console.example.com"}); err != ErrDuplicate {
		t.Fatalf("duplicate live job: %v", err)
	}
	if cancelled, err := service.Cancel(ctx, actor, job.ID); err != nil || cancelled.State != StateCancelled || secretStored(job.ID) {
		t.Fatalf("cancel = %+v %v", cancelled, err)
	}
}
