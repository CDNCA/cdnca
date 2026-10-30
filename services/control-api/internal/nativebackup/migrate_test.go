package nativebackup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

type fakeRemote struct {
	commands []string
	uploads  []string
	answers  map[string]string // command prefix -> stdout
	failing  string            // command substring that fails
	identity *age.X25519Identity
}

func (fake *fakeRemote) Run(_ context.Context, command string, _ func(string)) (string, error) {
	fake.commands = append(fake.commands, command)
	if fake.failing != "" && strings.Contains(command, fake.failing) {
		return "", errors.New("remote command failed")
	}
	if strings.Contains(command, "new-identity") {
		return fake.identity.Recipient().String() + "\n", nil
	}
	for prefix, answer := range fake.answers {
		if strings.HasPrefix(command, prefix) {
			return answer, nil
		}
	}
	return "", nil
}
func (fake *fakeRemote) Upload(_ context.Context, _, remote string, _ os.FileMode) error {
	fake.uploads = append(fake.uploads, remote)
	return nil
}
func (fake *fakeRemote) Close() error { return nil }

func migrationRig(t *testing.T) (*testRig, *fakeRemote, PushMigrator) {
	rig := newRig(t)
	script := rig.host.Layout.Path(DependenciesScript)
	_ = os.MkdirAll(filepath.Dir(script), 0o755)
	_ = os.WriteFile(script, []byte("#!/bin/bash\n"), 0o700)
	binary := filepath.Join(rig.root, "control-api")
	_ = os.WriteFile(binary, []byte("bin"), 0o755)
	identity, _ := age.GenerateX25519Identity()
	remote := &fakeRemote{answers: map[string]string{"id -u": "0\n", "uname -m": "x86_64\n", "for p in": "fresh\n"}, identity: identity}
	migrator := PushMigrator{Backuper: rig.backuper(nil), Binary: binary, ExpectedArch: "x86_64",
		Dial: func(context.Context, MigrationTarget) (Remote, error) { return remote, nil }}
	return rig, remote, migrator
}

var testTarget = MigrationTarget{Host: "203.0.113.9", Port: 22, User: "root", HostKeySHA256: "SHA256:" + strings.Repeat("A", 43), Password: "x"}

func TestPushMigrationHoldsSourceAndTargetCanDecrypt(t *testing.T) {
	rig, remote, migrator := migrationRig(t)
	result, err := migrator.Migrate(context.Background(), testTarget, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	backupID := result.BackupID
	for _, unit := range WriterUnits {
		if state := rig.systemd.states[unit]; state.Active || state.Enabled {
			t.Fatalf("source %s must stay frozen after a migration", unit)
		}
	}
	var restoreAt, depsAt, verifyAt int
	for index, command := range remote.commands {
		switch {
		case strings.Contains(command, "install-ubuntu-dependencies.sh"):
			depsAt = index
		case strings.Contains(command, "native-backup restore"):
			restoreAt = index
			if !strings.Contains(command, rig.keys.Fingerprint()) {
				t.Fatal("the target must pin this host's signer")
			}
		case strings.Contains(command, "verify-migration"):
			verifyAt = index
		}
	}
	if !(depsAt < restoreAt && restoreAt < verifyAt) {
		t.Fatalf("order: %v", remote.commands)
	}
	bundle, err := OpenBundle(filepath.Join(rig.host.Layout.Path(BackupRoot), backupID), rig.keys.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyAll(remote.identity); err != nil {
		t.Fatalf("the target's one-time identity must decrypt: %v", err)
	}
	if len(remote.uploads) != 2+len(ComponentOrder)+1 {
		t.Fatalf("uploads = %v", remote.uploads)
	}
}

func TestPushMigrationRestoreFailureUnfreezesSource(t *testing.T) {
	rig, remote, migrator := migrationRig(t)
	remote.failing = "native-backup restore"
	if _, err := migrator.Migrate(context.Background(), testTarget, func(string) {}); err == nil {
		t.Fatal("expected failure")
	}
	for _, unit := range WriterUnits {
		if state := rig.systemd.states[unit]; !state.Active || !state.Enabled {
			t.Fatalf("source %s must serve again after a failed restore", unit)
		}
	}
}

func TestPushMigrationVerifyFailureKeepsSourceFrozen(t *testing.T) {
	rig, remote, migrator := migrationRig(t)
	remote.failing = "verify-migration"
	if _, err := migrator.Migrate(context.Background(), testTarget, func(string) {}); err == nil {
		t.Fatal("expected failure")
	}
	if rig.systemd.states["cdnca-control-api.service"].Active {
		t.Fatal("after a successful restore the source must stay frozen")
	}
}

func TestPushMigrationRefusesNonFreshTargetBeforeFreezing(t *testing.T) {
	rig, remote, migrator := migrationRig(t)
	remote.answers["for p in"] = ""
	if _, err := migrator.Migrate(context.Background(), testTarget, func(string) {}); err == nil {
		t.Fatal("expected refusal")
	}
	if len(rig.systemd.calls) != 0 {
		t.Fatalf("the source must not be touched: %v", rig.systemd.calls)
	}
}

// fix-btenv: the migration form chooses the target environment (auto, bt,
// plain). A BaoTa target gets a host port profile written before the
// dependency installer runs: busy default ports move, the web port is loopback.
func TestPushMigrationWritesBaoTaPortProfileBeforeDependencies(t *testing.T) {
	for _, tc := range []struct {
		env, panel, listening string
		profile               string
	}{
		{env: "auto", panel: "bt\n", listening: "80\n443\n888\n5432\n6379\n8888\n",
			profile: "ENV=bt\nWEB_PORT=18443\nNODE_DOWNLOAD_PORT=19445\nPG_PORT=15432\nREDIS_PORT=16379\nCH_HTTP_PORT=8123\nCH_TCP_PORT=9000\nCH_MYSQL_PORT=9004\nCH_POSTGRESQL_PORT=9005\nCH_INTERSERVER_PORT=9009\n"},
		{env: "bt", panel: "", listening: "18443\n9000\n",
			profile: "ENV=bt\nWEB_PORT=18444\nNODE_DOWNLOAD_PORT=19445\nPG_PORT=5432\nREDIS_PORT=6379\nCH_HTTP_PORT=8123\nCH_TCP_PORT=19100\nCH_MYSQL_PORT=9004\nCH_POSTGRESQL_PORT=9005\nCH_INTERSERVER_PORT=9009\n"},
		{env: "auto", panel: "", listening: "5432\n"},
		{env: "plain", panel: "bt\n", listening: ""},
	} {
		_, remote, migrator := migrationRig(t)
		remote.answers["test -d /www/server/panel"] = tc.panel
		remote.answers["awk "] = tc.listening
		target := testTarget
		target.Env = tc.env
		_, err := migrator.Migrate(context.Background(), target, func(string) {})
		if tc.env != "bt" && tc.panel == "" && tc.listening == "5432\n" {
			// plain target with a busy default port: refused before freezing.
			if err == nil || !strings.Contains(err.Error(), "5432") {
				t.Fatalf("%+v: busy plain port must be refused, got %v", tc, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%+v: %v", tc, err)
		}
		var profileAt, depsAt = -1, -1
		var written string
		for index, command := range remote.commands {
			if strings.Contains(command, HostPortsFile) && strings.Contains(command, "printf") {
				profileAt, written = index, command
			}
			if strings.Contains(command, "install-ubuntu-dependencies.sh") && depsAt < 0 {
				depsAt = index
			}
		}
		if tc.profile == "" {
			if profileAt >= 0 {
				t.Fatalf("%+v: plain target must not get a profile: %s", tc, written)
			}
			continue
		}
		if profileAt < 0 || profileAt > depsAt {
			t.Fatalf("%+v: profile must be written before dependencies: %v", tc, remote.commands)
		}
		if !strings.Contains(written, quote(tc.profile)) {
			t.Fatalf("%+v: profile command = %s", tc, written)
		}
	}
}

// fix-btenv3: the target's direct download port skips this host's Gateway
// ports (restored as they are) and busy ports, starting at 19445.
func TestPushMigrationBaoTaDownloadPortAvoidsGatewayPorts(t *testing.T) {
	for _, tc := range []struct {
		gateway, listening, want string
	}{
		{gateway: "CDNCA_GATEWAY_ENROLLMENT_ADDR=0.0.0.0:19443\nCDNCA_GATEWAY_AGENT_ADDR=0.0.0.0:19444\n", want: "19445"},
		{gateway: "CDNCA_GATEWAY_ENROLLMENT_ADDR=0.0.0.0:19445\nCDNCA_GATEWAY_AGENT_ADDR=0.0.0.0:19446\n", want: "19447"},
		{gateway: "CDNCA_GATEWAY_ENROLLMENT_ADDR=0.0.0.0:21443\nCDNCA_GATEWAY_AGENT_ADDR=0.0.0.0:19446\n", listening: "19445\n", want: "19447"},
	} {
		rig, remote, migrator := migrationRig(t)
		writeRetargetFixture(t, rig.host.Layout, map[string]string{ConfigDirectory + "/gateway.env": tc.gateway})
		remote.answers["test -d /www/server/panel"] = "bt\n"
		remote.answers["awk "] = tc.listening
		var logs []string
		if _, err := migrator.Migrate(context.Background(), testTarget, func(line string) { logs = append(logs, line) }); err != nil {
			t.Fatalf("%+v: %v", tc, err)
		}
		var written string
		for _, command := range remote.commands {
			if strings.Contains(command, HostPortsFile) && strings.Contains(command, "printf") {
				written = command
			}
		}
		if !strings.Contains(written, "NODE_DOWNLOAD_PORT="+tc.want+"\n") {
			t.Fatalf("%+v: profile command = %s", tc, written)
		}
		if !strings.Contains(strings.Join(logs, "\n"), "节点升级下载端口 "+tc.want) {
			t.Fatalf("%+v: the BaoTa steps must name the download port: %v", tc, logs)
		}
	}
}

func TestMigrationTargetEnvValidation(t *testing.T) {
	for _, env := range []string{"", "auto", "bt", "plain"} {
		target := testTarget
		target.Env = env
		if err := target.Validate(); err != nil {
			t.Fatalf("%q: %v", env, err)
		}
	}
	target := testTarget
	target.Env = "docker"
	if target.Validate() == nil {
		t.Fatal("unknown env must be refused")
	}
}
