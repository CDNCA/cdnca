package nativebackup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Remote runs commands on and copies files to a migration target.
type Remote interface {
	Run(ctx context.Context, command string, log func(string)) (string, error)
	Upload(ctx context.Context, local, remote string, mode os.FileMode) error
	Close() error
}

// DependenciesScript is the signed dependency installer kept by the fresh
// installer, so a migration target installs the same pinned PostgreSQL,
// ClickHouse, Redis, ClamAV and nginx without downloading a package.
const DependenciesScript = SupportDirectory + "/install-ubuntu-dependencies.sh"

const remoteStaging = AgentRoot + "/migrate-in"

var recipientPattern = regexp.MustCompile(`^age1[0-9a-z]{58}$`)

// ErrMigrationStopped: a stop request ended the migration before the target
// restore started; this host was unfrozen (or never frozen).
var ErrMigrationStopped = errors.New("migration stopped before the restore; this control plane serves again")

// ErrMigrationAborted: a stop request ended the migration after the target
// restore started. This host stays frozen; the target must be cleaned.
var ErrMigrationAborted = errors.New("migration aborted after the restore started; this control plane stays frozen and the new host must be cleaned")

// ErrNotStoppable: only a running migration can be stopped.
var ErrNotStoppable = errors.New("only a running migration can be stopped")

// TargetCleanCommand is run as root on the new host to remove a partial or
// finished restore (services stopped and disabled, every component removed).
func TargetCleanCommand(backupID, signer string) string {
	return remoteStaging + "/control-api native-backup clean-target --bundle " + BackupRoot + "/" + backupID + " --signer " + signer
}

// PushMigrator moves this host to a fresh one: install dependencies there,
// take a held backup encrypted to a one-time identity of the target, copy it,
// restore it there and verify. A failure before the target restore succeeds
// unfreezes this host again; after that the source stays frozen so two
// control planes never run on diverging copies of the same database.
type PushMigrator struct {
	Backuper     Backuper
	Dial         func(context.Context, MigrationTarget) (Remote, error)
	Binary       string // this host's control-api executable
	ExpectedArch string // "x86_64"
}

func quote(value string) string { return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'" }

// MigrationResult is a finished (or partly finished) migration: the backup
// taken on this host and the detected target environment (bt or plain).
type MigrationResult struct {
	BackupID  string
	TargetEnv string
}

func (migrator PushMigrator) Migrate(ctx context.Context, target MigrationTarget, log func(string)) (MigrationResult, error) {
	var result MigrationResult
	backupID, err := migrator.migrate(ctx, target, log, &result)
	result.BackupID = backupID
	return result, err
}

func (migrator PushMigrator) migrate(ctx context.Context, target MigrationTarget, log func(string), outcome *MigrationResult) (backupID string, err error) {
	layout := migrator.Backuper.Host.Layout
	dependencies := layout.Path(DependenciesScript)
	if _, err := os.Stat(dependencies); err != nil {
		return "", errors.New("本机缺少依赖安装脚本 " + DependenciesScript + "（安装早于本功能）；请在新机用 install-control.sh migrate-from 并提供 --dependencies-script")
	}
	// stopped turns a failure caused by a stop request into ErrMigrationStopped
	// (this host is not frozen, or the backup/transfer failure unfroze it).
	stopped := func(err error) error {
		if ctx.Err() != nil {
			return errors.Join(ErrMigrationStopped, err)
		}
		return err
	}
	log("phase: " + PhaseConnect)
	log("connect: " + target.Host)
	remote, err := migrator.Dial(ctx, target)
	if err != nil {
		return "", stopped(fmt.Errorf("SSH 连接新主控失败：%w", err))
	}
	defer remote.Close()
	check := func(command, want, message string) error {
		got, err := remote.Run(ctx, command, nil)
		if err != nil || strings.TrimSpace(got) != want {
			return errors.New(message)
		}
		return nil
	}
	if err := check("id -u", "0", "新主控必须以 root 登录"); err != nil {
		return "", err
	}
	if err := check("uname -m", migrator.ExpectedArch, "新主控架构必须是 "+migrator.ExpectedArch); err != nil {
		return "", err
	}
	if err := check("for p in "+ConfigDirectory+" "+DataDirectory+" "+NativeRoot+"; do test -e $p && exit 0; done; echo fresh", "fresh",
		"新主控已有主控安装状态；迁移只接受全新系统"); err != nil {
		return "", err
	}
	log("phase: " + PhasePrepareTarget)
	staging := remoteStaging
	if _, err := remote.Run(ctx, "install -d -m 0700 "+quote(AgentRoot)+" "+quote(staging)+" "+quote(BackupRoot), nil); err != nil {
		return "", err
	}
	profile, err := planTargetPorts(ctx, remote, target.Env, sourceGatewayPorts(layout), log)
	if err != nil {
		return "", err
	}
	outcome.TargetEnv = "plain"
	if profile != "" {
		outcome.TargetEnv = "bt"
	}
	log("upload: control-api and dependency installer")
	if err := remote.Upload(ctx, migrator.Binary, staging+"/control-api", 0o755); err != nil {
		return "", err
	}
	if err := remote.Upload(ctx, dependencies, staging+"/install-ubuntu-dependencies.sh", 0o700); err != nil {
		return "", err
	}
	if profile != "" {
		if _, err := remote.Run(ctx, "install -d -m 0755 "+quote(path.Dir(HostPortsFile))+" && printf '%s' "+quote(profile)+
			" > "+quote(HostPortsFile)+" && chmod 0644 "+quote(HostPortsFile), nil); err != nil {
			return "", fmt.Errorf("新主控端口档案写入失败：%w", err)
		}
	}
	log("target: installing dependencies (PostgreSQL, ClickHouse, Redis, ClamAV, nginx)")
	if _, err := remote.Run(ctx, "bash "+quote(staging+"/install-ubuntu-dependencies.sh")+" install", log); err != nil {
		return "", stopped(fmt.Errorf("新主控依赖安装失败：%w", err))
	}
	recipient, err := remote.Run(ctx, quote(staging+"/control-api")+" native-backup new-identity --file "+quote(staging+"/identity"), nil)
	recipient = strings.TrimSpace(recipient)
	if err != nil || !recipientPattern.MatchString(recipient) {
		return "", stopped(errors.New("新主控未能生成一次性接收密钥"))
	}
	if ctx.Err() != nil {
		return "", ErrMigrationStopped
	}
	log("phase: " + PhaseBackup)
	backuper := migrator.Backuper
	backuper.Progress = log
	result, err := backuper.Run(ctx, BackupRequest{Reason: "migration", Hold: true, ExtraRecipients: []string{recipient},
		OutputDirectory: layout.Path(BackupRoot)})
	if err != nil {
		return "", stopped(err)
	}
	restored := false
	defer func() {
		if err != nil && !restored {
			log("rollback: restarting this control plane")
			if unfreezeErr := backuper.Freezer.Unfreeze(context.WithoutCancel(ctx)); unfreezeErr != nil {
				err = errors.Join(err, fmt.Errorf("旧主控解冻失败，请执行 control-api native-backup unfreeze：%w", unfreezeErr))
			}
		}
	}()
	remoteBundle := BackupRoot + "/" + result.BackupID
	log("phase: " + PhaseTransfer)
	log("copy: " + result.BackupID)
	if _, err = remote.Run(ctx, "install -d -m 0700 "+quote(remoteBundle), nil); err != nil {
		return result.BackupID, stopped(err)
	}
	entries, err := os.ReadDir(result.Directory)
	if err != nil {
		return result.BackupID, err
	}
	for _, entry := range entries {
		if err = remote.Upload(ctx, filepath.Join(result.Directory, entry.Name()), remoteBundle+"/"+entry.Name(), 0o600); err != nil {
			return result.BackupID, stopped(err)
		}
	}
	// Last safe point: once the restore starts the target may come up.
	if ctx.Err() != nil {
		err = ErrMigrationStopped
		return result.BackupID, err
	}
	log("phase: " + PhaseRestore)
	log("target: restoring")
	_, err = remote.Run(ctx, quote(staging+"/control-api")+" native-backup restore --bundle "+quote(remoteBundle)+
		" --signer "+quote(backuper.Keys.Fingerprint())+" --identity "+quote(staging+"/identity"), log)
	if err != nil && ctx.Err() != nil {
		// Stopped mid-restore: the target may have started its services.
		// Keep this host frozen; only a rollback with the new-master check
		// restarts it.
		restored = true
		log("clean the new host: " + TargetCleanCommand(result.BackupID, backuper.Keys.Fingerprint()))
		return result.BackupID, errors.Join(ErrMigrationAborted, err)
	}
	if err != nil {
		return result.BackupID, fmt.Errorf("新主控恢复失败（已自动清理新主控）：%w", err)
	}
	restored = true
	_, _ = remote.Run(ctx, "rm -f "+quote(staging+"/identity"), nil)
	log("phase: " + PhaseVerify)
	log("target: verifying")
	if _, verifyErr := remote.Run(ctx, quote(NativeRoot+"/current/bin/control-api")+" native-backup verify-migration --bundle "+quote(remoteBundle), log); verifyErr != nil {
		if ctx.Err() != nil {
			return result.BackupID, errors.Join(ErrMigrationAborted, verifyErr)
		}
		return result.BackupID, fmt.Errorf("新主控已恢复但校验未通过，旧主控保持冻结：%w", verifyErr)
	}
	if profile != "" {
		log("宝塔目标：新主控管理端网页只监听 127.0.0.1:" + profileValue(profile, "WEB_PORT") + "，请在新主控的宝塔里配置反向代理：" +
			"①「网站」添加站点（管理端域名，纯静态）并在「SSL」申请证书；②站点「反向代理」目标 URL https://127.0.0.1:" + profileValue(profile, "WEB_PORT") +
			"，发送域名 $host，或把新主控 " + BaoTaProxyFile + " 的内容加入站点配置；③宝塔「安全」放行管理端、网关与节点升级下载端口 " + profileValue(profile, "NODE_DOWNLOAD_PORT"))
	}
	log("phase: " + PhaseDone)
	log("done: switch DNS of the control and Gateway domains to the new host; the new control-api republishes the node install trust for the new address within 10 minutes " +
		"(or run " + NativeRoot + "/current/bin/control-api native-backup verify-migration --bundle " + remoteBundle +
		" there to do it now); this host stays frozen (rollback: control-api native-backup unfreeze)")
	return result.BackupID, nil
}

// SSHRemote is the production Remote over golang.org/x/crypto/ssh + SFTP.
type SSHRemote struct {
	client *ssh.Client
	sftp   *sftp.Client
}

func DialRemote(ctx context.Context, target MigrationTarget) (Remote, error) {
	auth, err := SSHAuth(target.Password, target.PrivateKey)
	if err != nil {
		return nil, err
	}
	client, err := DialSSH(ctx, target.Host, target.Port, target.User, auth, target.HostKeySHA256)
	if err != nil {
		return nil, err
	}
	transfer, err := sftp.NewClient(client)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return &SSHRemote{client: client, sftp: transfer}, nil
}

func (remote *SSHRemote) Run(ctx context.Context, command string, log func(string)) (string, error) {
	session, err := remote.client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()
	if err := session.Start(command); err != nil {
		return "", err
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Signal(ssh.SIGTERM)
			_ = session.Close()
		case <-done:
		}
	}()
	var output strings.Builder
	lines := func(reader io.Reader, keep bool) chan struct{} {
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			scanner := bufio.NewScanner(reader)
			scanner.Buffer(make([]byte, 64<<10), 1<<20)
			for scanner.Scan() {
				if keep && output.Len() < 1<<20 {
					output.WriteString(scanner.Text() + "\n")
				}
				if log != nil {
					log("target: " + scanner.Text())
				}
			}
		}()
		return finished
	}
	outDone, errDone := lines(stdout, true), lines(stderr, false)
	<-outDone
	<-errDone
	err = session.Wait()
	close(done)
	return output.String(), err
}

func (remote *SSHRemote) Upload(_ context.Context, local, destination string, mode os.FileMode) error {
	source, err := os.Open(local)
	if err != nil {
		return err
	}
	defer source.Close()
	if err := remote.sftp.MkdirAll(path.Dir(destination)); err != nil {
		return err
	}
	file, err := remote.sftp.OpenFile(destination+".part", os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, source); err != nil {
		_ = file.Close()
		return err
	}
	if err := errors.Join(file.Chmod(mode), file.Close()); err != nil {
		return err
	}
	return remote.sftp.PosixRename(destination+".part", destination)
}

func (remote *SSHRemote) Close() error {
	return errors.Join(remote.sftp.Close(), remote.client.Close())
}

// Fixed control-plane ports (install-control.sh NATIVE_RESERVED_PORTS): a
// moved dependency or the BaoTa web port never takes one of them.
var targetReservedPorts = map[int]bool{80: true, 4222: true, 4223: true, 5432: true, 6379: true, 6380: true, 8080: true, 8082: true,
	8123: true, 8222: true, 9000: true, 9004: true, 9005: true, 9009: true, 9091: true, 9445: true, 9446: true, 19000: true}

// targetDependencyPorts mirrors install-control.sh plan_install_ports: key,
// default port, first replacement candidate, label.
var targetDependencyPorts = []struct {
	key               string
	fallback, prefers int
	label             string
}{
	{"PG_PORT", 5432, 15432, "PostgreSQL"}, {"REDIS_PORT", 6379, 16379, "Redis"}, {"CH_HTTP_PORT", 8123, 18123, "ClickHouse-HTTP"},
	{"CH_TCP_PORT", 9000, 19100, "ClickHouse"}, {"CH_MYSQL_PORT", 9004, 19104, "ClickHouse-MySQL"},
	{"CH_POSTGRESQL_PORT", 9005, 19105, "ClickHouse-PostgreSQL"}, {"CH_INTERSERVER_PORT", 9009, 19109, "ClickHouse-复制"},
}

// planTargetPorts detects the target environment and returns the host port
// profile for a BaoTa target ("" for a plain one). A plain target with a
// busy dependency port is refused here, before this host is frozen.
func planTargetPorts(ctx context.Context, remote Remote, env string, gateway map[int]bool, log func(string)) (string, error) {
	if env == "" || env == "auto" {
		panel, err := remote.Run(ctx, "test -d /www/server/panel && echo bt || { command -v bt >/dev/null 2>&1 && echo bt; } || true", nil)
		if err != nil {
			return "", err
		}
		env = "plain"
		if strings.TrimSpace(panel) == "bt" {
			env = "bt"
		}
	}
	// Same /proc/net/tcp{,6} LISTEN (0A) reading as the installer preflight;
	// hex ports are converted by printf (mawk has no strtonum).
	listing, err := remote.Run(ctx, `awk 'FNR > 1 && $4 == "0A" { split($2, a, ":"); print a[2] }' /proc/net/tcp /proc/net/tcp6 2>/dev/null |`+
		` while read -r hex; do printf '%d\n' "0x$hex"; done | sort -un`, nil)
	if err != nil {
		return "", err
	}
	busy := map[int]bool{}
	for _, field := range strings.Fields(listing) {
		if port, err := strconv.Atoi(field); err == nil {
			busy[port] = true
		}
	}
	if env != "bt" {
		var taken []string
		for _, dependency := range targetDependencyPorts {
			if busy[dependency.fallback] {
				taken = append(taken, fmt.Sprintf("%d（%s）", dependency.fallback, dependency.label))
			}
		}
		if len(taken) > 0 {
			return "", errors.New("新主控端口已被占用：" + strings.Join(taken, "、") + "；若新主控装了宝塔面板，请把目标环境选为“宝塔”")
		}
		log("target: plain environment")
		return "", nil
	}
	used := map[int]bool{}
	pick := func(start int, label string) (int, error) {
		for port := start; port <= start+100; port++ {
			if !busy[port] && !used[port] && !targetReservedPorts[port] && !gateway[port] {
				used[port] = true
				return port, nil
			}
		}
		return 0, fmt.Errorf("新主控 %d-%d 内没有可用于 %s 的空闲端口", start, start+100, label)
	}
	web, err := pick(18443, "管理端网页")
	if err != nil {
		return "", err
	}
	// Same default and rule as install-control.sh: 19445 avoids the node
	// installer's Gateway defaults 19443/19444; the restored Gateway keeps this
	// host's ports, so those are skipped as well.
	download, err := pick(19445, "节点升级下载")
	if err != nil {
		return "", err
	}
	if download != 19445 {
		log(fmt.Sprintf("target: node upgrade downloads 19445 is busy or a Gateway port, using %d", download))
	}
	profile := "ENV=bt\nWEB_PORT=" + strconv.Itoa(web) + "\nNODE_DOWNLOAD_PORT=" + strconv.Itoa(download) + "\n"
	for _, dependency := range targetDependencyPorts {
		port := dependency.fallback
		if busy[port] {
			if port, err = pick(dependency.prefers, dependency.label); err != nil {
				return "", err
			}
			log(fmt.Sprintf("target: %s %d is busy, using %d", dependency.label, dependency.fallback, port))
		}
		used[port] = true
		profile += dependency.key + "=" + strconv.Itoa(port) + "\n"
	}
	log("target: BaoTa environment, management web on 127.0.0.1:" + strconv.Itoa(web))
	return profile, nil
}

// sourceGatewayPorts are the Gateway listener ports of this host
// (gateway.env); the restored Gateway listens on them on the target too.
func sourceGatewayPorts(layout Layout) map[int]bool {
	ports := map[int]bool{}
	environment, err := ReadEnvironmentFile(layout.Path(ConfigDirectory + "/gateway.env"))
	if err != nil {
		return ports
	}
	for _, key := range []string{"CDNCA_GATEWAY_ENROLLMENT_ADDR", "CDNCA_GATEWAY_AGENT_ADDR"} {
		value := environment[key]
		if port, err := strconv.Atoi(value[strings.LastIndex(value, ":")+1:]); strings.Contains(value, ":") && err == nil {
			ports[port] = true
		}
	}
	return ports
}

// profileValue reads KEY from a port profile built by planTargetPorts.
func profileValue(profile, key string) string {
	for _, line := range strings.Split(profile, "\n") {
		if value, ok := strings.CutPrefix(line, key+"="); ok {
			return value
		}
	}
	return ""
}
