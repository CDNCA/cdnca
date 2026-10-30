package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/controlbackuphttp"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nativebackup"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/term"
)

const nativeBackupUsage = `usage: control-api native-backup <command>
  create [--reason manual|scheduled|migration] [--hold] [--recipient AGE_RECIPIENT]... [--output DIR]
  list
  verify --bundle DIR [--signer SHA256:...] [--identity FILE | --recovery-kit FILE]
  restore --bundle DIR (--signer SHA256:... --identity FILE | --recovery-kit FILE) [--compensate]
  unfreeze                      end a freeze/migration hold and restart the writers (rollback)
  status                        freeze state, signer fingerprint, recipient, recent runs
  fingerprint                   print this host's backup signer fingerprint
  export-recovery-kit --output FILE   (passphrase read from the terminal or stdin)
  new-identity --file FILE      one-time receive identity for a migration target; prints the recipient
  verify-migration --bundle DIR [--wait-nodes DURATION]
  migrate-to --host HOST [--port 22] [--user root] --host-key SHA256:... (--password-stdin | --private-key FILE)
  host-key --host HOST [--port 22]
  fetch --target NAME --backup-id ID [--signer SHA256:...]
  clean-target --bundle DIR --signer SHA256:...   on a migration target: stop the restored services and remove the restore
  frozen-console                serve migration status, stop and rollback while this host is held (systemd unit)
  agent                         run queued jobs, the schedule and retention (systemd unit)
  install-units                 install and enable the agent path/timer units
  publish-node-install-trust    (re)publish the node install trust from control.env; prints its SHA-256`

func runNativeBackup(args []string) error {
	if len(args) == 0 {
		return errors.New(nativeBackupUsage)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	host := nativeBackupHost()
	command, args := args[0], args[1:]
	switch command {
	case "create":
		return nativeBackupCreate(ctx, host, args)
	case "list":
		return nativeBackupList(host)
	case "verify":
		return nativeBackupVerify(host, args)
	case "restore":
		return nativeBackupRestore(ctx, host, args)
	case "unfreeze":
		return nativeBackupFreezer(host).Unfreeze(ctx)
	case "status":
		return nativeBackupStatus(host)
	case "fingerprint":
		keys, err := nativebackup.LoadOrCreateKeys(host.Layout)
		if err != nil {
			return err
		}
		fmt.Println(keys.Fingerprint())
		return nil
	case "export-recovery-kit":
		return nativeBackupExportKit(host, args)
	case "new-identity":
		flags := flag.NewFlagSet("new-identity", flag.ContinueOnError)
		file := flags.String("file", "", "owner-only identity file to create")
		if err := flags.Parse(args); err != nil || *file == "" || !filepath.IsAbs(*file) {
			return errors.New("usage: control-api native-backup new-identity --file ABSOLUTE_FILE")
		}
		identity, err := nativebackup.NewEphemeralIdentity(*file)
		if err != nil {
			return err
		}
		fmt.Println(identity.Recipient().String())
		return nil
	case "verify-migration":
		return nativeBackupVerifyMigration(ctx, host, args)
	case "migrate-to":
		return nativeBackupMigrateTo(ctx, host, args)
	case "host-key":
		flags := flag.NewFlagSet("host-key", flag.ContinueOnError)
		target := flags.String("host", "", "SSH host")
		port := flags.Int("port", 22, "SSH port")
		if err := flags.Parse(args); err != nil || *target == "" {
			return errors.New("usage: control-api native-backup host-key --host HOST [--port 22]")
		}
		fingerprint, err := nativebackup.FetchHostKey(ctx, *target, *port)
		if err != nil {
			return err
		}
		fmt.Println(fingerprint)
		return nil
	case "fetch":
		return nativeBackupFetch(ctx, host, args)
	case "clean-target":
		return nativeBackupCleanTarget(ctx, host, args)
	case "frozen-console":
		return nativeBackupFrozenConsole(ctx)
	case "agent":
		return nativeBackupAgent(host).Tick(ctx)
	case "install-units":
		return nativebackup.InstallUnits(ctx, host)
	case "publish-node-install-trust":
		// install-control.sh publish_upgrade_trust: the same document a restore
		// republishes (fix-btenv4); prints its SHA-256.
		if len(args) != 0 {
			return errors.New(nativeBackupUsage)
		}
		trust, err := nativebackup.PublishNodeInstallTrust(ctx, host.Layout, nil)
		if err != nil {
			return err
		}
		fmt.Println(trust.SHA256)
		return nil
	default:
		return errors.New(nativeBackupUsage)
	}
}

func nativeBackupHost() *nativebackup.Host {
	executor := nativebackup.OSExecutor{}
	database := nativebackup.DefaultDatabaseTarget()
	if _, err := os.Stat(database.ToolsDir + "/pg_dump"); err != nil {
		database.ToolsDir = "/usr/bin"
	}
	layout := nativebackup.Layout{Root: "/"}
	return &nativebackup.Host{Layout: layout, Exec: executor,
		Systemd: nativebackup.Systemctl{Executor: executor}, Owners: nativebackup.SystemOwners(), Database: database.WithHostPorts(layout)}
}

func nativeBackupFreezer(host *nativebackup.Host) nativebackup.Freezer {
	return nativebackup.Freezer{Layout: host.Layout, Systemd: host.Systemd, Now: time.Now, Console: nativebackup.FrozenConsoleUnit}
}

func nativeBackupBackuper(host *nativebackup.Host) (nativebackup.Backuper, error) {
	keys, err := nativebackup.LoadOrCreateKeys(host.Layout)
	if err != nil {
		return nativebackup.Backuper{}, err
	}
	return nativebackup.Backuper{Host: host, Freezer: nativeBackupFreezer(host), Keys: keys, Facts: nativebackup.NativeFacts,
		Components: nativebackup.Components(), Now: time.Now, Progress: func(line string) { fmt.Fprintln(os.Stderr, line) }}, nil
}

func nativeBackupAgent(host *nativebackup.Host) nativebackup.Agent {
	backuper, err := nativeBackupBackuper(host)
	agent := nativebackup.Agent{Layout: host.Layout, Backuper: backuper, Now: time.Now}
	if err == nil {
		binary, _ := os.Executable()
		// The copied control-api must run on the target: same architecture.
		arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
		agent.Migrator = nativebackup.PushMigrator{Backuper: backuper, Dial: nativebackup.DialRemote, Binary: binary, ExpectedArch: arch}
	}
	return agent
}

type repeated []string

func (values *repeated) String() string     { return strings.Join(*values, ",") }
func (values *repeated) Set(v string) error { *values = append(*values, v); return nil }

func nativeBackupCreate(ctx context.Context, host *nativebackup.Host, args []string) error {
	flags := flag.NewFlagSet("create", flag.ContinueOnError)
	reason := flags.String("reason", "manual", "manual, scheduled or migration")
	hold := flags.Bool("hold", false, "keep the writers stopped and disabled afterwards (migration source)")
	output := flags.String("output", nativebackup.BackupRoot, "bundle directory")
	var recipients repeated
	flags.Var(&recipients, "recipient", "additional age X25519 recipient (repeatable)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New(nativeBackupUsage)
	}
	backuper, err := nativeBackupBackuper(host)
	if err != nil {
		return err
	}
	result, err := backuper.Run(ctx, nativebackup.BackupRequest{Reason: *reason, Hold: *hold, ExtraRecipients: recipients, OutputDirectory: *output})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"backup_id": result.BackupID, "directory": result.Directory,
		"signer_fingerprint": backuper.Keys.Fingerprint(), "version": result.Manifest.Control.Version,
		"schema_version": result.Manifest.Control.SchemaVersion, "held": *hold})
}

func nativeBackupList(host *nativebackup.Host) error {
	keys, err := nativebackup.LoadOrCreateKeys(host.Layout)
	if err != nil {
		return err
	}
	bundles, err := nativebackup.ListBundles(nativebackup.BackupRoot, keys.Fingerprint())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(bundles)
}

// openIdentity resolves the decryption identity and signer pin from flags.
func openIdentity(identityFile, recoveryKit, signer string) (age.Identity, string, error) {
	if recoveryKit != "" {
		encoded, err := os.ReadFile(recoveryKit)
		if err != nil {
			return nil, "", err
		}
		passphrase, err := readPassphrase("恢复口令: ")
		if err != nil {
			return nil, "", err
		}
		identity, kit, err := nativebackup.OpenRecoveryKit(encoded, passphrase)
		if err != nil {
			return nil, "", err
		}
		if signer == "" {
			signer = kit.SignerFinger
		}
		return identity, signer, nil
	}
	if identityFile == "" || signer == "" {
		return nil, "", errors.New("--identity with --signer, or --recovery-kit, is required")
	}
	identity, err := nativebackup.ReadIdentity(identityFile)
	return identity, signer, err
}

func nativeBackupVerify(host *nativebackup.Host, args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	bundle := flags.String("bundle", "", "bundle directory")
	signer := flags.String("signer", "", "pinned signer fingerprint (default: this host)")
	identityFile := flags.String("identity", "", "age identity file (default: this host)")
	kit := flags.String("recovery-kit", "", "recovery kit file")
	if err := flags.Parse(args); err != nil || *bundle == "" {
		return errors.New(nativeBackupUsage)
	}
	var identity age.Identity
	pinned := *signer
	if *identityFile == "" && *kit == "" {
		keys, err := nativebackup.LoadKeys(host.Layout)
		if err != nil {
			return err
		}
		identity = keys.Identity
		if pinned == "" {
			pinned = keys.Fingerprint()
		}
	} else {
		var err error
		if identity, pinned, err = openIdentity(*identityFile, *kit, pinned); err != nil {
			return err
		}
	}
	opened, err := nativebackup.OpenBundle(*bundle, pinned)
	if err != nil {
		return err
	}
	if err := opened.VerifyAll(identity); err != nil {
		return err
	}
	fmt.Printf("verified %s (%s, schema %d)\n", opened.Manifest.BackupID, opened.Manifest.Control.Version, opened.Manifest.Control.SchemaVersion)
	return nil
}

func nativeBackupRestore(ctx context.Context, host *nativebackup.Host, args []string) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	bundle := flags.String("bundle", "", "bundle directory")
	signer := flags.String("signer", "", "pinned signer fingerprint")
	identityFile := flags.String("identity", "", "age identity file")
	kit := flags.String("recovery-kit", "", "recovery kit file")
	compensate := flags.Bool("compensate", false, "first remove an unfinished restore of the same bundle")
	if err := flags.Parse(args); err != nil || *bundle == "" {
		return errors.New(nativeBackupUsage)
	}
	identity, pinned, err := openIdentity(*identityFile, *kit, *signer)
	if err != nil {
		return err
	}
	opened, err := nativebackup.OpenBundle(*bundle, pinned)
	if err != nil {
		return err
	}
	restorer := nativebackup.Restorer{Host: host, Components: nativebackup.Components(), Now: time.Now,
		Progress: func(line string) { fmt.Fprintln(os.Stderr, line) }}
	result, err := restorer.Run(ctx, nativebackup.RestoreRequest{Bundle: opened, Identity: identity, Compensate: *compensate})
	if err != nil {
		return err
	}
	// Renewal of a restored Let's Encrypt lineage needs certbot; a failure
	// here never undoes the restore.
	if _, statErr := os.Stat("/etc/letsencrypt/renewal"); statErr == nil {
		if _, lookErr := exec.LookPath("certbot"); lookErr != nil {
			install := exec.CommandContext(ctx, "apt-get", "install", "-y", "-qq", "--no-install-recommends", "certbot")
			install.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			if install.Run() != nil {
				fmt.Fprintln(os.Stderr, "warning: certbot 安装失败，证书续期前请手动安装 certbot")
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func nativeBackupStatus(host *nativebackup.Host) error {
	keys, err := nativebackup.LoadOrCreateKeys(host.Layout)
	if err != nil {
		return err
	}
	freeze, err := nativeBackupFreezer(host).Current()
	if err != nil {
		return err
	}
	runs, err := nativebackup.ListRuns(host.Layout, 10)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"signer_fingerprint": keys.Fingerprint(), "recipient": keys.Recipient(),
		"freeze": freeze, "runs": runs})
}

func readPassphrase(prompt string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(value), err
	}
	line, err := bufio.NewReader(io.LimitReader(os.Stdin, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func nativeBackupExportKit(host *nativebackup.Host, args []string) error {
	flags := flag.NewFlagSet("export-recovery-kit", flag.ContinueOnError)
	output := flags.String("output", "", "file to create (owner-only)")
	if err := flags.Parse(args); err != nil || *output == "" {
		return errors.New("usage: control-api native-backup export-recovery-kit --output FILE")
	}
	keys, err := nativebackup.LoadOrCreateKeys(host.Layout)
	if err != nil {
		return err
	}
	facts, _ := nativebackup.NativeFacts(context.Background(), host)
	passphrase, err := readPassphrase("恢复口令（至少 12 个字符）: ")
	if err != nil {
		return err
	}
	kit, err := nativebackup.ExportRecoveryKit(keys, facts.InstallationID, passphrase, time.Now())
	if err != nil {
		return err
	}
	encoded, _ := json.MarshalIndent(kit, "", "  ")
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(append(encoded, '\n'))
	return errors.Join(writeErr, file.Close())
}

func nativeBackupVerifyMigration(ctx context.Context, host *nativebackup.Host, args []string) error {
	flags := flag.NewFlagSet("verify-migration", flag.ContinueOnError)
	bundle := flags.String("bundle", "", "restored bundle directory")
	wait := flags.Duration("wait-nodes", 0, "wait up to this long for every active node to reconnect")
	if err := flags.Parse(args); err != nil || *bundle == "" {
		return errors.New(nativeBackupUsage)
	}
	signed, err := nativebackup.ReadSignedManifest(*bundle)
	if err != nil {
		return err
	}
	manifest, err := nativebackup.ReadUnverifiedManifest(signed)
	if err != nil {
		return err
	}
	verifier := nativebackup.Verifier{Host: host, HTTP: &http.Client{Timeout: 5 * time.Second},
		Lookup: func(ctx context.Context, name string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, name)
		},
		Local: nativebackup.LocalAddresses,
		PublishTrust: func(ctx context.Context) (nativebackup.NodeInstallTrust, error) {
			return nativebackup.PublishNodeInstallTrust(ctx, host.Layout, nil)
		}}
	since := manifest.FrozenAt
	deadline := time.Now().Add(*wait)
	for {
		report, err := verifier.Verify(ctx, manifest, since)
		// The migration log (migrate-to forwards stderr; install-control.sh migrate-from shows it).
		if report.NodeInstallTrust != nil {
			fmt.Fprintln(os.Stderr, report.NodeInstallTrust.Message())
		}
		if err != nil || *wait == 0 || report.OnlineNodes >= report.ActiveNodes || time.Now().After(deadline) {
			_ = json.NewEncoder(os.Stdout).Encode(report)
			return err
		}
		fmt.Fprintf(os.Stderr, "waiting for nodes: %d/%d online\n", report.OnlineNodes, report.ActiveNodes)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(15 * time.Second):
		}
	}
}

func nativeBackupMigrateTo(ctx context.Context, host *nativebackup.Host, args []string) error {
	flags := flag.NewFlagSet("migrate-to", flag.ContinueOnError)
	target := nativebackup.MigrationTarget{}
	flags.StringVar(&target.Host, "host", "", "new control host")
	flags.IntVar(&target.Port, "port", 22, "SSH port")
	flags.StringVar(&target.User, "user", "root", "SSH user (root)")
	flags.StringVar(&target.HostKeySHA256, "host-key", "", "pinned SSH host key fingerprint (see host-key)")
	passwordStdin := flags.Bool("password-stdin", false, "read the SSH password from stdin")
	keyFile := flags.String("private-key", "", "unencrypted OpenSSH private key file")
	if err := flags.Parse(args); err != nil {
		return errors.New(nativeBackupUsage)
	}
	if *passwordStdin {
		password, err := readPassphrase("新主控 SSH 密码: ")
		if err != nil {
			return err
		}
		target.Password = password
	}
	if *keyFile != "" {
		key, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		target.PrivateKey = string(key)
	}
	if err := target.Validate(); err != nil {
		return err
	}
	agent := nativeBackupAgent(host)
	if agent.Migrator == nil {
		return errors.New("backup identity unavailable")
	}
	result, err := agent.Migrator.Migrate(ctx, target, func(line string) { fmt.Fprintln(os.Stderr, nativebackup.Redact(line)) })
	if result.BackupID != "" {
		fmt.Println(result.BackupID)
	}
	return err
}

func nativeBackupFetch(ctx context.Context, host *nativebackup.Host, args []string) error {
	flags := flag.NewFlagSet("fetch", flag.ContinueOnError)
	targetName := flags.String("target", "", "configured target name")
	backupID := flags.String("backup-id", "", "backup to download")
	signer := flags.String("signer", "", "pinned signer fingerprint (default: this host)")
	if err := flags.Parse(args); err != nil || *targetName == "" || *backupID == "" {
		return errors.New(nativeBackupUsage)
	}
	settings, err := nativebackup.LoadSettings(host.Layout)
	if err != nil {
		return err
	}
	pinned := *signer
	if pinned == "" {
		keys, err := nativebackup.LoadKeys(host.Layout)
		if err != nil {
			return err
		}
		pinned = keys.Fingerprint()
	}
	for _, target := range settings.Targets {
		if target.Name != *targetName {
			continue
		}
		storage, err := nativebackup.OpenStorage(target)
		if err != nil {
			return err
		}
		defer storage.Close()
		bundle, err := nativebackup.Download(ctx, storage, *backupID, nativebackup.BackupRoot, pinned)
		if err != nil {
			return err
		}
		fmt.Println(bundle.Directory)
		return nil
	}
	return errors.New("unknown target")
}

// buildControlBackupHandler mounts the console backup/migration API. Every
// write is audited in the caller's platform scope before it is queued.
func buildControlBackupHandler(pool *pgxpool.Pool, identityService *identity.Service) (http.Handler, error) {
	if pool == nil || identityService == nil {
		return nil, errors.New("control backup runtime dependencies are unavailable")
	}
	return controlbackuphttp.NewHandler(controlbackuphttp.Dependencies{Layout: nativebackup.Layout{Root: "/"},
		Authenticate: identityService.AuthenticateSession, VerifyPassword: identityService.VerifyPlatformPassword,
		Audit: controlBackupAuditor(pool)})
}

// controlBackupAuditor writes console actions in the caller's platform scope.
// A payload "result" (denied) becomes the event result.
func controlBackupAuditor(pool *pgxpool.Pool) controlbackuphttp.Auditor {
	auditor := audit.New(pool)
	return func(ctx context.Context, session identity.AuthenticatedSession, action, resourceID, requestID string, payload map[string]any) error {
		result := "success"
		if value, ok := payload["result"].(string); ok {
			result = value
			delete(payload, "result")
		}
		return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			actor := session.Principal.UserID
			return auditor.Append(ctx, tx, audit.Event{ScopeID: session.Principal.ScopeID, ActorUserID: &actor, Action: action,
				ResourceType: "control_backup", ResourceID: resourceID, RequestID: requestID, Result: result, Payload: payload})
		})
	}
}

// nativeBackupCleanTarget removes a restore from a migration target that is
// no longer wanted (fix-migrollback). Run as root on the new host.
func nativeBackupCleanTarget(ctx context.Context, host *nativebackup.Host, args []string) error {
	flags := flag.NewFlagSet("clean-target", flag.ContinueOnError)
	bundle := flags.String("bundle", "", "bundle directory of the migration")
	signer := flags.String("signer", "", "pinned signer fingerprint of the old control plane")
	if err := flags.Parse(args); err != nil || *bundle == "" || *signer == "" {
		return errors.New("usage: control-api native-backup clean-target --bundle DIR --signer SHA256:...")
	}
	opened, err := nativebackup.OpenBundle(*bundle, *signer)
	if err != nil {
		return err
	}
	restorer := nativebackup.Restorer{Host: host, Components: nativebackup.Components(), Now: time.Now,
		Progress: func(line string) { fmt.Fprintln(os.Stderr, line) }}
	if err := restorer.CleanTarget(ctx, opened); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "clean: done; this host holds no control plane state of "+opened.Manifest.BackupID)
	return nil
}

// nativeBackupFrozenConsole serves the frozen console on the control-api
// address while a migration hold is in force (cdnca-control-frozen-console
// .service, started by the hold and stopped before the writers restart). Its
// database pool is read-only: the held database must not diverge from the
// copy on the new host.
func nativeBackupFrozenConsole(ctx context.Context) error {
	databaseURL, secret := os.Getenv("DATABASE_URL"), os.Getenv("ACCESS_TOKEN_SECRET")
	if databaseURL == "" || secret == "" {
		return errors.New("frozen console needs DATABASE_URL and ACCESS_TOKEN_SECRET (control.env)")
	}
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return errors.New("DATABASE_URL is invalid")
	}
	poolConfig.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	poolConfig.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return err
	}
	defer pool.Close()
	tokens, err := identity.NewTokenManager(secret, 10*time.Minute)
	if err != nil {
		return err
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		return err
	}
	// Audit rows are the only writes: one stop/rollback record is harmless
	// whether this host is discarded or becomes the live one again, and after
	// a rollback the trail must be here.
	auditPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer auditPool.Close()
	console, err := controlbackuphttp.NewFrozenConsole(controlbackuphttp.Dependencies{Layout: nativebackup.Layout{Root: "/"},
		VerifyPassword: identityService.VerifyPlatformPassword, Audit: controlBackupAuditor(auditPool)}, nil)
	if err != nil {
		return err
	}
	address := os.Getenv("HTTP_ADDR")
	if address == "" {
		address = ":8080"
	}
	server := &http.Server{Addr: address, Handler: console, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
