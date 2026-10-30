package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
)

const (
	sentinelFamily  = "inet"
	sentinelTable   = "cdnca_firewall_smoke_sentinel"
	sentinelComment = "cdnca firewall smoke sentinel"
	checkFailID     = "firewall-smoke-check-failure"
)

type evidence struct {
	NftVersion                  string   `json:"nft_version"`
	AppliedVersions             []string `json:"applied_versions"`
	IPv4DenyVerified            bool     `json:"ipv4_deny_verified"`
	IPv6DenyVerified            bool     `json:"ipv6_deny_verified"`
	IPv4AllowPrecedenceVerified bool     `json:"ipv4_allow_precedence_verified"`
	IPv6AllowPrecedenceVerified bool     `json:"ipv6_allow_precedence_verified"`
	InvalidCandidateKeptV2      bool     `json:"invalid_candidate_kept_v2"`
	RealCheckFailureKeptV2      bool     `json:"real_check_failure_kept_v2"`
	FailedTaskReplayVerified    bool     `json:"failed_task_replay_verified"`
	RestartRecoveryVerified     bool     `json:"restart_recovery_verified"`
	SentinelPreserved           bool     `json:"sentinel_preserved"`
	OwnedTableCleaned           bool     `json:"owned_table_cleaned"`
	SentinelCleaned             bool     `json:"sentinel_cleaned"`
}

type nftRunner struct {
	binary        string
	checkFailures atomic.Int32
}

func (r *nftRunner) Run(ctx context.Context, arguments ...string) ([]byte, error) {
	if len(arguments) == 3 && arguments[0] == "--check" && arguments[1] == "--file" {
		batch, err := os.ReadFile(arguments[2])
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(batch), "version="+checkFailID+" ") {
			return r.runInvalidCheck(ctx, arguments[2], batch)
		}
	}
	return exec.CommandContext(ctx, r.binary, arguments...).Output()
}

func (r *nftRunner) runInvalidCheck(ctx context.Context, original string, batch []byte) ([]byte, error) {
	file, err := os.CreateTemp(filepath.Dir(original), ".forced-invalid-*.nft")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Write(append(batch, []byte("cdnca forced invalid nft syntax\n")...)); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	output, checkErr := exec.CommandContext(ctx, r.binary, "--check", "--file", path).Output()
	if checkErr == nil {
		return nil, errors.New("nft unexpectedly accepted the forced-invalid transaction")
	}
	r.checkFailures.Add(1)
	return output, checkErr
}

type testListener struct {
	listener net.Listener
	done     chan struct{}
}

func startListener(network, address string) (*testListener, error) {
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	server := &testListener{listener: listener, done: make(chan struct{})}
	go func() {
		defer close(server.done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	return server, nil
}

func (s *testListener) close() {
	_ = s.listener.Close()
	<-s.done
}

func (s *testListener) reachable(ctx context.Context, network string) bool {
	connection, err := (&net.Dialer{}).DialContext(ctx, network, s.listener.Addr().String())
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func main() {
	var stateRoot string
	var nftBinary string
	var isolatedNamespace bool
	flag.StringVar(&stateRoot, "state-root", "", "absolute firewall smoke state directory")
	flag.StringVar(&nftBinary, "nft-binary", "/usr/sbin/nft", "absolute nft binary path")
	flag.BoolVar(&isolatedNamespace, "isolated-namespace", false, "confirm this destructive smoke runs in a disposable network namespace")
	flag.Parse()
	if err := run(stateRoot, nftBinary, isolatedNamespace); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(stateRoot, nftBinary string, isolatedNamespace bool) error {
	if stateRoot == "" || !filepath.IsAbs(stateRoot) || !filepath.IsAbs(nftBinary) || !isolatedNamespace || flag.NArg() != 0 {
		return errors.New("invalid smoke-test arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	runner := &nftRunner{binary: nftBinary}
	if err := cleanupTables(ctx, nftBinary); err != nil {
		return fmt.Errorf("clean stale firewall tables: %w", err)
	}
	cleanupRequired := true
	defer func() {
		if cleanupRequired {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cleanupCancel()
			_ = cleanupTables(cleanupCtx, nftBinary)
		}
	}()
	if err := createSentinel(ctx, nftBinary, stateRoot); err != nil {
		return fmt.Errorf("create sentinel table: %w", err)
	}
	sentinelBefore, err := listTable(ctx, nftBinary, sentinelFamily, sentinelTable)
	if err != nil || tableComment(sentinelBefore) != sentinelComment {
		return errors.New("sentinel table was not created as expected")
	}

	ipv4, err := startListener("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start IPv4 listener: %w", err)
	}
	defer ipv4.close()
	ipv6, err := startListener("tcp6", "[::1]:0")
	if err != nil {
		return fmt.Errorf("start IPv6 listener: %w", err)
	}
	defer ipv6.close()
	if !probe(ctx, ipv4, "tcp4", true) || !probe(ctx, ipv6, "tcp6", true) {
		return errors.New("loopback preflight failed before applying firewall rules")
	}

	manager, err := firewall.NewManagerWithDependencies(stateRoot, runner, time.Now)
	if err != nil {
		return err
	}
	v1 := firewall.FirewallVersion{TaskID: "firewall-smoke-task-v1", VersionID: "firewall-smoke-v1", Entries: []firewall.Entry{
		{Action: firewall.ActionDeny, Network: "127.0.0.1", Source: "smoke", Reason: "verify IPv4 deny"},
		{Action: firewall.ActionDeny, Network: "::1", Source: "smoke", Reason: "verify IPv6 deny"},
	}}
	first, err := manager.Apply(ctx, v1)
	if err != nil || first.State != firewall.StateApplied {
		return fmt.Errorf("apply firewall v1: result=%+v error=%v", first, err)
	}
	ipv4Denied := probe(ctx, ipv4, "tcp4", false)
	ipv6Denied := probe(ctx, ipv6, "tcp6", false)
	if !ipv4Denied || !ipv6Denied {
		return errors.New("v1 did not deny both IPv4 and IPv6 traffic")
	}

	v2 := firewall.FirewallVersion{TaskID: "firewall-smoke-task-v2", VersionID: "firewall-smoke-v2", Entries: []firewall.Entry{
		{Action: firewall.ActionAllow, Network: "127.0.0.1", Source: "smoke", Reason: "IPv4 exception"},
		{Action: firewall.ActionAllow, Network: "::1", Source: "smoke", Reason: "IPv6 exception"},
		{Action: firewall.ActionDeny, Network: "127.0.0.0/8", Source: "smoke", Reason: "IPv4 deny range"},
		{Action: firewall.ActionDeny, Network: "::1", Source: "smoke", Reason: "IPv6 deny range"},
	}}
	second, err := manager.Apply(ctx, v2)
	if err != nil || second.State != firewall.StateApplied {
		return fmt.Errorf("apply firewall v2: result=%+v error=%v", second, err)
	}
	ipv4Allowed := probe(ctx, ipv4, "tcp4", true)
	ipv6Allowed := probe(ctx, ipv6, "tcp6", true)
	if !ipv4Allowed || !ipv6Allowed {
		return errors.New("v2 allow precedence did not restore both loopback families")
	}

	invalid := firewall.FirewallVersion{TaskID: "firewall-smoke-invalid", VersionID: "firewall-smoke-invalid", Entries: []firewall.Entry{
		{Action: firewall.ActionDeny, Network: "0.0.0.0/0", Source: "smoke", Reason: "must reject unsafe candidate"},
	}}
	if _, err := manager.Apply(ctx, invalid); !errors.Is(err, firewall.ErrInvalidVersion) {
		return fmt.Errorf("invalid candidate error=%v, want ErrInvalidVersion", err)
	}
	invalidKeptV2, err := healthyVersion(ctx, manager, v2.VersionID)
	if err != nil || !invalidKeptV2 {
		return fmt.Errorf("invalid candidate changed v2: %w", err)
	}

	checkFailure := firewall.FirewallVersion{TaskID: "firewall-smoke-check-task", VersionID: checkFailID, Entries: []firewall.Entry{
		{Action: firewall.ActionDeny, Network: "192.0.2.19", Source: "smoke", Reason: "force real nft check failure"},
	}}
	failed, err := manager.Apply(ctx, checkFailure)
	if err != nil || failed.State != firewall.StateFailed || failed.ErrorCode != "CHECK_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != v2.VersionID {
		return fmt.Errorf("real nft check failure result=%+v error=%v", failed, err)
	}
	failedReplay, err := manager.Apply(ctx, checkFailure)
	if err != nil || !reflect.DeepEqual(failed, failedReplay) || runner.checkFailures.Load() != 1 {
		return fmt.Errorf("failed task replay result=%+v checks=%d error=%v", failedReplay, runner.checkFailures.Load(), err)
	}
	checkFailureKeptV2, err := healthyVersion(ctx, manager, v2.VersionID)
	if err != nil || !checkFailureKeptV2 {
		return fmt.Errorf("check failure changed v2: %w", err)
	}

	restarted, err := firewall.NewManagerWithDependencies(stateRoot, runner, time.Now)
	if err != nil {
		return err
	}
	restartHealthy, err := healthyVersion(ctx, restarted, v2.VersionID)
	if err != nil || !restartHealthy {
		return fmt.Errorf("restart did not recover v2: %w", err)
	}
	sentinelAfter, err := listTable(ctx, nftBinary, sentinelFamily, sentinelTable)
	if err != nil || string(sentinelBefore) != string(sentinelAfter) {
		return errors.New("non-owned sentinel table changed during firewall publication")
	}

	nftVersion, err := exec.CommandContext(ctx, nftBinary, "--version").Output()
	if err != nil {
		return err
	}
	if err := cleanupTables(ctx, nftBinary); err != nil {
		return fmt.Errorf("cleanup firewall tables: %w", err)
	}
	ownedCleaned := tableAbsent(ctx, nftBinary, firewall.TableFamily, firewall.TableName)
	sentinelCleaned := tableAbsent(ctx, nftBinary, sentinelFamily, sentinelTable)
	if !ownedCleaned || !sentinelCleaned {
		return errors.New("firewall smoke tables remained after cleanup")
	}
	cleanupRequired = false

	return json.NewEncoder(os.Stdout).Encode(evidence{
		NftVersion: strings.TrimSpace(string(nftVersion)), AppliedVersions: []string{first.ActiveVersionID, second.ActiveVersionID},
		IPv4DenyVerified: ipv4Denied, IPv6DenyVerified: ipv6Denied,
		IPv4AllowPrecedenceVerified: ipv4Allowed, IPv6AllowPrecedenceVerified: ipv6Allowed,
		InvalidCandidateKeptV2: invalidKeptV2, RealCheckFailureKeptV2: checkFailureKeptV2,
		FailedTaskReplayVerified: runner.checkFailures.Load() == 1, RestartRecoveryVerified: restartHealthy,
		SentinelPreserved: true, OwnedTableCleaned: ownedCleaned, SentinelCleaned: sentinelCleaned,
	})
}

func probe(parent context.Context, listener *testListener, network string, wantReachable bool) bool {
	ctx, cancel := context.WithTimeout(parent, 400*time.Millisecond)
	defer cancel()
	return listener.reachable(ctx, network) == wantReachable
}

func healthyVersion(ctx context.Context, manager *firewall.Manager, versionID string) (bool, error) {
	status, err := manager.Status(ctx)
	if err != nil {
		return false, err
	}
	return status.Active && status.Healthy && status.VersionID == versionID, nil
}

func createSentinel(ctx context.Context, nftBinary, stateRoot string) error {
	batch := fmt.Sprintf("destroy table %s %s\nadd table %s %s { comment \"%s\"; }\n", sentinelFamily, sentinelTable, sentinelFamily, sentinelTable, sentinelComment)
	return runBatch(ctx, nftBinary, stateRoot, batch)
}

func cleanupTables(ctx context.Context, nftBinary string) error {
	directory, err := os.MkdirTemp("", "cdnca-firewall-cleanup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	batch := fmt.Sprintf("destroy table %s %s\ndestroy table %s %s\n", firewall.TableFamily, firewall.TableName, sentinelFamily, sentinelTable)
	return runBatch(ctx, nftBinary, directory, batch)
}

func runBatch(ctx context.Context, nftBinary, directory, batch string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".firewall-smoke-*.nft")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.WriteString(batch); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return exec.CommandContext(ctx, nftBinary, "--file", path).Run()
}

func listTable(ctx context.Context, nftBinary, family, name string) ([]byte, error) {
	return exec.CommandContext(ctx, nftBinary, "--json", "list", "table", family, name).Output()
}

func tableComment(document []byte) string {
	var listing struct {
		Objects []struct {
			Table *struct {
				Comment string `json:"comment"`
			} `json:"table,omitempty"`
		} `json:"nftables"`
	}
	if json.Unmarshal(document, &listing) != nil {
		return ""
	}
	for _, object := range listing.Objects {
		if object.Table != nil {
			return object.Table.Comment
		}
	}
	return ""
}

func tableAbsent(ctx context.Context, nftBinary, family, name string) bool {
	_, err := listTable(ctx, nftBinary, family, name)
	return err != nil
}
