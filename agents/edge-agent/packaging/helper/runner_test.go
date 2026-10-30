package helper

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestUpgradeCommandIsFixed(t *testing.T) {
	staged, _ := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	temporaryBase := t.TempDir()
	handoff, taskRoot, err := createUpgradeHandoff(staged, temporaryBase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanupUpgradeHandoff(taskRoot, temporaryBase) })
	command, err := upgradeCommand(handoff)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{
		"--artifact", handoff.ExecutablePath,
		"--sbom", handoff.SBOMPath,
		"--manifest", handoff.ManifestPath,
		"--signature", handoff.SignaturePath,
		"--public-key", PinnedReleasePublicKeyPath,
	}
	if command.path != upgradeScriptPath || !reflect.DeepEqual(command.args, wantArgs) || !reflect.DeepEqual(command.env, fixedPackagingEnvironment()) {
		t.Fatalf("unexpected fixed command: %+v", command)
	}
}

func TestUpgradeCommandRejectsNonCanonicalStagedPath(t *testing.T) {
	staged, _ := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	temporaryBase := t.TempDir()
	handoff, taskRoot, err := createUpgradeHandoff(staged, temporaryBase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanupUpgradeHandoff(taskRoot, temporaryBase) })
	handoff.ExecutablePath = "/tmp/caller-program"
	if _, err := upgradeCommand(handoff); err == nil {
		t.Fatal("non-canonical executable path was accepted")
	}
}

func TestUpgradeHandoffVisibleToFixedScriptRunnerAndCleaned(t *testing.T) {
	staged, _ := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	temporaryBase := t.TempDir()
	sourcePaths := map[string]string{
		"manifest": staged.ManifestPath, "manifest.sig": staged.SignaturePath,
		"edge-agent.spdx.json": staged.SBOMPath, "edge-agent": staged.ExecutablePath,
	}
	observed := false
	err := runUpgradeWithHandoff(context.Background(), staged, temporaryBase, func(_ context.Context, command packagingCommand) error {
		observed = true
		if command.path != upgradeScriptPath || !reflect.DeepEqual(command.env, fixedPackagingEnvironment()) {
			return errors.New("script command was not fixed")
		}
		handoffDirectory := filepath.Dir(commandArgument(t, command, "--artifact"))
		taskRoot := filepath.Dir(handoffDirectory)
		assertOwnedMode(t, taskRoot, 0711)
		assertOwnedMode(t, handoffDirectory, 0755)
		for name, sourcePath := range sourcePaths {
			destinationPath := filepath.Join(handoffDirectory, name)
			wantMode := os.FileMode(0444)
			if name == "edge-agent" {
				wantMode = 0555
			}
			assertOwnedMode(t, destinationPath, wantMode)
			sourceContent, sourceErr := os.ReadFile(sourcePath)
			destinationContent, destinationErr := os.ReadFile(destinationPath)
			if sourceErr != nil || destinationErr != nil || !bytes.Equal(sourceContent, destinationContent) {
				return errors.New("script observed different handoff content")
			}
		}
		if commandArgument(t, command, "--manifest") != filepath.Join(handoffDirectory, "manifest") ||
			commandArgument(t, command, "--signature") != filepath.Join(handoffDirectory, "manifest.sig") ||
			commandArgument(t, command, "--sbom") != filepath.Join(handoffDirectory, "edge-agent.spdx.json") ||
			commandArgument(t, command, "--public-key") != PinnedReleasePublicKeyPath {
			return errors.New("script observed non-canonical arguments")
		}
		return nil
	})
	if err != nil || !observed {
		t.Fatalf("run upgrade handoff: observed=%v err=%v", observed, err)
	}
	assertDirectoryEmpty(t, temporaryBase)
	assertOwnedMode(t, staged.Directory, 0700)
	assertOwnedMode(t, staged.ExecutablePath, 0500)
}

func TestUpgradeHandoffCleansAfterScriptFailure(t *testing.T) {
	staged, _ := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	temporaryBase := t.TempDir()
	want := errors.New("script failed")
	err := runUpgradeWithHandoff(context.Background(), staged, temporaryBase, func(_ context.Context, command packagingCommand) error {
		if _, statErr := os.Stat(commandArgument(t, command, "--artifact")); statErr != nil {
			return statErr
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
	assertDirectoryEmpty(t, temporaryBase)
}

func TestUpgradeHandoffCleansAfterCancellation(t *testing.T) {
	staged, _ := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	temporaryBase := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runUpgradeWithHandoff(ctx, staged, temporaryBase, func(ctx context.Context, _ packagingCommand) error {
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
	assertDirectoryEmpty(t, temporaryBase)
}

func TestCopyVerifiedHandoffFileRejectsPreexistingAndSymlinkTargets(t *testing.T) {
	staged, _ := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	directory := t.TempDir()
	specification := handoffFile{
		source: staged.ManifestPath, destination: filepath.Join(directory, "manifest"),
		size: staged.ManifestSize, digest: staged.ManifestSHA256, sourceMode: 0400, destinationMode: 0444,
	}
	if err := os.WriteFile(specification.destination, []byte("preexisting"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyVerifiedHandoffFile(specification); err == nil {
		t.Fatal("preexisting handoff target was accepted")
	}
	content, err := os.ReadFile(specification.destination)
	if err != nil || string(content) != "preexisting" {
		t.Fatalf("preexisting target changed: %q, %v", content, err)
	}
	if err := os.Remove(specification.destination); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, specification.destination); err != nil {
		t.Fatal(err)
	}
	if err := copyVerifiedHandoffFile(specification); err == nil {
		t.Fatal("symlink handoff target was accepted")
	}
	info, err := os.Lstat(specification.destination)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink target changed: %v, %v", info, err)
	}
}

func TestCreateUpgradeHandoffRejectsSymlinkSourceAndCleans(t *testing.T) {
	staged, _ := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	target := filepath.Join(t.TempDir(), "manifest")
	content, err := os.ReadFile(staged.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(staged.ManifestPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(staged.ManifestPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, staged.ManifestPath); err != nil {
		t.Fatal(err)
	}
	temporaryBase := t.TempDir()
	if _, _, err := createUpgradeHandoff(staged, temporaryBase); err == nil {
		t.Fatal("symlink source was accepted")
	}
	assertDirectoryEmpty(t, temporaryBase)
}

func TestCreateUpgradeHandoffRejectsDigestMismatchAndCleans(t *testing.T) {
	staged, _ := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	staged.ExecutableSHA256 = strings.Repeat("0", 64)
	temporaryBase := t.TempDir()
	if _, _, err := createUpgradeHandoff(staged, temporaryBase); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("got %v, want %v", err, ErrArtifactMismatch)
	}
	assertDirectoryEmpty(t, temporaryBase)
}

func TestUpgradeHandoffConcurrentIsolation(t *testing.T) {
	staged, _ := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	temporaryBase := t.TempDir()
	const workers = 12
	seen := make(map[string]struct{}, workers)
	var mutex sync.Mutex
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsChannel <- runUpgradeWithHandoff(context.Background(), staged, temporaryBase, func(_ context.Context, command packagingCommand) error {
				directory := filepath.Dir(command.args[1])
				mutex.Lock()
				defer mutex.Unlock()
				if _, exists := seen[directory]; exists {
					return errors.New("handoff directory was reused")
				}
				seen[directory] = struct{}{}
				_, err := os.ReadFile(filepath.Join(directory, "edge-agent"))
				return err
			})
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != workers {
		t.Fatalf("got %d isolated handoffs, want %d", len(seen), workers)
	}
	assertDirectoryEmpty(t, temporaryBase)
}

func TestRollbackCommandAllowsOnlyVersionArgument(t *testing.T) {
	command, err := rollbackCommand("1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if command.path != rollbackScriptPath || !reflect.DeepEqual(command.args, []string{"--version", "1.2.3"}) || !reflect.DeepEqual(command.env, fixedPackagingEnvironment()) {
		t.Fatalf("unexpected rollback command: %+v", command)
	}
	for _, value := range []string{"", "../1.2.3", "1.2.3;id", "1.2.3 value"} {
		if _, err := rollbackCommand(value); err == nil {
			t.Fatalf("unsafe rollback version %q accepted", value)
		}
	}
}

func TestFixedPackagingEnvironmentContainsNoInheritedValue(t *testing.T) {
	first := fixedPackagingEnvironment()
	first[0] = "ATTACKER=value"
	if reflect.DeepEqual(first, fixedPackagingEnvironment()) {
		t.Fatal("fixed environment storage was mutable")
	}
}

func TestSystemdUnitsFreezeSocketAndPrivilegeBoundary(t *testing.T) {
	service := readUnit(t, "cdnca-edge-agent-helper.service")
	socket := readUnit(t, "cdnca-edge-agent-helper.socket")
	for _, line := range []string{
		"ExecStart=/usr/libexec/cdnca-edge-agent-helper serve",
		"NoNewPrivileges=yes",
		"PrivateNetwork=yes",
		"ProtectSystem=strict",
		"ReadOnlyPaths=" + PinnedReleasePublicKeyPath,
		"CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID",
		"RestrictAddressFamilies=AF_UNIX",
	} {
		if !unitHasLine(service, line) {
			t.Fatalf("service is missing %q", line)
		}
	}
	if strings.Contains(service, "EnvironmentFile=") || strings.Contains(service, "/bin/sh") || strings.Contains(service, "/bin/bash") {
		t.Fatal("service introduced inherited environment or a generic shell")
	}
	for _, line := range []string{
		"ListenSequentialPacket=/run/cdnca-edge-agent/helper.sock",
		"SocketUser=cdnca-edge",
		"SocketGroup=cdnca-edge",
		"SocketMode=0600",
		"Accept=no",
	} {
		if !unitHasLine(socket, line) {
			t.Fatalf("socket is missing %q", line)
		}
	}
}

func readUnit(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "systemd", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func unitHasLine(content, expected string) bool {
	for _, line := range strings.Split(content, "\n") {
		if line == expected {
			return true
		}
	}
	return false
}

func commandArgument(t *testing.T, command packagingCommand, option string) string {
	t.Helper()
	for index := 0; index+1 < len(command.args); index += 2 {
		if command.args[index] == option {
			return command.args[index+1]
		}
	}
	t.Fatalf("command option %s is missing", option)
	return ""
}

func assertOwnedMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() || info.Mode().Perm() != mode.Perm() {
		t.Fatalf("unexpected ownership or mode for %s: %+v", filepath.Base(path), info)
	}
}

func assertDirectoryEmpty(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary root not empty: %v, %v", entries, err)
	}
}
