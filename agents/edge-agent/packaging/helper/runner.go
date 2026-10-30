package helper

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	upgradeScriptPath      = "/usr/libexec/cdnca-edge-agent/upgrade.sh"
	rollbackScriptPath     = "/usr/libexec/cdnca-edge-agent/rollback.sh"
	upgradeHandoffTempBase = "/tmp"
	upgradeTaskPrefix      = "cdnca-edge-agent-helper-"
	upgradeHandoffName     = "handoff"
)

var ErrPackagingCommand = errors.New("packaging command failed")

type PackagingRunner struct{}

type packagingCommand struct {
	path string
	args []string
	env  []string
}

func (PackagingRunner) Upgrade(ctx context.Context, staged StagedBundle) error {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("%w: root identity required", ErrPackagingCommand)
	}
	return runUpgradeWithHandoff(ctx, staged, upgradeHandoffTempBase, runPackagingCommand)
}

func (PackagingRunner) Rollback(ctx context.Context, journalBoundVersion string) error {
	command, err := rollbackCommand(journalBoundVersion)
	if err != nil {
		return err
	}
	return runPackagingCommand(ctx, command)
}

func upgradeCommand(staged StagedBundle) (packagingCommand, error) {
	if err := validateUpgradeHandoffPaths(staged); err != nil {
		return packagingCommand{}, err
	}
	args := []string{
		"--artifact", staged.ExecutablePath,
		"--sbom", staged.SBOMPath,
		"--manifest", staged.ManifestPath,
		"--signature", staged.SignaturePath,
		"--public-key", PinnedReleasePublicKeyPath,
	}
	if staged.NativePath != "" {
		args = append(args, "--native", staged.NativePath)
	}
	return packagingCommand{path: upgradeScriptPath, args: args, env: fixedPackagingEnvironment()}, nil
}

func runUpgradeWithHandoff(ctx context.Context, staged StagedBundle, temporaryBase string, run func(context.Context, packagingCommand) error) (err error) {
	if ctx == nil || run == nil {
		return fmt.Errorf("%w: upgrade invocation rejected", ErrPackagingCommand)
	}
	handoff, taskRoot, err := createUpgradeHandoff(staged, temporaryBase)
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := cleanupUpgradeHandoff(taskRoot, temporaryBase); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()
	command, err := upgradeCommand(handoff)
	if err != nil {
		return err
	}
	return run(ctx, command)
}

func createUpgradeHandoff(staged StagedBundle, temporaryBase string) (result StagedBundle, taskRoot string, err error) {
	if err := validateStagedBundlePaths(staged); err != nil {
		return result, "", err
	}
	if temporaryBase == "" || !filepath.IsAbs(temporaryBase) || filepath.Clean(temporaryBase) != temporaryBase {
		return result, "", fmt.Errorf("%w: temporary root rejected", ErrPackagingCommand)
	}
	taskRoot, err = os.MkdirTemp(temporaryBase, upgradeTaskPrefix)
	if err != nil {
		return result, "", fmt.Errorf("%w: cannot create task root", ErrPackagingCommand)
	}
	defer func() {
		if err != nil {
			if cleanupErr := cleanupUpgradeHandoff(taskRoot, temporaryBase); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
			taskRoot = ""
		}
	}()
	if err = os.Chmod(taskRoot, 0711); err != nil {
		return result, taskRoot, fmt.Errorf("%w: cannot secure task root", ErrPackagingCommand)
	}
	if err = validateOwnedDirectory(taskRoot, 0711); err != nil {
		return result, taskRoot, err
	}
	if err = syncDirectory(temporaryBase); err != nil {
		return result, taskRoot, fmt.Errorf("%w: cannot sync temporary root", ErrPackagingCommand)
	}
	handoffDirectory := filepath.Join(taskRoot, upgradeHandoffName)
	if err = os.Mkdir(handoffDirectory, 0755); err != nil {
		return result, taskRoot, fmt.Errorf("%w: cannot create handoff", ErrPackagingCommand)
	}
	if err = os.Chmod(handoffDirectory, 0755); err != nil {
		return result, taskRoot, fmt.Errorf("%w: cannot set handoff mode", ErrPackagingCommand)
	}
	if err = validateOwnedDirectory(handoffDirectory, 0755); err != nil {
		return result, taskRoot, err
	}

	files := []handoffFile{
		{source: staged.ManifestPath, destination: filepath.Join(handoffDirectory, "manifest"), size: staged.ManifestSize, digest: staged.ManifestSHA256, sourceMode: 0400, destinationMode: 0444},
		{source: staged.SignaturePath, destination: filepath.Join(handoffDirectory, "manifest.sig"), size: SignatureBytes, digest: staged.SignatureSHA256, sourceMode: 0400, destinationMode: 0444},
		{source: staged.SBOMPath, destination: filepath.Join(handoffDirectory, "edge-agent.spdx.json"), size: staged.SBOMSize, digest: staged.SBOMSHA256, sourceMode: 0400, destinationMode: 0444},
		{source: staged.ExecutablePath, destination: filepath.Join(handoffDirectory, "edge-agent"), size: staged.ExecutableSize, digest: staged.ExecutableSHA256, sourceMode: 0500, destinationMode: 0555},
	}
	if staged.NativePath != "" {
		files = append(files, handoffFile{source: staged.NativePath, destination: filepath.Join(handoffDirectory, NativeSectionName), size: staged.NativeSize, digest: staged.NativeSHA256, sourceMode: 0400, destinationMode: 0444})
	}
	for _, file := range files {
		if err = copyVerifiedHandoffFile(file); err != nil {
			return result, taskRoot, err
		}
	}
	if err = syncDirectory(handoffDirectory); err != nil {
		return result, taskRoot, fmt.Errorf("%w: cannot sync handoff", ErrPackagingCommand)
	}
	if err = syncDirectory(taskRoot); err != nil {
		return result, taskRoot, fmt.Errorf("%w: cannot sync task root", ErrPackagingCommand)
	}
	result = StagedBundle{
		Directory:    handoffDirectory,
		ManifestPath: filepath.Join(handoffDirectory, "manifest"), ManifestSize: staged.ManifestSize, ManifestSHA256: staged.ManifestSHA256,
		SignaturePath: filepath.Join(handoffDirectory, "manifest.sig"), SignatureSHA256: staged.SignatureSHA256,
		SBOMPath: filepath.Join(handoffDirectory, "edge-agent.spdx.json"), SBOMSize: staged.SBOMSize, SBOMSHA256: staged.SBOMSHA256,
		ExecutablePath: filepath.Join(handoffDirectory, "edge-agent"), ExecutableSize: staged.ExecutableSize, ExecutableSHA256: staged.ExecutableSHA256,
		OuterSize: staged.OuterSize, OuterSHA256: staged.OuterSHA256,
	}
	if staged.NativePath != "" {
		result.NativePath, result.NativeSize, result.NativeSHA256 = filepath.Join(handoffDirectory, NativeSectionName), staged.NativeSize, staged.NativeSHA256
	}
	return result, taskRoot, nil
}

type handoffFile struct {
	source          string
	destination     string
	size            int64
	digest          string
	sourceMode      os.FileMode
	destinationMode os.FileMode
}

func copyVerifiedHandoffFile(specification handoffFile) (err error) {
	if specification.size <= 0 || !validSHA256(specification.digest) || filepath.Base(specification.destination) == "." {
		return fmt.Errorf("%w: handoff facts rejected", ErrPackagingCommand)
	}
	sourceFD, err := unix.Open(specification.source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%w: cannot open verified source", ErrPackagingCommand)
	}
	source := os.NewFile(uintptr(sourceFD), filepath.Base(specification.source))
	defer source.Close()
	if err := validateOwnedRegularFD(sourceFD, specification.size, specification.sourceMode); err != nil {
		return err
	}

	destinationFD, err := unix.Open(specification.destination, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(specification.destinationMode.Perm()))
	if err != nil {
		return fmt.Errorf("%w: handoff target rejected", ErrPackagingCommand)
	}
	destination := os.NewFile(uintptr(destinationFD), filepath.Base(specification.destination))
	remove := true
	defer func() {
		_ = destination.Close()
		if remove {
			_ = os.Remove(specification.destination)
		}
	}()
	if err := destination.Chmod(specification.destinationMode); err != nil {
		return fmt.Errorf("%w: cannot set handoff mode", ErrPackagingCommand)
	}
	if err := validateOwnedRegularFD(destinationFD, 0, specification.destinationMode); err != nil {
		return err
	}

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(source, specification.size+1))
	if err != nil || written != specification.size {
		return fmt.Errorf("%w: handoff copy size differs", ErrArtifactMismatch)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(digest), []byte(specification.digest)) != 1 {
		return fmt.Errorf("%w: handoff copy digest differs", ErrArtifactMismatch)
	}
	if err := destination.Chmod(specification.destinationMode); err != nil {
		return fmt.Errorf("%w: cannot set handoff mode", ErrPackagingCommand)
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("%w: cannot sync handoff file", ErrPackagingCommand)
	}
	if err := destination.Close(); err != nil {
		return fmt.Errorf("%w: cannot close handoff file", ErrPackagingCommand)
	}
	remove = false
	return nil
}

func validateOwnedRegularFD(fd int, expectedSize int64, expectedMode os.FileMode) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 ||
		stat.Size != expectedSize || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() || os.FileMode(stat.Mode).Perm() != expectedMode.Perm() {
		return fmt.Errorf("%w: handoff file policy rejected", ErrPackagingCommand)
	}
	return nil
}

func validateOwnedDirectory(path string, expectedMode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != expectedMode.Perm() {
		return fmt.Errorf("%w: handoff directory policy rejected", ErrPackagingCommand)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() {
		return fmt.Errorf("%w: handoff directory owner rejected", ErrPackagingCommand)
	}
	return nil
}

func validateUpgradeHandoffPaths(staged StagedBundle) error {
	if staged.Directory == "" || filepath.Clean(staged.Directory) != staged.Directory || filepath.Base(staged.Directory) != upgradeHandoffName {
		return fmt.Errorf("%w: handoff directory rejected", ErrPackagingCommand)
	}
	if !strings.HasPrefix(filepath.Base(filepath.Dir(staged.Directory)), upgradeTaskPrefix) {
		return fmt.Errorf("%w: task root rejected", ErrPackagingCommand)
	}
	if err := validateOwnedDirectory(filepath.Dir(staged.Directory), 0711); err != nil {
		return err
	}
	if err := validateOwnedDirectory(staged.Directory, 0755); err != nil {
		return err
	}
	want := map[string]string{
		staged.ManifestPath: "manifest", staged.SignaturePath: "manifest.sig",
		staged.SBOMPath: "edge-agent.spdx.json", staged.ExecutablePath: "edge-agent",
	}
	expected := 4
	if staged.NativePath != "" {
		want[staged.NativePath] = NativeSectionName
		expected = 5
	}
	if len(want) != expected {
		return fmt.Errorf("%w: duplicate handoff path", ErrPackagingCommand)
	}
	for path, name := range want {
		if path != filepath.Join(staged.Directory, name) {
			return fmt.Errorf("%w: handoff path rejected", ErrPackagingCommand)
		}
	}
	return nil
}

func cleanupUpgradeHandoff(taskRoot, temporaryBase string) error {
	if taskRoot == "" {
		return nil
	}
	if temporaryBase == "" || !filepath.IsAbs(temporaryBase) || filepath.Dir(taskRoot) != temporaryBase ||
		!strings.HasPrefix(filepath.Base(taskRoot), upgradeTaskPrefix) {
		return fmt.Errorf("%w: cleanup path rejected", ErrPackagingCommand)
	}
	if err := os.RemoveAll(taskRoot); err != nil {
		return fmt.Errorf("%w: handoff cleanup failed", ErrPackagingCommand)
	}
	if _, err := os.Lstat(taskRoot); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: handoff cleanup incomplete", ErrPackagingCommand)
	}
	if err := syncDirectory(temporaryBase); err != nil {
		return fmt.Errorf("%w: cannot sync handoff cleanup", ErrPackagingCommand)
	}
	return nil
}

func rollbackCommand(journalBoundVersion string) (packagingCommand, error) {
	if !validIdentifier(journalBoundVersion) {
		return packagingCommand{}, fmt.Errorf("%w: rollback version rejected", ErrPackagingCommand)
	}
	return packagingCommand{
		path: rollbackScriptPath,
		args: []string{"--version", journalBoundVersion},
		env:  fixedPackagingEnvironment(),
	}, nil
}

func fixedPackagingEnvironment() []string {
	return []string{
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"TZ=UTC",
	}
}

func runPackagingCommand(ctx context.Context, command packagingCommand) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is missing", ErrPackagingCommand)
	}
	if err := validateFixedPackagingScript(command.path); err != nil {
		return err
	}
	process := exec.CommandContext(ctx, command.path, command.args...)
	process.Args[0] = command.path
	process.Dir = "/"
	process.Env = append([]string(nil), command.env...)
	process.Stdin = nil
	process.Stdout = nil
	process.Stderr = nil
	process.ExtraFiles = nil
	if err := process.Run(); err != nil {
		return ErrPackagingCommand
	}
	return nil
}

func validateFixedPackagingScript(path string) error {
	if path != upgradeScriptPath && path != rollbackScriptPath {
		return fmt.Errorf("%w: executable rejected", ErrPackagingCommand)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0555 {
		return fmt.Errorf("%w: executable policy rejected", ErrPackagingCommand)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return fmt.Errorf("%w: executable ownership rejected", ErrPackagingCommand)
	}
	return nil
}
