//go:build !windows

package controlplaneupgrade

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
)

func (executor *nativeExecutor) current() (Artifact, NativeManifest, error) {
	target, err := os.Readlink(filepath.Join(executor.config.ReleaseRoot, "current"))
	if err != nil || !filepath.IsAbs(target) || filepath.Dir(target) != filepath.Join(executor.config.ReleaseRoot, "releases") ||
		!digestPattern.MatchString(filepath.Base(target)) || nativeOwnedDirectory(target, executor.owner) != nil {
		return Artifact{}, NativeManifest{}, ErrTargetMismatch
	}
	filename := filepath.Join(executor.config.ReleaseRoot, "artifacts", filepath.Base(target)+".tar")
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() > nativeArchiveLimit {
		return Artifact{}, NativeManifest{}, ErrTargetMismatch
	}
	encoded, err := nativeReadRegular(filepath.Join(target, NativeManifestFilename), executor.owner, nativeManifestLimit)
	var manifest NativeManifest
	if err != nil || decodeNativeJSON(encoded, &manifest) != nil {
		return Artifact{}, NativeManifest{}, ErrTargetMismatch
	}
	artifact := Artifact{Version: manifest.Version, Digest: filepath.Base(target), Size: info.Size()}
	verified, err := executor.verifyArtifact(artifact)
	return artifact, verified, err
}

func (executor *nativeExecutor) verifyArtifact(artifact Artifact) (NativeManifest, error) {
	filename := filepath.Join(executor.config.ReleaseRoot, "artifacts", artifact.Digest+".tar")
	if !executor.ownedArchive(filename) {
		return NativeManifest{}, ErrTargetMismatch
	}
	manifest, err := validateNativeReleaseArchive(filename, artifact, executor.platform, executor.config.ArtifactPublicKeys)
	if err != nil {
		return NativeManifest{}, err
	}
	if manifest.Schema == NativeManifestSchema && executor.config.SourceGitDirectory == "" {
		return NativeManifest{}, ErrTargetMismatch
	}
	if err := executor.verifyDirectory(executor.release(artifact), manifest); err != nil {
		return NativeManifest{}, err
	}
	return manifest, nil
}

func (executor *nativeExecutor) ownedArchive(filename string) bool {
	info, err := os.Lstat(filename)
	stat, ok := infoSysStat(info)
	return err == nil && ok && stat.Uid == executor.owner && stat.Nlink == 1 && info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0
}

func (executor *nativeExecutor) release(artifact Artifact) string {
	return filepath.Join(executor.config.ReleaseRoot, "releases", artifact.Digest)
}

func nativeReadRegular(filename string, owner uint32, maximum int64) ([]byte, error) {
	file, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSysStat(info)
	if err != nil || !ok || stat.Uid != owner || stat.Nlink != 1 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o022 != 0 || info.Size() < 0 || info.Size() > maximum {
		return nil, ErrTargetMismatch
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(encoded)) != info.Size() {
		return nil, ErrTargetMismatch
	}
	return encoded, nil
}

func (executor *nativeExecutor) verifyDirectory(directory string, manifest NativeManifest) error {
	if err := nativeOwnedDirectory(directory, executor.owner); err != nil {
		return err
	}
	encoded, err := nativeReadRegular(filepath.Join(directory, NativeManifestFilename), executor.owner, nativeManifestLimit)
	manifestInfo, manifestErr := os.Lstat(filepath.Join(directory, NativeManifestFilename))
	var physicalManifest NativeManifest
	if err != nil || manifestErr != nil || manifestInfo.Mode().Perm() != 0o644 ||
		decodeNativeJSON(encoded, &physicalManifest) != nil || !reflect.DeepEqual(physicalManifest, manifest) {
		return ErrTargetMismatch
	}
	if manifest.Schema == NativeManifestSchema {
		var members map[string]json.RawMessage
		if json.Unmarshal(encoded, &members) != nil {
			return ErrTargetMismatch
		}
		if _, present := members["key_id"]; present {
			return ErrTargetMismatch
		}
	}
	if manifest.Schema == NativeManifestSignedSchema {
		signaturePath := filepath.Join(directory, NativeSignatureFilename)
		signature, err := nativeReadRegular(signaturePath, executor.owner, 128)
		info, statErr := os.Lstat(signaturePath)
		if err != nil || statErr != nil || info.Mode().Perm() != 0o644 ||
			verifyNativeManifestSignature(manifest, encoded, signature, executor.config.ArtifactPublicKeys) != nil {
			return ErrTargetMismatch
		}
	}
	expected := make(map[string]NativeFile, len(manifest.Files))
	for _, file := range manifest.Files {
		expected[file.Path] = file
	}
	seen := 0
	err = filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return ErrTargetMismatch
		}
		if entry.IsDir() {
			return nativeOwnedDirectory(filename, executor.owner)
		}
		relative, err := filepath.Rel(directory, filename)
		if err != nil {
			return err
		}
		if relative == NativeManifestFilename {
			return nil
		}
		if relative == NativeSignatureFilename && manifest.Schema == NativeManifestSignedSchema {
			return nil
		}
		file, exists := expected[filepath.ToSlash(relative)]
		if !exists {
			return ErrTargetMismatch
		}
		info, err := entry.Info()
		if err != nil || uint32(info.Mode().Perm()) != file.Mode || info.Size() != file.Bytes {
			return ErrTargetMismatch
		}
		stat, ok := infoSysStat(info)
		if !ok || stat.Uid != executor.owner || stat.Nlink != 1 || !info.Mode().IsRegular() {
			return ErrTargetMismatch
		}
		if file.Bytes == 0 {
			if file.SHA256 != digestBytes(nil) {
				return ErrTargetMismatch
			}
		} else if digest, size, err := digestRegularFile(filename, file.Bytes); err != nil || size != file.Bytes || digest != file.SHA256 {
			return ErrTargetMismatch
		}
		seen++
		return nil
	})
	if err != nil || seen != len(manifest.Files) {
		return ErrTargetMismatch
	}
	for _, name := range []string{"bin/control-api", "bin/agent-gateway"} {
		file, err := elf.Open(filepath.Join(directory, name))
		if err != nil {
			return ErrTargetMismatch
		}
		valid := file.Class == elf.ELFCLASS64 && file.Data == elf.ELFDATA2LSB &&
			(file.Type == elf.ET_EXEC || file.Type == elf.ET_DYN) &&
			((manifest.Platform.Arch == "amd64" && file.Machine == elf.EM_X86_64) ||
				(manifest.Platform.Arch == "arm64" && file.Machine == elf.EM_AARCH64))
		_ = file.Close()
		if !valid {
			return ErrTargetMismatch
		}
	}
	return nil
}

func (executor *nativeExecutor) ensureArchive(ctx context.Context, artifact Artifact) (NativeManifest, error) {
	if !digestPattern.MatchString(artifact.Digest) || artifact.Size < 1024 || artifact.Size > nativeArchiveLimit {
		return NativeManifest{}, ErrInvalidPlan
	}
	filename := filepath.Join(executor.config.ReleaseRoot, "artifacts", artifact.Digest+".tar")
	if _, err := os.Lstat(filename); err == nil {
		if !executor.ownedArchive(filename) {
			return NativeManifest{}, ErrTargetMismatch
		}
		manifest, err := validateNativeReleaseArchive(filename, artifact, executor.platform, executor.config.ArtifactPublicKeys)
		if err != nil {
			logRun(ctx, RunLogEntry{Level: "error", Event: "artifact_rejected", Reason: "cached_archive_invalid", Version: artifact.Version})
			return NativeManifest{}, err
		}
		logRun(ctx, RunLogEntry{Level: "info", Event: "artifact_cached", Version: artifact.Version, Bytes: artifact.Size})
		return manifest, nil
	} else if !os.IsNotExist(err) {
		return NativeManifest{}, err
	}
	address, err := url.Parse(artifact.URL)
	if err != nil || address.Scheme != "https" || address.Host == "" || address.User != nil {
		logRun(ctx, RunLogEntry{Level: "error", Event: "artifact_download_failed", Reason: "url_rejected", Version: artifact.Version})
		return NativeManifest{}, ErrInvalidPlan
	}
	// Only the host is logged: the path and query of a signed URL can carry
	// short-lived credentials.
	host := address.Hostname()
	started := executor.now()
	elapsed := func() int64 { return executor.now().Sub(started).Milliseconds() }
	logRun(ctx, RunLogEntry{Level: "info", Event: "artifact_download_started", Version: artifact.Version, Host: host, Bytes: artifact.Size})
	ctx, cancel := context.WithTimeout(ctx, executor.config.StepTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return NativeManifest{}, ErrInvalidPlan
	}
	response, err := executor.client.Do(request)
	if err != nil {
		// A signed download URL can carry short-lived credentials. Never return
		// net/http's URL-bearing error into receipt or runner logs.
		reason := "network_error"
		if ctx.Err() != nil {
			reason = "timeout"
		}
		logRun(ctx, RunLogEntry{Level: "error", Event: "artifact_download_failed", Reason: reason, Host: host, DurationMS: elapsed()})
		return NativeManifest{}, ErrArtifactUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.Scheme != "https" {
		logRun(ctx, RunLogEntry{Level: "error", Event: "artifact_download_failed", Reason: "http_status", Host: host,
			HTTPStatus: response.StatusCode, DurationMS: elapsed()})
		return NativeManifest{}, ErrArtifactUnavailable
	}
	file, err := os.CreateTemp(filepath.Dir(filename), ".download-*.tar")
	if err != nil {
		return NativeManifest{}, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	copied, err := io.Copy(file, io.LimitReader(response.Body, artifact.Size+1))
	if err != nil || file.Sync() != nil || file.Close() != nil {
		reason := "interrupted"
		if ctx.Err() != nil {
			reason = "timeout"
		}
		logRun(ctx, RunLogEntry{Level: "error", Event: "artifact_download_failed", Reason: reason, Host: host, Bytes: copied, DurationMS: elapsed()})
		return NativeManifest{}, ErrArtifactUnavailable
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "artifact_downloaded", Version: artifact.Version, Host: host, Bytes: copied, DurationMS: elapsed()})
	manifest, err := validateNativeReleaseArchive(file.Name(), artifact, executor.platform, executor.config.ArtifactPublicKeys)
	if err != nil {
		reason := "digest_or_signature_mismatch"
		if copied != artifact.Size {
			reason = "size_mismatch"
		}
		logRun(ctx, RunLogEntry{Level: "error", Event: "artifact_rejected", Reason: reason, Version: artifact.Version, Bytes: copied})
		return NativeManifest{}, err
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "artifact_verified", Version: artifact.Version})
	if err := os.Rename(file.Name(), filename); err != nil {
		return NativeManifest{}, err
	}
	return manifest, syncDirectory(filepath.Dir(filename))
}

func (executor *nativeExecutor) stage(plan Plan, current, candidate NativeManifest) error {
	destination := executor.release(plan.Target)
	if _, err := os.Lstat(destination); err == nil {
		return executor.verifyDirectory(destination, candidate)
	} else if !os.IsNotExist(err) {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Join(executor.config.ReleaseRoot, "releases"), ".stage-"+plan.Target.Digest+"-")
	if err != nil {
		return err
	}
	// Failed staging remains for inspection; it is never referenced by current.
	for _, file := range current.Files {
		encoded, err := nativeReadRegular(filepath.Join(executor.release(plan.Rollback), file.Path), executor.owner, file.Bytes)
		if err != nil {
			return err
		}
		if err := nativeStageFile(stage, file.Path, encoded, file.Mode); err != nil {
			return err
		}
	}
	archive, err := os.Open(filepath.Join(executor.config.ReleaseRoot, "artifacts", plan.Target.Digest+".tar"))
	if err != nil {
		return err
	}
	defer archive.Close()
	reader := tar.NewReader(archive)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || !nativeRelativePath(header.Name) || header.Typeflag != tar.TypeReg {
			return ErrInvalidPlan
		}
		encoded, err := io.ReadAll(io.LimitReader(reader, nativeArchiveLimit+1))
		if err != nil || int64(len(encoded)) != header.Size {
			return ErrInvalidPlan
		}
		if err := nativeStageFile(stage, header.Name, encoded, uint32(header.Mode)); err != nil {
			return err
		}
	}
	if err := executor.verifyDirectory(stage, candidate); err != nil {
		return err
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		return err
	}
	if err := syncNativeDirectories(stage, executor.syncDir); err != nil {
		return err
	}
	if err := os.Rename(stage, destination); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

func syncNativeDirectories(root string, syncDir func(string) error) error {
	if syncDir == nil {
		syncDir = syncDirectory
	}
	var directories []string
	if err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, filename)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool {
		left, right := strings.Count(directories[i], string(filepath.Separator)), strings.Count(directories[j], string(filepath.Separator))
		if left != right {
			return left > right
		}
		return directories[i] < directories[j]
	})
	for _, directory := range directories {
		if err := syncDir(directory); err != nil {
			return err
		}
	}
	return nil
}

func nativeStageFile(root, relative string, content []byte, mode uint32) error {
	filename := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, os.FileMode(mode))
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chmod(os.FileMode(mode)); err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		return err
	}
	return file.Sync()
}

func nativeCompatibleFiles(current, candidate NativeManifest) bool {
	next := make(map[string]NativeFile, len(candidate.Files))
	for _, file := range candidate.Files {
		next[file.Path] = file
	}
	for _, file := range current.Files {
		target, exists := next[file.Path]
		if !exists || ((!nativeOwnedContent(file.Path) || strings.HasPrefix(file.Path, "static/web/assets/")) && target != file) {
			return false
		}
	}
	old := make(map[string]NativeFile, len(current.Files))
	for _, file := range current.Files {
		old[file.Path] = file
	}
	for _, file := range candidate.Files {
		// New migration files are judged by nativeAppendedMigrations and
		// nativeAppendedClickHouseMigrations.
		_, existing := old[file.Path]
		if !nativeOwnedContent(file.Path) && old[file.Path] != file &&
			(existing || !strings.HasPrefix(file.Path, "migrations/") && !strings.HasPrefix(file.Path, nativeClickHouseMigrations)) {
			return false
		}
	}
	return true
}

// nativeRecoveryRunbook is the root recovery runbook shipped with every release
// (scripts/native-release-package.mjs copyNativeRecoveryRunbook). Only this one
// docs path is owned; any other new or changed docs file is still refused.
const nativeRecoveryRunbook = "docs/platform-admin-recovery.md"

func nativeOwnedContent(path string) bool {
	return path == "bin/control-api" || path == "bin/agent-gateway" || path == nativeClickHouseScript || path == nativeRecoveryRunbook ||
		strings.HasPrefix(path, "static/web/")
}

func nativeFile(manifest NativeManifest, name string) NativeFile {
	for _, file := range manifest.Files {
		if file.Path == name {
			return file
		}
	}
	return NativeFile{}
}

func nativeResponseDigest(response *http.Response, maximum int64) (string, error) {
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", ErrTargetMismatch
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(response.Body, maximum+1))
	if err != nil || size > maximum {
		return "", ErrTargetMismatch
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
