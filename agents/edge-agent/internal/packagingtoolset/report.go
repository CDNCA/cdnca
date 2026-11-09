// Package packagingtoolset reports EdgeRuntimeStatus.packaging_toolset:
// the node's last packaging toolset refresh (the
// toolset-refresh record install.sh writes) and the digests of the installed
// packaging scripts and root packaging helper. Read only; never on the
// request path.
package packagingtoolset

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/packagingtoolset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Paths are the production locations (tests use a temporary root).
type Paths struct {
	Record  string
	Scripts string
	Helper  string
}

func ProductionPaths() Paths {
	return Paths{
		Record:  "/var/lib/cdnca-edge-agent-packaging/toolset-refresh",
		Scripts: "/usr/libexec/cdnca-edge-agent",
		Helper:  "/usr/libexec/cdnca-edge-agent-helper",
	}
}

var scriptNames = []string{"install", "lib", "preflight", "rollback", "uninstall", "upgrade"}

const (
	maxRecordBytes = 4 << 10
	maxScriptBytes = 4 << 20
	maxHelperBytes = 64 << 20
)

// Reporter caches each file's digest (or read failure) under its stat
// signature, absence included: a heartbeat rereads only the small record and
// a file whose stat changed (replaced, created, deleted).
type Reporter struct {
	paths Paths
	hash  func(path string, limit int64) (string, error)
	mu    sync.Mutex
	files map[string]cachedDigest
}

type cachedDigest struct {
	signature string
	sum       string
	ok        bool
}

func NewReporter(paths Paths) *Reporter {
	return &Reporter{paths: paths, hash: fileSHA256, files: map[string]cachedDigest{}}
}

func (r *Reporter) Report() *agentv1.PackagingToolsetStatus {
	status := readRecord(r.paths.Record)
	status.ScriptsSha256, status.HelperSha256 = r.digests()
	return status
}

func (r *Reporter) digests() (string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var lines bytes.Buffer
	scripts := true
	for _, name := range scriptNames {
		sum, ok := r.digestLocked(filepath.Join(r.paths.Scripts, name+".sh"), maxScriptBytes)
		scripts = scripts && ok
		fmt.Fprintf(&lines, "%s  %s.sh\n", sum, name)
	}
	scriptsSum := ""
	if scripts {
		total := sha256.Sum256(lines.Bytes())
		scriptsSum = hex.EncodeToString(total[:])
	}
	helper, _ := r.digestLocked(r.paths.Helper, maxHelperBytes)
	return scriptsSum, helper
}

// digestLocked hashes path only when its stat signature changed since the
// last report; a missing or unreadable file is cached the same way.
func (r *Reporter) digestLocked(path string, limit int64) (string, bool) {
	signature := statSignature(path)
	if cached, found := r.files[path]; found && cached.signature == signature {
		return cached.sum, cached.ok
	}
	entry := cachedDigest{signature: signature}
	if !strings.HasPrefix(signature, "missing") && !strings.HasPrefix(signature, "error") {
		sum, err := r.hash(path, limit)
		entry.sum, entry.ok = sum, err == nil
		if err != nil {
			entry.sum = ""
		}
	}
	r.files[path] = entry
	return entry.sum, entry.ok
}

// statSignature: device, inode, mode, size, mtime and ctime, or the stat
// failure (missing, or the error) as its own state.
func statSignature(path string) string {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "missing"
	}
	if err != nil {
		return "error:" + err.Error()
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Sprintf("info:%v:%d:%d", info.Mode(), info.Size(), info.ModTime().UnixNano())
	}
	return fmt.Sprintf("%d:%d:%v:%d:%d:%d", stat.Dev, stat.Ino, info.Mode(), info.Size(), info.ModTime().UnixNano(), statCtime(stat))
}

func fileSHA256(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return "", errors.New("not a bounded regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, limit+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readRecord(path string) *agentv1.PackagingToolsetStatus {
	unknown := &agentv1.PackagingToolsetStatus{RefreshStatus: "unknown"}
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &agentv1.PackagingToolsetStatus{RefreshStatus: "none"}
	}
	if err != nil {
		return unknown
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxRecordBytes {
		return unknown
	}
	values := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(file, maxRecordBytes))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			return unknown
		}
		if _, seen := values[key]; seen {
			return unknown
		}
		values[key] = value
	}
	if scanner.Err() != nil {
		return unknown
	}
	status := &agentv1.PackagingToolsetStatus{
		RefreshStatus: values["status"], RefreshVersion: values["version"], RefreshReason: values["reason"],
		HelperStatus: values["helper_status"], HelperReason: values["helper_reason"],
	}
	if status.RefreshStatus == "none" || status.RefreshStatus == "unknown" {
		return unknown
	}
	at := info.ModTime()
	if raw, ok := values["time"]; ok {
		if at, err = time.Parse(time.RFC3339, raw); err != nil {
			return unknown
		}
	}
	status.RefreshTime = timestamppb.New(at.UTC())
	if !contract.Valid(status.RefreshStatus, status.RefreshVersion, status.RefreshReason, true,
		status.HelperStatus, status.HelperReason, "", "") {
		return unknown
	}
	return status
}
