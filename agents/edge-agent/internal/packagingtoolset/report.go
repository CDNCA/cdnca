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

// Reporter caches the parsed record and each file's digest (or read failure)
// under its stat signature, absence included: a file whose stat changed
// (replaced, created, deleted) is read again. With the three directories
// watched (Linux), an unchanged heartbeat makes no stat and returns a copy of
// the last report; otherwise it stats each file (record, six scripts, helper).
type Reporter struct {
	paths   Paths
	scripts []string
	hash    func(path string, limit int64) (string, error)
	read    func(path string) *agentv1.PackagingToolsetStatus
	stat    func(path string) fileSignature
	watch   *watch
	mu      sync.Mutex
	files   map[string]cachedDigest
	record  cachedRecord
	// scriptsSum is the combined scripts digest, recomputed only when one of
	// the six scripts changed; scriptsKnown is false before the first report.
	scriptsSum   string
	scriptsKnown bool
	helperSum    string
}

type cachedDigest struct {
	signature fileSignature
	sum       string
	ok        bool
}

type cachedRecord struct {
	signature fileSignature
	status    *agentv1.PackagingToolsetStatus
}

func NewReporter(paths Paths) *Reporter {
	scripts := make([]string, len(scriptNames))
	for index, name := range scriptNames {
		scripts[index] = filepath.Join(paths.Scripts, name+".sh")
	}
	return &Reporter{paths: paths, scripts: scripts, hash: fileSHA256, read: readRecord, stat: statSignature,
		watch: newWatch(filepath.Dir(paths.Record), paths.Scripts, filepath.Dir(paths.Helper)), files: map[string]cachedDigest{}}
}

func (r *Reporter) Report() *agentv1.PackagingToolsetStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Drain the events before the stats: a change during them is still queued
	// for the next report.
	if r.watch.changed() || r.record.status == nil {
		r.recordLocked()
		r.scriptsSum, r.helperSum = r.digestsLocked()
	}
	record := r.record.status
	status := &agentv1.PackagingToolsetStatus{
		RefreshStatus: record.RefreshStatus, RefreshVersion: record.RefreshVersion, RefreshReason: record.RefreshReason,
		HelperStatus: record.HelperStatus, HelperReason: record.HelperReason,
	}
	if record.RefreshTime != nil {
		status.RefreshTime = timestamppb.New(record.RefreshTime.AsTime())
	}
	status.ScriptsSha256, status.HelperSha256 = r.scriptsSum, r.helperSum
	return status
}

// recordLocked rereads the record only when its stat signature changed.
func (r *Reporter) recordLocked() {
	signature := r.stat(r.paths.Record)
	if r.record.status == nil || r.record.signature != signature {
		r.record = cachedRecord{signature: signature, status: r.read(r.paths.Record)}
	}
}

func (r *Reporter) digestsLocked() (string, string) {
	changed := !r.scriptsKnown
	scripts := true
	for _, path := range r.scripts {
		_, ok, fresh := r.digestLocked(path, maxScriptBytes)
		scripts, changed = scripts && ok, changed || fresh
	}
	if changed {
		r.scriptsSum, r.scriptsKnown = "", true
		if scripts {
			var lines bytes.Buffer
			for index, path := range r.scripts {
				fmt.Fprintf(&lines, "%s  %s.sh\n", r.files[path].sum, scriptNames[index])
			}
			total := sha256.Sum256(lines.Bytes())
			r.scriptsSum = hex.EncodeToString(total[:])
		}
	}
	helper, _, _ := r.digestLocked(r.paths.Helper, maxHelperBytes)
	return r.scriptsSum, helper
}

// digestLocked hashes path only when its stat signature changed since the
// last report (changed reports that); a missing or unreadable file is cached
// the same way.
func (r *Reporter) digestLocked(path string, limit int64) (string, bool, bool) {
	signature := r.stat(path)
	if cached, found := r.files[path]; found && cached.signature == signature {
		return cached.sum, cached.ok, false
	}
	entry := cachedDigest{signature: signature}
	if signature.state == statPresent {
		sum, err := r.hash(path, limit)
		entry.sum, entry.ok = sum, err == nil
		if err != nil {
			entry.sum = ""
		}
	}
	r.files[path] = entry
	return entry.sum, entry.ok, true
}

const (
	statPresent = iota
	statMissing
	statError
)

// fileSignature: device, inode, mode, size, mtime and ctime, or the stat
// failure (missing, or the error) as its own state. Comparable, so an
// unchanged file costs no formatting.
type fileSignature struct {
	state             int
	err               string
	dev, ino          uint64
	mode              fs.FileMode
	size, mtime, ctim int64
}

func statSignature(path string) fileSignature {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileSignature{state: statMissing}
	}
	if err != nil {
		return fileSignature{state: statError, err: err.Error()}
	}
	signature := fileSignature{mode: info.Mode(), size: info.Size(), mtime: info.ModTime().UnixNano()}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		signature.dev, signature.ino, signature.ctim = uint64(stat.Dev), uint64(stat.Ino), statCtime(stat)
	}
	return signature
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
