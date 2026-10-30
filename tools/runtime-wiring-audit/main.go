package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const schemaVersion = "cdnca.runtime-wiring-audit/v1"

type status string

const (
	statusPass       status = "pass"
	statusFail       status = "fail"
	statusUnknown    status = "unknown"
	statusNotApplied status = "not-applicable"
)

var checkOrder = []string{
	"core_package",
	"postgres_repository",
	"migration_up",
	"migration_down",
	"migration_runtime_head",
	"http_handler",
	"router_mount",
	"runtime_dependency_wiring",
	"runtime_configuration",
	"openapi_path",
	"openapi_operation",
	"openapi_error",
	"openapi_aggregation",
	"rbac_permission",
	"rbac_transactional_recheck",
	"idempotency",
	"audit",
	"background_worker",
	"outbox",
	"frontend_api_consumer",
	"smoke_e2e",
}

type checkResult struct {
	Status   status   `json:"status"`
	Evidence []string `json:"evidence"`
	Reason   string   `json:"reason"`
}

type finding struct {
	Code     string `json:"code"`
	Evidence string `json:"evidence"`
	Detail   string `json:"detail"`
}

type domainResult struct {
	Name     string                 `json:"name"`
	Packages []string               `json:"packages"`
	Checks   map[string]checkResult `json:"checks"`
	Findings []finding              `json:"findings"`
}

type taskSuggestion struct {
	Priority  int      `json:"priority"`
	Domain    string   `json:"domain"`
	Title     string   `json:"title"`
	Reason    string   `json:"reason"`
	Ownership []string `json:"ownership"`
	Excludes  []string `json:"excludes"`
}

type conflictFilter struct {
	Name  string   `json:"name"`
	Globs []string `json:"globs"`
}

type report struct {
	SchemaVersion            string           `json:"schema_version"`
	SnapshotSemantics        string           `json:"snapshot_semantics"`
	Scope                    []string         `json:"scope"`
	SourceSHA256             string           `json:"source_sha256"`
	SourceManifestSHA256     string           `json:"source_manifest_sha256"`
	ToolSourceSHA256         string           `json:"tool_source_sha256"`
	ToolSourceManifestSHA256 string           `json:"tool_source_manifest_sha256"`
	StatusVocabulary         []status         `json:"status_vocabulary"`
	CheckOrder               []string         `json:"check_order"`
	Summary                  map[status]int   `json:"summary"`
	Domains                  []domainResult   `json:"domains"`
	ConflictFilters          []conflictFilter `json:"conflict_filters"`
	NextTasks                []taskSuggestion `json:"next_tasks"`
	Diagnostics              []string         `json:"diagnostics"`
	SourceManifest           fileManifest     `json:"-"`
	RepositoryRoot           string           `json:"-"`
	ToolRoot                 string           `json:"-"`
}

func main() {
	var root string
	var out string
	var verifyManifest string
	var toolRoot string
	flag.StringVar(&root, "root", ".", "repository root")
	flag.StringVar(&out, "out", "", "output directory outside the repository")
	flag.StringVar(&verifyManifest, "verify-source-manifest", "", "verify a prior source manifest without writing a report")
	flag.StringVar(&toolRoot, "tool-root", "", "repository root containing the audit tool source")
	flag.Parse()
	verifyOnly := strings.TrimSpace(verifyManifest) != ""
	if flag.NArg() != 0 || verifyOnly == (strings.TrimSpace(out) != "") {
		fatal(errors.New("usage: runtime-wiring-audit --root REPOSITORY (--out TEMP_DIRECTORY | --verify-source-manifest MANIFEST)"))
	}

	rootAbs, err := canonicalPath(root)
	if err != nil {
		fatal(fmt.Errorf("resolve repository root: %w", err))
	}
	if verifyOnly {
		manifestAbs, err := canonicalPath(verifyManifest)
		if err != nil {
			fatal(fmt.Errorf("resolve source manifest: %w", err))
		}
		if err := verifySourceManifest(rootAbs, manifestAbs); err != nil {
			fatal(err)
		}
		fmt.Println("runtime-wiring-audit: source manifest current")
		return
	}
	outAbs, err := canonicalPath(out)
	if err != nil {
		fatal(fmt.Errorf("resolve output directory: %w", err))
	}
	if pathWithin(outAbs, rootAbs) {
		fatal(errors.New("output directory must be outside the repository"))
	}
	result, err := auditRepository(rootAbs)
	if err != nil {
		fatal(err)
	}
	if strings.TrimSpace(toolRoot) == "" {
		result.ToolRoot = rootAbs
	} else {
		result.ToolRoot, err = canonicalPath(toolRoot)
		if err != nil {
			fatal(fmt.Errorf("resolve audit tool root: %w", err))
		}
	}
	if err := writeReport(outAbs, result); err != nil {
		fatal(err)
	}
}

func canonicalPath(value string) (string, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	cursor := absolute
	var suffix []string
	for {
		resolved, resolveErr := filepath.EvalSymlinks(cursor)
		if resolveErr == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(resolveErr) {
			return "", resolveErr
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return "", resolveErr
		}
		suffix = append(suffix, filepath.Base(cursor))
		cursor = parent
	}
}

func pathWithin(path, parent string) bool {
	relative, err := filepath.Rel(parent, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func writeReport(out string, result report) error {
	if err := validateFileManifest(result.SourceManifest, sourceManifestKind); err != nil {
		return fmt.Errorf("validate source manifest: %w", err)
	}
	toolManifest, err := buildToolSourceManifest(result.ToolRoot)
	if err != nil {
		return err
	}
	sourceManifest, err := encodeFileManifest(result.SourceManifest)
	if err != nil {
		return fmt.Errorf("encode source manifest: %w", err)
	}
	toolSourceManifest, err := encodeFileManifest(toolManifest)
	if err != nil {
		return fmt.Errorf("encode tool source manifest: %w", err)
	}
	result.SnapshotSemantics = "snapshot-at-time"
	result.SourceSHA256 = result.SourceManifest.TotalSHA256
	result.SourceManifestSHA256 = manifestBytesSHA256(sourceManifest)
	result.ToolSourceSHA256 = toolManifest.TotalSHA256
	result.ToolSourceManifestSHA256 = manifestBytesSHA256(toolSourceManifest)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON report: %w", err)
	}
	encoded = append(encoded, '\n')
	markdown := []byte(renderMarkdown(result))
	artifacts := map[string][]byte{
		"report.json":               encoded,
		"report.md":                 markdown,
		"source-manifest.json":      sourceManifest,
		"tool-source-manifest.json": toolSourceManifest,
	}
	for name, content := range artifacts {
		if err := os.WriteFile(filepath.Join(out, name), content, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	names := make([]string, 0, len(artifacts))
	for name := range artifacts {
		names = append(names, name)
	}
	sort.Strings(names)
	var checksums strings.Builder
	for _, name := range names {
		sum := sha256.Sum256(artifacts[name])
		fmt.Fprintf(&checksums, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	if err := os.WriteFile(filepath.Join(out, "SHA256SUMS"), []byte(checksums.String()), 0o644); err != nil {
		return fmt.Errorf("write checksums: %w", err)
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "runtime-wiring-audit:", err)
	os.Exit(1)
}
