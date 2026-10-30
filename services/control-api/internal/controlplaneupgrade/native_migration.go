package controlplaneupgrade

import (
	"regexp"
	"strconv"
	"strings"
)

var nativeMigrationFile = regexp.MustCompile(`^migrations/(([0-9]{3})_[a-z0-9]+(?:_[a-z0-9]+)*)\.(up|down)\.sql$`)

// nativeAppendedMigrations accepts only an append-only migration change: every
// current migration file stays byte-, size- and mode-identical, and the
// candidate adds contiguous versions after the current head, each with an up
// and a down script of the same identifier. It returns the appended
// identifiers in version order (nil when the set is unchanged).
func nativeAppendedMigrations(current, candidate NativeManifest) ([]string, bool) {
	old := make(map[string]NativeFile)
	for _, file := range current.Files {
		if strings.HasPrefix(file.Path, "migrations/") {
			old[file.Path] = file
		}
	}
	next := make(map[string]NativeFile)
	for _, file := range candidate.Files {
		if strings.HasPrefix(file.Path, "migrations/") {
			next[file.Path] = file
		}
	}
	for path, file := range old {
		if next[path] != file {
			return nil, false
		}
	}
	head := nativeMigrationHead(current)
	added := make(map[int]map[string]string)
	for path, file := range next {
		if _, exists := old[path]; exists {
			continue
		}
		match := nativeMigrationFile.FindStringSubmatch(path)
		if match == nil || len(match[1]) > 96 || file.Mode != 0o644 || file.Bytes < 1 {
			return nil, false
		}
		version, _ := strconv.Atoi(match[2])
		if version <= head {
			return nil, false
		}
		if added[version] == nil {
			added[version] = make(map[string]string)
		}
		added[version][match[3]] = match[1]
	}
	if len(added) == 0 {
		return nil, true
	}
	if len(added) > maxMigrationsPerPlan {
		return nil, false
	}
	applied := make([]string, 0, len(added))
	for version := head + 1; version <= head+len(added); version++ {
		pair := added[version]
		if pair == nil || pair["up"] == "" || pair["up"] != pair["down"] {
			return nil, false
		}
		applied = append(applied, pair["up"])
	}
	return applied, true
}

// nativeMigrationHead is the highest numbered migration a release carries.
func nativeMigrationHead(manifest NativeManifest) int {
	head := 0
	for _, file := range manifest.Files {
		if match := nativeMigrationFile.FindStringSubmatch(file.Path); match != nil {
			if version, _ := strconv.Atoi(match[2]); version > head {
				head = version
			}
		}
	}
	return head
}

func nativeMigrationVersion(identifier string) int {
	version, _ := strconv.Atoi(identifier[:3])
	return version
}
